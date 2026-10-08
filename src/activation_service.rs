// SPDX-License-Identifier: Apache-2.0
//! Current mTLS authority, Council ratification and Gate pause precede Registry apply.
use super::*;
use munarium_registry::activation_store::{Authority, Store, VerifiedArtifact};
use std::collections::BTreeSet;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    kind: String,
    digest: String,
    profile: String,
    retired: bool,
    policy: Option<Value>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    scope: Value,
    coordinator: String,
    readers: BTreeSet<String>,
    initial_epoch: u64,
    initial_artifact_set_digest: String,
    artifacts: Vec<Artifact>,
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
enum Operation {
    Apply { transition: String },
    Lookup { transition_id: String },
    Head,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    tenant: String,
    action: Operation,
}
async fn post(runtime: &Runtime, endpoint: &str, body: Value) -> Result<Value, Failure> {
    if !endpoint.starts_with("https://") {
        return Err(Failure::Configuration);
    }
    let response = runtime
        .client
        .post(endpoint)
        .json(&body)
        .send()
        .await
        .map_err(|_| Failure::Unavailable)?;
    service_transport::json_response(response, 1048576).await
}
async fn admitted(runtime: &Runtime, peer: &Peer, body: &[u8]) -> Result<Value, Failure> {
    let _permit = runtime
        .permits
        .try_acquire()
        .map_err(|_| Failure::Unavailable)?;
    let request: Request = serde_json::from_slice(body).map_err(|_| Failure::Refused)?;
    if !peer.tenants.contains(&request.tenant) {
        return Err(Failure::Refused);
    }
    let state = service_transport::authority(
        &runtime.client,
        &runtime.config.server_endpoint,
        &runtime.config.deployment,
        &request.tenant,
    )
    .await?;
    let bindings = &state["artifact"]["bindings"];
    let policy: Policy =
        serde_json::from_value(bindings[format!("stage2:{}", runtime.config.service)].clone())
            .map_err(|_| Failure::Refused)?;
    if policy.scope["tenant"] != request.tenant
        || policy.scope["deployment"] != runtime.config.deployment
    {
        return Err(Failure::Refused);
    }
    let mut stores = runtime.activations.lock().await;
    if peer.service != policy.coordinator && !policy.readers.contains(&peer.service) {
        return Err(Failure::Refused);
    }
    if !stores.contains_key(&request.tenant) {
        let file = runtime.config.database_directory.join(format!(
            "{:x}.activation.sqlite",
            Sha256::digest(request.tenant.as_bytes())
        ));
        let mut store = Store::open(&file).map_err(catalog_failure)?;
        match store.head(&policy.scope) {
            Err(munarium_registry::candidate::Error::NotFound) => store
                .initialize(
                    &policy.scope,
                    policy.initial_epoch,
                    &policy.initial_artifact_set_digest,
                    &json!([]),
                )
                .map_err(catalog_failure)?,
            Ok(_) => {}
            Err(e) => return Err(catalog_failure(e)),
        }
        stores.insert(request.tenant.clone(), store);
    }
    let store = stores
        .get_mut(&request.tenant)
        .ok_or(Failure::Unavailable)?;
    for artifact in &policy.artifacts {
        if artifact.retired {
            store
                .retire(
                    &policy.scope,
                    &artifact.digest,
                    state["revision"].as_str().ok_or(Failure::Refused)?,
                )
                .map_err(catalog_failure)?;
        }
    }
    match request.action {
        Operation::Lookup { transition_id } => store
            .lookup(&policy.scope, &transition_id)
            .map_err(catalog_failure),
        Operation::Head => store.head(&policy.scope).map_err(catalog_failure),
        Operation::Apply { transition } => {
            if peer.service != policy.coordinator || transition.len() > 65536 {
                return Err(Failure::Refused);
            }
            let t: Value = serde_json::from_str(&transition).map_err(|_| Failure::Refused)?;
            if serde_json::to_string(&t).map_err(|_| Failure::Refused)? != transition {
                return Err(Failure::Refused);
            }
            let id = t["transition"]["id"].as_str().ok_or(Failure::Refused)?;
            let council = runtime
                .config
                .council_endpoint
                .as_ref()
                .ok_or(Failure::Configuration)?;
            let ratified = post(
                runtime,
                &format!("{}/v1/transitions", council.trim_end_matches('/')),
                json!({"tenant":request.tenant,"action":{"operation":"lookup","transition_id":id}}),
            )
            .await?;
            if ratified["transition"] != t || ratified["ratified"] != true {
                return Err(Failure::Refused);
            }
            let gate = runtime
                .config
                .gate_endpoint
                .as_ref()
                .ok_or(Failure::Configuration)?;
            let pause=post(runtime,&format!("{}/v1/actions",gate.trim_end_matches('/')),json!({"tenant":request.tenant,"action":{"operation":"pause-lookup","transition_id":id}})).await?;
            // Reuse the candidate owner's verification and current trust; hashes alone are not admission.
            let trust_bytes =
                serde_json::to_vec(&bindings["registry"]).map_err(|_| Failure::Refused)?;
            let snapshot =
                TrustSnapshot::from_canonical_json(&trust_bytes).map_err(|_| Failure::Refused)?;
            let mut catalogs = runtime.catalogs.lock().await;
            if !catalogs.contains_key(&request.tenant) {
                let filename = format!("{:x}.sqlite", Sha256::digest(request.tenant.as_bytes()));
                let registry = Registry::open(
                    &runtime.config.database_directory.join(filename),
                    snapshot.clone(),
                    runtime.config.capacity,
                )
                .map_err(catalog_failure)?;
                catalogs.insert(
                    request.tenant.clone(),
                    Catalog {
                        registry,
                        trust: trust_bytes.clone(),
                    },
                );
            }
            let catalog = catalogs
                .get_mut(&request.tenant)
                .ok_or(Failure::Unavailable)?;
            if catalog.trust != trust_bytes {
                catalog
                    .registry
                    .replace_trust(Some(snapshot))
                    .map_err(catalog_failure)?;
                catalog.trust = trust_bytes;
            }
            let caller = Caller::from_verified_identity(&request.tenant, &[Permission::Read])
                .map_err(catalog_failure)?;
            let mut artifacts = Vec::new();
            for a in &policy.artifacts {
                if !t["artifacts"]
                    .as_array()
                    .ok_or(Failure::Refused)?
                    .iter()
                    .any(|item| item["kind"] == a.kind && item["digest"] == a.digest)
                {
                    continue;
                }
                match a.kind.as_str() {
                    "manifest" => {
                        catalog
                            .registry
                            .reader(&caller)
                            .resolve(&Query {
                                manifest_digest: a.digest.clone(),
                                artifact_digest: None,
                            })
                            .map_err(catalog_failure)?;
                    }
                    "policy" => {
                        let bytes = serde_json::to_vec(a.policy.as_ref().ok_or(Failure::Refused)?)
                            .map_err(|_| Failure::Refused)?;
                        let mut hash = Sha256::new();
                        hash.update(b"munarium:decision-policy:v1\0");
                        hash.update(&bytes);
                        if format!("sha256:{:x}", hash.finalize()) != a.digest {
                            return Err(Failure::Refused);
                        }
                    }
                    _ => return Err(Failure::Refused),
                }
                artifacts.push(VerifiedArtifact {
                    kind: a.kind.clone(),
                    digest: a.digest.clone(),
                    profile: a.profile.clone(),
                    retired: a.retired,
                });
            }
            let authority = Authority {
                scope: policy.scope,
                ratified_digest: ratified["transition_digest"]
                    .as_str()
                    .ok_or(Failure::Refused)?
                    .into(),
                ratification: t["ratification"].clone(),
                artifacts,
                pause,
                now: service_transport::now()?
                    .try_into()
                    .map_err(|_| Failure::Unavailable)?,
            };
            store.apply(&authority, &t).map_err(catalog_failure)
        }
    }
}
pub(super) async fn operate(
    State(runtime): State<Arc<Runtime>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    body: Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    admitted(&runtime,&peer,&body).await.map(Json).map_err(|error|{let unavailable=matches!(error,Failure::Unavailable);(if unavailable{StatusCode::SERVICE_UNAVAILABLE}else{StatusCode::FORBIDDEN},Json(json!({"error":if unavailable{"registry-unavailable"}else{"activation-refused"}})))})
}
