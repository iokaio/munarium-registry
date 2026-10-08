// SPDX-License-Identifier: Apache-2.0
//! Authenticated inert candidates and a separately authorized activation adapter.
mod activation_service;
#[path = "../vendor/warden-transport/service_transport.rs"]
mod service_transport;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, State},
    http::StatusCode,
    routing::post,
};
use munarium_registry::{
    candidate::{Caller, Candidate, Permission, Query, Registry, Submission, TrustSnapshot},
    catalog::CatalogReader,
    intake::CandidateIntake,
    policy, principal,
};
use serde::Deserialize;
use serde_json::{Value, json};
use service_transport::{Failure, Peer, TlsConfig};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    tls: TlsConfig,
    server_endpoint: String,
    deployment: String,
    service: String,
    database_directory: PathBuf,
    capacity: usize,
    council_endpoint: Option<String>,
    gate_endpoint: Option<String>,
}
struct Catalog {
    registry: Registry,
    trust: Vec<u8>,
}
struct Runtime {
    config: Config,
    client: reqwest::Client,
    catalogs: tokio::sync::Mutex<BTreeMap<String, Catalog>>,
    permits: tokio::sync::Semaphore,
    activations: tokio::sync::Mutex<BTreeMap<String, munarium_registry::activation_store::Store>>,
}
fn catalog_failure(error: munarium_registry::candidate::Error) -> Failure {
    match error {
        munarium_registry::candidate::Error::StorageUnavailable
        | munarium_registry::candidate::Error::TrustUnavailable => Failure::Unavailable,
        _ => Failure::Refused,
    }
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
enum Operation {
    Submit {
        envelope: String,
    },
    Resolve {
        manifest_digest: String,
        artifact_digest: Option<String>,
    },
    List,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    tenant: String,
    chain: Vec<String>,
    action: Operation,
}
fn candidate(value: &Candidate) -> Value {
    json!({"status":"candidate","active":false,"manifest":value.manifest(),"envelope":value.envelope(),
        "manifest_digest":value.manifest_digest(),"artifact_digest":value.artifact_digest(),
        "admission_revision":value.admission_revision(),"verified_revision":value.verified_revision()})
}
async fn operate(
    State(runtime): State<Arc<Runtime>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    body: Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    async fn admitted(runtime: &Runtime, peer: &Peer, body: &[u8]) -> Result<Value, Failure> {
        let _permit = runtime
            .permits
            .try_acquire()
            .map_err(|_| Failure::Unavailable)?;
        let request: Request = serde_json::from_slice(body).map_err(|_| Failure::Refused)?;
        if !peer.tenants.contains(&request.tenant) {
            return Err(Failure::Refused);
        }
        // No cached snapshot is used if this read fails.
        let state = service_transport::authority(
            &runtime.client,
            &runtime.config.server_endpoint,
            &runtime.config.deployment,
            &request.tenant,
        )
        .await?;
        let bindings = &state["artifact"]["bindings"];
        let trust = policy::current(
            &bindings[format!("identity:{}", runtime.config.service)],
            &runtime.config.deployment,
            &request.tenant,
            &runtime.config.service,
            &peer.service,
            service_transport::now()?,
        )
        .map_err(|_| Failure::Refused)?;
        let principal = principal::verify(&request.chain, &trust).map_err(|_| Failure::Refused)?;
        let (scope, permission) = match &request.action {
            Operation::Submit { .. } => ("propose", Permission::Submit),
            Operation::Resolve { .. } => ("read", Permission::Read),
            Operation::List => ("read", Permission::List),
        };
        if !principal.permits(scope, &format!("registry:{}", request.tenant)) {
            return Err(Failure::Refused);
        }
        let caller = Caller::from_verified_identity(&request.tenant, &[permission])
            .map_err(|_| Failure::Refused)?;
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
            .map_err(|_| Failure::Unavailable)?;
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
        match request.action {
            Operation::Submit { envelope } => catalog
                .registry
                .intake(&caller)
                .submit(&Submission { envelope })
                .map(|c| candidate(&c))
                .map_err(catalog_failure),
            Operation::Resolve {
                manifest_digest,
                artifact_digest,
            } => catalog
                .registry
                .reader(&caller)
                .resolve(&Query {
                    manifest_digest,
                    artifact_digest,
                })
                .map(|c| candidate(&c))
                .map_err(catalog_failure),
            Operation::List => catalog
                .registry
                .reader(&caller)
                .list()
                .map(|items| json!({"candidates":items.iter().map(candidate).collect::<Vec<_>>()}))
                .map_err(catalog_failure),
        }
    }
    admitted(&runtime,&peer,&body).await.map(Json).map_err(|error| {
        let unavailable=matches!(error,Failure::Unavailable);
        (if unavailable {StatusCode::SERVICE_UNAVAILABLE} else {StatusCode::FORBIDDEN},Json(json!({"error":if unavailable {"registry-unavailable"} else {"candidate-refused"}})))
    })
}
async fn run() -> Result<(), Failure> {
    let path = std::env::args_os().nth(1).ok_or(Failure::Configuration)?;
    let raw = std::fs::read(path).map_err(|_| Failure::Configuration)?;
    if raw.len() > 1048576 {
        return Err(Failure::Configuration);
    }
    let config: Config = serde_json::from_slice(&raw).map_err(|_| Failure::Configuration)?;
    if !config.database_directory.is_absolute()
        || !config.database_directory.is_dir()
        || config.capacity == 0
        || config.capacity > 100000
    {
        return Err(Failure::Configuration);
    }
    let client = service_transport::client(&config.tls)?;
    let listener = service_transport::Mtls::bind(&config.tls).await?;
    let runtime = Arc::new(Runtime {
        config,
        client,
        catalogs: tokio::sync::Mutex::new(BTreeMap::new()),
        permits: tokio::sync::Semaphore::new(32),
        activations: tokio::sync::Mutex::new(BTreeMap::new()),
    });
    let router = Router::new()
        .route("/v1/candidates", post(operate))
        .route("/v1/activation", post(activation_service::operate))
        .layer(DefaultBodyLimit::max(131072))
        .with_state(runtime);
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<Peer>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
    .map_err(|_| Failure::Unavailable)
}
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("Registry service unavailable: {error:?}");
        std::process::exit(1);
    }
}
