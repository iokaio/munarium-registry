// SPDX-License-Identifier: Apache-2.0
// Built only by scripts/verify_warden.py against the pinned public Warden revision.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use munarium_registry::identity::{self, Authority, Context, IssuerKey};
use munarium_warden::principal::{self, Delegation, Trust, TrustedKey};
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn text(v: &Value, name: &str) -> String {
    v[name].as_str().unwrap().into()
}
fn strings(v: &Value, name: &str) -> Vec<String> {
    v[name]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().into())
        .collect()
}

fn main() {
    let all: Value = serde_json::from_str(include_str!(env!("REGISTRY_IDENTITY_VECTORS"))).unwrap();
    let mut accepted = 0;
    let mut rejected = 0;
    for case in all["cases"].as_array().unwrap() {
        let ctx = &case["context"];
        let authority = Authority {
            digest: format!("sha256:{}", "a".repeat(64)),
            not_before: 900,
            expires: 1200,
            scopes: vec!["read".into(), "evaluate".into(), "propose".into()],
            resources: vec!["item-a".into(), "item-b".into()],
        };
        let mut registry = Context {
            deployment: text(ctx, "deployment"),
            tenant: text(ctx, "tenant"),
            audience: text(ctx, "audience"),
            peer_service: text(ctx, "peer_service"),
            now: ctx["now"].as_i64().unwrap(),
            available: ctx["authority_available"].as_bool().unwrap(),
            restore_quarantined: ctx["restore_quarantined"].as_bool().unwrap(),
            keys: BTreeMap::new(),
            task: authority.clone(),
            policy: authority,
            maximum_depth: 4,
            registrations: vec![],
            access: vec![],
        };
        let mut warden = Trust {
            deployment: registry.deployment.clone(),
            tenant: registry.tenant.clone(),
            audience: registry.audience.clone(),
            peer_service: registry.peer_service.clone(),
            now: registry.now,
            available: registry.available && !registry.restore_quarantined,
            keys: BTreeMap::new(),
            delegations: vec![],
            task_digest: registry.task.digest.clone(),
            policy_digest: registry.policy.digest.clone(),
            not_before: 900,
            expires: 1200,
            scopes: registry.task.scopes.clone(),
            resources: registry.task.resources.clone(),
            maximum_depth: 4,
        };
        for (id, k) in all["keys"].as_object().unwrap() {
            if ctx["retired_keys"].as_array().unwrap().contains(&json!(id)) {
                continue;
            }
            registry.keys.insert(
                id.clone(),
                IssuerKey {
                    public_key: text(k, "public_key"),
                    issuer: text(k, "issuer"),
                    decision: true,
                },
            );
            warden.keys.insert(
                id.clone(),
                TrustedKey {
                    public_key: URL_SAFE_NO_PAD
                        .decode(text(k, "public_key"))
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    issuer: text(k, "issuer"),
                    decision: true,
                },
            );
        }
        let tokens = case["tokens"].as_array().unwrap();
        let chain: Vec<_> = tokens
            .iter()
            .map(|t| {
                format!(
                    "{}.{}.{}",
                    text(t, "protected"),
                    text(t, "payload"),
                    text(t, "signature")
                )
            })
            .collect();
        let payloads: Vec<Value> = tokens
            .iter()
            .map(|t| {
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(text(t, "payload")).unwrap())
                    .unwrap()
            })
            .collect();
        for (i, pair) in payloads.windows(2).enumerate() {
            let (parent, child) = (&pair[0], &pair[1]);
            let id = format!("edge-{i}");
            registry.registrations.push(json!({"schema_version":1,"registration_id":id,
                "deployment":registry.deployment,"tenant":registry.tenant,"origin":child["origin"],
                "origin_kind":child["origin_kind"],"from_actor":parent["actor"],"to_actor":child["actor"],
                "presenter_service":child["service"],"audience":registry.audience,
                "task_digest":registry.task.digest,"policy_digest":registry.policy.digest,
                "scopes":child["scopes"],"resources":child["resources"],"max_depth":4,"nbf":900,"exp":1200}));
            warden.delegations.push(Delegation {
                registration_id: id,
                deployment: warden.deployment.clone(),
                tenant: warden.tenant.clone(),
                origin_kind: text(child, "origin_kind"),
                audience: warden.audience.clone(),
                task_digest: warden.task_digest.clone(),
                policy_digest: warden.policy_digest.clone(),
                origin: text(child, "origin"),
                from: text(parent, "actor"),
                to: text(child, "actor"),
                service: text(child, "service"),
                scopes: strings(child, "scopes"),
                resources: strings(child, "resources"),
                not_before: 900,
                expires: 1200,
                maximum_depth: 4,
            });
        }
        let a = identity::verify(&chain, &registry);
        let b = principal::verify(&chain, &warden);
        let expected = case["expected"] == "accept" && case["id"] != "valid-bootstrap";
        assert_eq!(a.is_ok(), expected, "Registry: {}", case["id"]);
        assert_eq!(b.is_ok(), expected, "Warden: {}", case["id"]);
        if let (Ok(a), Ok(b)) = (a, b) {
            assert_eq!(a.principal_digest(), b.fingerprint());
            assert_eq!(a.principal()["origin"], b.origin());
            assert_eq!(a.principal()["actor"], b.actor());
            assert_eq!(a.principal()["tenant"], b.tenant());
            assert_eq!(a.principal()["origin_kind"], b.origin_kind());
            assert_eq!(a.principal()["audience"], b.audience());
            assert_eq!(a.principal()["service"], b.service());
            assert_eq!(strings(a.principal(), "scopes"), b.scopes());
            assert_eq!(strings(a.principal(), "resources"), b.resources());
            accepted += 1;
        } else {
            rejected += 1;
        }
    }
    assert_eq!(accepted + rejected, 32);
    println!(
        "Registry and actual Warden agree on all 32 unchanged signed cases: {accepted} accepted, {rejected} refused; accepted leaf identity and digests agree."
    );
}
