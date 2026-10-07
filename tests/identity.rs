// SPDX-License-Identifier: Apache-2.0
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use munarium_registry::{
    candidate::{Error, Permission, Query, Registry, Submission, TrustSnapshot},
    identity::{self, AccessRule, Authority, Context, IssuerKey},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn context() -> Context {
    let authority = Authority {
        digest: format!("sha256:{}", "a".repeat(64)),
        not_before: 900,
        expires: 1200,
        scopes: vec!["read".into(), "evaluate".into(), "propose".into()],
        resources: vec!["item-a".into(), "item-b".into()],
    };
    Context {
        deployment: "fixture".into(),
        tenant: "alpha".into(),
        audience: "svc-registry".into(),
        peer_service: "svc-harness".into(),
        now: 1000,
        available: true,
        restore_quarantined: false,
        keys: BTreeMap::new(),
        task: authority.clone(),
        policy: authority,
        maximum_depth: 4,
        registrations: vec![],
        access: [Permission::Submit, Permission::Read, Permission::List]
            .into_iter()
            .map(|permission| AccessRule {
                permission,
                resource: "item-a".into(),
            })
            .collect(),
    }
}
fn payload() -> Value {
    json!({"schema_version":1,"deployment":"fixture","tenant":"alpha","issuer":"test-issuer",
        "audience":"svc-registry","origin":"agent-a","actor":"agent-a","origin_kind":"agent",
        "service":"svc-harness","purpose":"decision","scopes":["read","propose"],
        "resources":["item-a"],"iat":980,"nbf":980,"exp":1040,"parent_digest":null,"bootstrap":null})
}
// Fictional deterministic key created only inside tests; never deployment provisioning.
fn key() -> SigningKey {
    SigningKey::from_bytes(&[47; 32])
}
fn signed(k: &SigningKey, p: &Value) -> String {
    let header = json!({"alg":"Ed25519","kid":"test-key","typ":"munarium-principal+jws"});
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(p).unwrap())
    );
    format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(k.sign(input.as_bytes()).to_bytes())
    )
}
fn prepared() -> (Context, Vec<String>) {
    let mut c = context();
    c.keys.insert(
        "test-key".into(),
        IssuerKey {
            public_key: URL_SAFE_NO_PAD.encode(key().verifying_key().as_bytes()),
            issuer: "test-issuer".into(),
            decision: true,
        },
    );
    (c, vec![signed(&key(), &payload())])
}
fn registration(parent: &Value, child: &Value, id: &str, c: &Context) -> Value {
    json!({"schema_version":1,"registration_id":id,"deployment":c.deployment,"tenant":c.tenant,
        "origin":child["origin"],"origin_kind":child["origin_kind"],
        "from_actor":parent["actor"],"to_actor":child["actor"],"presenter_service":child["service"],
        "audience":c.audience,"task_digest":c.task.digest,"policy_digest":c.policy.digest,
        "scopes":child["scopes"],"resources":child["resources"],"max_depth":4,"nbf":900,"exp":1200})
}
fn fixture() -> (Registry, Submission, Query) {
    let inventory: Value =
        serde_json::from_str(include_str!("../contracts/registry-v2/trust.json")).unwrap();
    let trust =
        TrustSnapshot::from_canonical_json(&serde_json::to_vec(&inventory).unwrap()).unwrap();
    let vectors: Value =
        serde_json::from_str(include_str!("../contracts/registry-v2/signed-vectors.json")).unwrap();
    let p = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "alpha")
        .unwrap();
    (
        Registry::new(trust, 32),
        Submission {
            envelope: p["envelope"].as_str().unwrap().into(),
        },
        Query {
            manifest_digest: p["manifest_digest"].as_str().unwrap().into(),
            artifact_digest: Some(p["artifact_digest"].as_str().unwrap().into()),
        },
    )
}

#[test]
fn unchanged_hub_identity_corpus_is_consumed_with_explicit_nonhuman_narrowing() {
    let all: Value = serde_json::from_str(include_str!(
        "../contracts/identity-v1/identity-vectors.json"
    ))
    .unwrap();
    assert_eq!(all["cases"].as_array().unwrap().len(), 32);
    for case in all["cases"].as_array().unwrap() {
        let mut c = context();
        let ctx = &case["context"];
        c.deployment = ctx["deployment"].as_str().unwrap().into();
        c.tenant = ctx["tenant"].as_str().unwrap().into();
        c.audience = ctx["audience"].as_str().unwrap().into();
        c.peer_service = ctx["peer_service"].as_str().unwrap().into();
        c.now = ctx["now"].as_i64().unwrap();
        c.available = ctx["authority_available"].as_bool().unwrap();
        c.restore_quarantined = ctx["restore_quarantined"].as_bool().unwrap();
        for (id, k) in all["keys"].as_object().unwrap() {
            if !ctx["retired_keys"].as_array().unwrap().contains(&json!(id)) {
                c.keys.insert(
                    id.clone(),
                    IssuerKey {
                        public_key: k["public_key"].as_str().unwrap().into(),
                        issuer: k["issuer"].as_str().unwrap().into(),
                        decision: true,
                    },
                );
            }
        }
        let chain: Vec<_> = case["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| {
                format!(
                    "{}.{}.{}",
                    t["protected"].as_str().unwrap(),
                    t["payload"].as_str().unwrap(),
                    t["signature"].as_str().unwrap()
                )
            })
            .collect();
        let payloads: Vec<Value> = case["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| {
                serde_json::from_slice(
                    &URL_SAFE_NO_PAD
                        .decode(t["payload"].as_str().unwrap())
                        .unwrap(),
                )
                .unwrap()
            })
            .collect();
        // These are fictional independent admitted records, not runtime auto-enrollment.
        for (index, pair) in payloads.windows(2).enumerate() {
            c.registrations.push(registration(
                &pair[0],
                &pair[1],
                &format!("edge-{index}"),
                &c,
            ));
        }
        let accepted = case["expected"] == "accept" && case["id"] != "valid-bootstrap";
        let result = identity::verify(&chain, &c);
        assert_eq!(result.is_ok(), accepted, "{}", case["id"]);
        if let Ok(verified) = result {
            assert_eq!(verified.principal(), payloads.last().unwrap());
            assert_eq!(
                verified.principal_digest(),
                digest(chain.last().unwrap().as_bytes())
            );
            assert_eq!(verified.registration_ids().len(), chain.len() - 1);
        }
    }
}

#[test]
fn actual_candidate_operations_reverify_identity_and_keep_intake_inert() {
    let (mut c, chain) = prepared();
    let (mut registry, submission, query) = fixture();
    let candidate = identity::submit(&mut registry, &chain, &c, &submission).unwrap();
    assert_eq!(candidate.envelope(), submission.envelope);
    assert_eq!(
        identity::resolve(&registry, &chain, &c, &query)
            .unwrap()
            .envelope(),
        submission.envelope
    );
    assert_eq!(identity::list(&registry, &chain, &c).unwrap().len(), 1);
    let evidence = identity::verify(&chain, &c).unwrap();
    assert_eq!(evidence.principal()["origin_kind"], "agent");
    assert_eq!(evidence.task_digest(), c.task.digest);
    assert_eq!(evidence.policy_digest(), c.policy.digest);
    c.keys.clear();
    assert_eq!(
        identity::resolve(&registry, &chain, &c, &query).unwrap_err(),
        Error::Unauthorized
    );
    assert!(identity::list(&registry, &chain, &c).is_err());
    assert!(identity::submit(&mut registry, &chain, &c, &submission).is_err());
    // The earlier evidence cannot be supplied as authority; restoring current host
    // admission makes the unchanged inert bytes readable again.
    let (c, _) = prepared();
    assert_eq!(
        identity::resolve(&registry, &chain, &c, &query)
            .unwrap()
            .envelope(),
        submission.envelope
    );
}

#[test]
fn permissions_scopes_and_exact_resources_are_independent() {
    let (c, chain) = prepared();
    let (mut registry, submission, query) = fixture();
    identity::submit(&mut registry, &chain, &c, &submission).unwrap();
    for permission in [Permission::Submit, Permission::Read, Permission::List] {
        let mut narrowed = c.clone();
        narrowed.access.retain(|r| r.permission != permission);
        assert_eq!(
            identity::submit(&mut registry, &chain, &narrowed, &submission).is_ok(),
            permission != Permission::Submit
        );
        assert_eq!(
            identity::resolve(&registry, &chain, &narrowed, &query).is_ok(),
            permission != Permission::Read
        );
        assert_eq!(
            identity::list(&registry, &chain, &narrowed).is_ok(),
            permission != Permission::List
        );
    }
    let mut p = payload();
    p["scopes"] = json!(["read"]);
    let read = vec![signed(&key(), &p)];
    assert!(identity::submit(&mut registry, &read, &c, &submission).is_err());
    assert!(identity::resolve(&registry, &read, &c, &query).is_ok());
    p["scopes"] = json!(["propose"]);
    let propose = vec![signed(&key(), &p)];
    assert!(identity::resolve(&registry, &propose, &c, &query).is_err());
    for resource in ["item-b", "*"] {
        let mut other = c.clone();
        for rule in &mut other.access {
            rule.resource = resource.into();
        }
        assert!(identity::submit(&mut registry, &chain, &other, &submission).is_err());
        assert!(identity::list(&registry, &chain, &other).is_err());
    }
    let mut ambiguous = c;
    ambiguous.access.push(ambiguous.access[0].clone());
    assert!(identity::submit(&mut registry, &chain, &ambiguous, &submission).is_err());
}

#[test]
fn recipient_peer_tenant_clock_and_current_authority_cannot_be_reused() {
    let (c, chain) = prepared();
    for mutation in 0..12 {
        let mut changed = c.clone();
        match mutation {
            0 => changed.tenant = "beta".into(),
            1 => changed.deployment = "other".into(),
            2 => changed.audience = "svc-server".into(),
            3 => changed.peer_service = "svc-gate".into(),
            4 => changed.available = false,
            5 => changed.restore_quarantined = true,
            6 => changed.keys.get_mut("test-key").unwrap().decision = false,
            7 => changed.task.scopes = vec!["read".into()],
            8 => changed.policy.resources = vec!["item-b".into()],
            9 => changed.policy.expires = 1039,
            10 => changed.task.not_before = 981,
            _ => changed.keys.get_mut("test-key").unwrap().issuer = "other".into(),
        }
        assert!(identity::verify(&chain, &changed).is_err(), "{mutation}");
    }
    for (now, accepted) in [
        (981, false),
        (982, true),
        (1037, true),
        (1038, false),
        (i64::MIN, false),
        (i64::MAX, false),
    ] {
        let mut changed = c.clone();
        changed.now = now;
        assert_eq!(
            identity::verify(&chain, &changed).is_ok(),
            accepted,
            "{now}"
        );
    }
    let mut wrong = payload();
    wrong["tenant"] = json!("beta");
    assert!(identity::verify(&[signed(&key(), &wrong)], &c).is_err());
}

#[test]
fn all_delegation_edges_use_their_own_presenter_and_preserve_evidence() {
    let (mut c, mut chain) = prepared();
    let root = payload();
    let mut middle = root.clone();
    middle["actor"] = json!("agent-b");
    middle["service"] = json!("svc-middle");
    middle["parent_digest"] = json!(digest(chain[0].as_bytes()));
    chain.push(signed(&key(), &middle));
    let mut leaf = middle.clone();
    leaf["actor"] = json!("agent-c");
    leaf["service"] = json!("svc-harness");
    leaf["parent_digest"] = json!(digest(chain[1].as_bytes()));
    leaf["scopes"] = json!(["read"]);
    chain.push(signed(&key(), &leaf));
    c.registrations = vec![
        registration(&root, &middle, "first", &c),
        registration(&middle, &leaf, "second", &c),
    ];
    assert_eq!(
        identity::verify(&chain, &c).unwrap().registration_ids(),
        ["first", "second"]
    );
    for change in 0..11 {
        let mut bad = c.clone();
        match change {
            0 => {
                bad.registrations.remove(0);
            }
            1 => {
                let mut duplicate = bad.registrations[0].clone();
                duplicate["registration_id"] = json!("third");
                bad.registrations.push(duplicate);
            }
            2 => bad.registrations[0]["presenter_service"] = json!("svc-harness"),
            3 => bad.registrations[0]["task_digest"] = json!(format!("sha256:{}", "b".repeat(64))),
            4 => bad.registrations[0]["max_depth"] = json!(1),
            5 => bad.registrations[0]["exp"] = json!(999),
            6 => bad.registrations[0]["scopes"] = json!(["read"]),
            7 => bad.registrations[1]["registration_id"] = json!("first"),
            8 => bad.maximum_depth = 1,
            9 => bad.registrations[0]["unknown"] = json!(true),
            _ => bad.registrations[0]["tenant"] = json!("beta"),
        }
        assert!(identity::verify(&chain, &bad).is_err(), "{change}");
    }
    assert!(identity::verify(&chain[1..], &c).is_err());
    chain.reverse();
    assert!(identity::verify(&chain, &c).is_err());
}

#[test]
fn signed_malformed_or_privileged_payloads_never_authorize() {
    let (c, _) = prepared();
    for change in 0..14 {
        let mut p = payload();
        match change {
            0 => p["origin_kind"] = json!("human"),
            1 => p["purpose"] = json!("bootstrap"),
            2 => p["scopes"] = json!(["govern"]),
            3 => p["scopes"] = json!(["ratify"]),
            4 => {
                p.as_object_mut().unwrap().remove("bootstrap");
            }
            5 => p["scopes"] = json!(["read", "read"]),
            6 => p["actor"] = json!("different"),
            7 => p["schema_version"] = json!(2),
            8 => p["exp"] = json!(1041),
            9 => p["resources"] = json!(["*"]),
            10 => p["verified"] = json!(true),
            11 => p["iat"] = json!(-1),
            12 => p["parent_digest"] = json!(format!("sha256:{}", "a".repeat(64))),
            _ => {
                p.as_object_mut().unwrap().remove("parent_digest");
            }
        }
        assert!(
            identity::verify(&[signed(&key(), &p)], &c).is_err(),
            "{change}"
        );
    }
    let attribution = json!({"schema_version":1,"purpose":"attribution-only","deployment":"fixture",
        "tenant":"alpha","sender_service":"svc-gate","recipient_service":"svc-registry",
        "principal_digest":format!("sha256:{}", "a".repeat(64)),
        "request_digest":format!("sha256:{}", "b".repeat(64))});
    assert!(identity::verify(&[signed(&key(), &attribution)], &c).is_err());
    assert!(identity::verify(&[attribution.to_string()], &c).is_err());
}

#[test]
fn identity_input_limits_and_signature_failures_leave_no_candidate() {
    let (c, chain) = prepared();
    let (mut registry, submission, _) = fixture();
    let token = &chain[0];
    let parts: Vec<_> = token.split('.').collect();
    let cases = vec![
        vec![],
        vec![token.clone(); 6],
        vec!["x".repeat(65_537)],
        vec![format!("{token}.")],
        vec![format!("{}.{}.AA", parts[0], parts[1])],
        vec![format!("{}=.{}.{}", parts[0], parts[1], parts[2])],
        vec![format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(
                b"{\"alg\":\"Ed25519\", \"kid\":\"test-key\",\"typ\":\"munarium-principal+jws\"}"
            ),
            parts[1],
            parts[2]
        )],
    ];
    for malformed in cases {
        assert!(identity::submit(&mut registry, &malformed, &c, &submission).is_err());
        assert!(identity::list(&registry, &chain, &c).unwrap().is_empty());
    }
    let mut weak = c;
    weak.keys.get_mut("test-key").unwrap().public_key = URL_SAFE_NO_PAD.encode([0; 32]);
    assert!(identity::verify(&chain, &weak).is_err());
}

#[test]
fn identity_bundle_pins_match_the_unmodified_hub_locks() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("contracts/identity-v1");
    for (file, expected) in [
        ("candidate-lock.json", identity::FOUNDATION_DIGEST),
        ("warden-admission-lock.json", identity::ADMISSION_DIGEST),
    ] {
        let lock: Value = serde_json::from_slice(&std::fs::read(root.join(file)).unwrap()).unwrap();
        let mut aggregate = String::new();
        for (name, hash) in lock["files"].as_object().unwrap() {
            assert!(!name.contains('/') && !name.contains('\\'));
            let raw = std::fs::read_to_string(root.join(name))
                .unwrap()
                .replace("\r\n", "\n");
            assert_eq!(
                digest(raw.as_bytes()),
                format!("sha256:{}", hash.as_str().unwrap())
            );
            aggregate.push_str(&format!("{name}\0{}\n", hash.as_str().unwrap()));
        }
        assert_eq!(digest(aggregate.as_bytes()), format!("sha256:{expected}"));
        assert_eq!(lock["bundle_sha256"], expected);
    }
}

#[test]
fn gate_uses_its_own_recipient_identity_and_cannot_cross_tenants() {
    let (mut c, _) = prepared();
    c.peer_service = "svc-gate".into();
    let mut p = payload();
    p["origin_kind"] = json!("service");
    p["origin"] = json!("svc-gate");
    p["actor"] = json!("svc-gate");
    p["service"] = json!("svc-gate");
    let chain = vec![signed(&key(), &p)];
    let evidence = identity::verify(&chain, &c).unwrap();
    assert_eq!(evidence.principal()["origin"], "svc-gate");
    assert_eq!(evidence.principal()["origin_kind"], "service");
    let (mut registry, submission, query) = fixture();
    identity::submit(&mut registry, &chain, &c, &submission).unwrap();
    assert!(identity::resolve(&registry, &chain, &c, &query).is_ok());
    // The same provisioned public key does not share alpha's inventory with beta.
    let mut beta = c.clone();
    beta.tenant = "beta".into();
    p["tenant"] = json!("beta");
    let beta_chain = vec![signed(&key(), &p)];
    assert!(identity::verify(&beta_chain, &beta).is_ok());
    assert_eq!(
        identity::resolve(&registry, &beta_chain, &beta, &query).unwrap_err(),
        Error::NotFound
    );
    assert!(
        identity::list(&registry, &beta_chain, &beta)
            .unwrap()
            .is_empty()
    );
    assert!(identity::submit(&mut registry, &beta_chain, &beta, &submission).is_err());
    // A valid Gate-audience signature cannot be reused at Registry.
    p["tenant"] = json!("alpha");
    p["audience"] = json!("svc-gate");
    assert!(identity::resolve(&registry, &[signed(&key(), &p)], &c, &query).is_err());
}
