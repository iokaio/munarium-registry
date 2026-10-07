// SPDX-License-Identifier: Apache-2.0
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use munarium_registry::{
    candidate::{
        CONTRACT_DIGEST, Caller, Error, Permission, Query, Registry, Submission, TrustSnapshot,
    },
    catalog::CatalogReader,
    intake::CandidateIntake,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn vectors() -> Value {
    serde_json::from_str(include_str!("../contracts/registry-v2/signed-vectors.json")).unwrap()
}

#[test]
#[cfg(feature = "sqlite")]
fn durable_catalog_restarts_with_exact_bytes_and_rechecks_current_revocation() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("catalog.sqlite");
    let alpha = caller("alpha");
    let first;
    {
        let mut registry = Registry::open(&path, snapshot(&trust_value()), 32).unwrap();
        first = registry
            .intake(&alpha)
            .submit(&submission("alpha"))
            .unwrap();
        assert!(matches!(
            Registry::open(&path, snapshot(&trust_value()), 32),
            Err(Error::StorageUnavailable)
        ));
        assert_eq!(
            registry
                .intake(&alpha)
                .submit(&submission("alpha"))
                .unwrap()
                .artifact_digest(),
            first.artifact_digest()
        );
    }
    let mut registry = Registry::open(&path, snapshot(&trust_value()), 32).unwrap();
    let read = registry.reader(&alpha).resolve(&query("alpha")).unwrap();
    assert_eq!(read.envelope(), first.envelope());
    assert_eq!(read.admission_revision(), first.admission_revision());
    assert!(
        registry
            .reader(&caller("beta"))
            .resolve(&query("alpha"))
            .is_err()
    );
    let mut revoked = trust_value();
    revoked["revision"] = json!(2);
    revoked["tenants"][0]["publishers"][0]["enabled"] = json!(false);
    registry.replace_trust(Some(snapshot(&revoked))).unwrap();
    assert!(registry.reader(&alpha).resolve(&query("alpha")).is_err());
    drop(registry);
    assert!(matches!(
        Registry::open(&path, snapshot(&trust_value()), 32),
        Err(Error::StaleTrust)
    ));
    let registry = Registry::open(&path, snapshot(&revoked), 32).unwrap();
    assert!(registry.reader(&alpha).resolve(&query("alpha")).is_err());
    drop(registry);
    let mut substituted = revoked.clone();
    substituted["tenants"][0]["publishers"][0]["enabled"] = json!(true);
    assert!(matches!(
        Registry::open(&path, snapshot(&substituted), 32),
        Err(Error::StaleTrust)
    ));
    let raw = rusqlite::Connection::open(&path).unwrap();
    assert!(raw.execute("DELETE FROM catalog_trust_pins", []).is_err());
    assert!(
        raw.execute("UPDATE catalog_trust_pins SET digest='substituted'", [])
            .is_err()
    );
    assert!(raw.execute("DELETE FROM candidates", []).is_err());
    assert!(
        raw.execute("UPDATE candidates SET envelope='different'", [])
            .is_err()
    );
    assert_eq!(
        raw.query_row("SELECT count(*) FROM candidates", [], |row| row
            .get::<_, usize>(0))
            .unwrap(),
        1
    );
}

#[test]
#[cfg(feature = "sqlite")]
fn failed_durable_admission_never_returns_an_acknowledgement() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("catalog.sqlite");
    let mut registry = Registry::open(&path, snapshot(&trust_value()), 32).unwrap();
    let alpha = caller("alpha");
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(matches!(
        registry.intake(&alpha).submit(&submission("alpha")),
        Err(Error::StorageUnavailable)
    ));
    assert!(matches!(
        registry.reader(&alpha).list(),
        Err(Error::TrustUnavailable)
    ));
    raw.execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        raw.query_row("SELECT count(*) FROM candidates", [], |row| row
            .get::<_, usize>(0))
            .unwrap(),
        0
    );
    drop(raw);
    drop(registry);
    let registry = Registry::open(&path, snapshot(&trust_value()), 32).unwrap();
    assert!(registry.reader(&alpha).list().unwrap().is_empty());
}
fn trust_value() -> Value {
    serde_json::from_str(include_str!("../contracts/registry-v2/trust.json")).unwrap()
}
fn snapshot(value: &Value) -> TrustSnapshot {
    TrustSnapshot::from_canonical_json(&serde_json::to_vec(value).unwrap()).unwrap()
}
fn registry() -> Registry {
    Registry::new(snapshot(&trust_value()), 32)
}
fn caller(tenant: &str) -> Caller {
    Caller::from_verified_identity(
        tenant,
        &[Permission::Submit, Permission::Read, Permission::List],
    )
    .unwrap()
}
fn vector(name: &str) -> Value {
    vectors()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == name)
        .unwrap()
        .clone()
}
fn submission(name: &str) -> Submission {
    Submission {
        envelope: vector(name)["envelope"].as_str().unwrap().into(),
    }
}
fn query(name: &str) -> Query {
    Query {
        manifest_digest: vector(name)["manifest_digest"].as_str().unwrap().into(),
        artifact_digest: Some(vector(name)["artifact_digest"].as_str().unwrap().into()),
    }
}

#[test]
fn signed_hub_vectors_match_bytes_hashes_and_typed_refusals() {
    let all = vectors();
    assert_eq!(all["cases"].as_array().unwrap().len(), 32);
    for case in all["cases"].as_array().unwrap() {
        let mut store = registry();
        let identity = caller(case["tenant"].as_str().unwrap());
        let envelope = case["envelope"].as_str().unwrap();
        let result = store.intake(&identity).submit(&Submission {
            envelope: envelope.into(),
        });
        if case["expected"] == "accept" {
            let admitted = result.unwrap_or_else(|e| panic!("{}: {e}", case["id"]));
            assert_eq!(admitted.envelope(), envelope);
            assert_eq!(
                admitted.payload(),
                case["payload"].as_str().unwrap().as_bytes()
            );
            assert_eq!(admitted.manifest_digest(), case["manifest_digest"]);
            assert_eq!(admitted.artifact_digest(), case["artifact_digest"]);
            let resolved = store
                .reader(&identity)
                .resolve(&Query {
                    manifest_digest: admitted.manifest_digest().into(),
                    artifact_digest: None,
                })
                .unwrap();
            assert_eq!(resolved.envelope(), envelope);
            assert_eq!(resolved.verified_revision(), 1);
        } else {
            assert_eq!(
                result.unwrap_err().to_string(),
                case["expected"].as_str().unwrap(),
                "{}",
                case["id"]
            );
            assert!(store.reader(&identity).list().unwrap().is_empty());
        }
    }
}

#[test]
fn immutable_identity_rejects_substitution_and_resigning_but_allows_exact_retry() {
    let mut store = registry();
    let alpha = caller("alpha");
    store.intake(&alpha).submit(&submission("alpha")).unwrap();
    for name in ["changed-bytes", "resigned", "approval"] {
        assert_eq!(
            store.intake(&alpha).submit(&submission(name)).unwrap_err(),
            Error::Conflict
        );
        assert_eq!(
            store
                .reader(&alpha)
                .resolve(&query("alpha"))
                .unwrap()
                .envelope(),
            submission("alpha").envelope
        );
    }
    store.intake(&alpha).submit(&submission("alpha")).unwrap();
    assert_eq!(store.reader(&alpha).list().unwrap().len(), 1);
    store
        .intake(&alpha)
        .submit(&submission("new-version"))
        .unwrap();
    assert_eq!(store.reader(&alpha).list().unwrap().len(), 2);
}

#[test]
fn tenant_and_digest_bindings_refuse_cross_tenant_or_fallback_reads() {
    let mut store = registry();
    let alpha = caller("alpha");
    let beta = caller("beta");
    store.intake(&alpha).submit(&submission("alpha")).unwrap();
    assert!(store.reader(&beta).list().unwrap().is_empty());
    assert_eq!(
        store.reader(&beta).resolve(&query("alpha")).unwrap_err(),
        Error::NotFound
    );
    assert_eq!(
        store
            .intake(&beta)
            .submit(&submission("alpha"))
            .unwrap_err(),
        Error::Unauthorized
    );
    store.intake(&beta).submit(&submission("beta")).unwrap();
    assert_eq!(store.reader(&alpha).list().unwrap().len(), 1);
    assert_eq!(
        store.reader(&beta).list().unwrap()[0].manifest()["tenant"],
        "beta"
    );
    let mut wrong = query("alpha");
    wrong.artifact_digest = query("beta").artifact_digest;
    assert_eq!(
        store.reader(&alpha).resolve(&wrong).unwrap_err(),
        Error::NotFound
    );
    wrong.manifest_digest = "sha256:".to_owned() + &"f".repeat(64);
    wrong.artifact_digest = None;
    assert_eq!(
        store.reader(&alpha).resolve(&wrong).unwrap_err(),
        Error::NotFound
    );
}

#[test]
fn read_list_and_submit_permissions_are_independent() {
    let mut store = registry();
    let alpha = caller("alpha");
    store.intake(&alpha).submit(&submission("alpha")).unwrap();
    for permissions in [
        vec![],
        vec![Permission::Read],
        vec![Permission::List],
        vec![Permission::Submit],
    ] {
        let c = Caller::from_verified_identity("alpha", &permissions).unwrap();
        assert_eq!(
            store.reader(&c).resolve(&query("alpha")).is_ok(),
            permissions.contains(&Permission::Read)
        );
        assert_eq!(
            store.reader(&c).list().is_ok(),
            permissions.contains(&Permission::List)
        );
        assert_eq!(
            store.intake(&c).submit(&submission("alpha")).is_ok(),
            permissions.contains(&Permission::Submit)
        );
    }
    let unknown = caller("missing");
    assert_eq!(
        store
            .intake(&unknown)
            .submit(&submission("alpha"))
            .unwrap_err(),
        Error::Unauthorized
    );
}

#[test]
fn current_trust_is_rechecked_on_read_list_and_retry_without_erasing_bytes() {
    let mut store = registry();
    let alpha = caller("alpha");
    store.intake(&alpha).submit(&submission("alpha")).unwrap();
    let mut trust = trust_value();
    trust["revision"] = json!(2);
    trust["tenants"][0]["publishers"][0]["enabled"] = json!(false);
    store.replace_trust(Some(snapshot(&trust))).unwrap();
    assert_eq!(
        store.reader(&alpha).resolve(&query("alpha")).unwrap_err(),
        Error::UntrustedPublisher
    );
    assert_eq!(
        store.reader(&alpha).list().unwrap_err(),
        Error::UntrustedPublisher
    );
    assert_eq!(
        store
            .intake(&alpha)
            .submit(&submission("alpha"))
            .unwrap_err(),
        Error::UntrustedPublisher
    );
    trust["revision"] = json!(3);
    trust["tenants"][0]["publishers"][0]["enabled"] = json!(true);
    store.replace_trust(Some(snapshot(&trust))).unwrap();
    let result = store.reader(&alpha).resolve(&query("alpha")).unwrap();
    assert_eq!(result.envelope(), submission("alpha").envelope);
    assert_eq!(
        (result.admission_revision(), result.verified_revision()),
        (1, 3)
    );
    let retry = store.intake(&alpha).submit(&submission("alpha")).unwrap();
    assert_eq!(
        (retry.admission_revision(), retry.verified_revision()),
        (1, 3)
    );
}

#[test]
fn unavailable_or_rolled_back_trust_cannot_restore_permission() {
    let mut store = registry();
    let alpha = caller("alpha");
    store.intake(&alpha).submit(&submission("alpha")).unwrap();
    store.replace_trust(None).unwrap();
    assert_eq!(
        store.reader(&alpha).resolve(&query("alpha")).unwrap_err(),
        Error::TrustUnavailable
    );
    assert_eq!(
        store.reader(&alpha).list().unwrap_err(),
        Error::TrustUnavailable
    );
    assert_eq!(
        store
            .intake(&alpha)
            .submit(&submission("alpha"))
            .unwrap_err(),
        Error::TrustUnavailable
    );
    assert_eq!(
        store.replace_trust(Some(snapshot(&trust_value()))),
        Err(Error::StaleTrust)
    );
    assert_eq!(
        store.reader(&alpha).list().unwrap_err(),
        Error::TrustUnavailable
    );
}

#[test]
fn narrowing_publisher_owner_or_operation_scope_revokes_only_that_tenants_reads() {
    for narrow_owner in [true, false] {
        let mut store = registry();
        let alpha = caller("alpha");
        let beta = caller("beta");
        store.intake(&alpha).submit(&submission("alpha")).unwrap();
        store.intake(&beta).submit(&submission("beta")).unwrap();
        let mut trust = trust_value();
        trust["revision"] = json!(2);
        if narrow_owner {
            trust["tenants"][0]["owners"]
                .as_array_mut()
                .unwrap()
                .push(json!({"id":"other-owner","kind":"organization"}));
            trust["tenants"][0]["publishers"][0]["owner_ids"] = json!(["other-owner"]);
        } else {
            let mut operation = trust["tenants"][0]["operations"][0].clone();
            operation["operation_id"] = json!("other-operation");
            trust["tenants"][0]["operations"]
                .as_array_mut()
                .unwrap()
                .push(operation.clone());
            trust["tenants"][0]["publishers"][0]["operations"] = json!([operation]);
        }
        store.replace_trust(Some(snapshot(&trust))).unwrap();
        assert_eq!(
            store.reader(&alpha).resolve(&query("alpha")).unwrap_err(),
            Error::UntrustedPublisher
        );
        assert_eq!(
            store
                .reader(&beta)
                .resolve(&query("beta"))
                .unwrap()
                .envelope(),
            submission("beta").envelope
        );
    }
}

#[test]
fn invalid_trust_and_schema_substitutions_are_rejected() {
    let original = trust_value();
    let mut cases = Vec::new();
    let mut t = original.clone();
    t["tenants"]
        .as_array_mut()
        .unwrap()
        .push(original["tenants"][0].clone());
    cases.push(t);
    let mut t = original.clone();
    t["tenants"][0]["publishers"]
        .as_array_mut()
        .unwrap()
        .push(original["tenants"][0]["publishers"][0].clone());
    cases.push(t);
    let mut t = original.clone();
    t["tenants"][0]["owners"][0]["kind"] = json!("agent");
    cases.push(t);
    let mut t = original.clone();
    t["tenants"][0]["schemas"][0]["canonical"] = json!("{}");
    cases.push(t);
    let mut t = original.clone();
    t["tenants"][0]["schemas"].as_array_mut().unwrap().clear();
    cases.push(t);
    let mut t = original.clone();
    t["tenants"][0]["publishers"][0]["public_key"] =
        json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    cases.push(t);
    let mut t = original.clone();
    t["tenants"][0]["operations"][0]["parameter_schema_digest"] =
        json!("sha256:".to_owned() + &"f".repeat(64));
    cases.push(t);
    for t in cases {
        assert_eq!(
            TrustSnapshot::from_canonical_json(&serde_json::to_vec(&t).unwrap()).unwrap_err(),
            Error::InvalidTrust
        );
    }
}

#[test]
fn capacity_and_invalid_submission_do_not_change_existing_inventory() {
    let mut store = Registry::new(snapshot(&trust_value()), 1);
    let alpha = caller("alpha");
    store.intake(&alpha).submit(&submission("alpha")).unwrap();
    assert_eq!(
        store
            .intake(&alpha)
            .submit(&submission("new-version"))
            .unwrap_err(),
        Error::Capacity
    );
    store.intake(&alpha).submit(&submission("alpha")).unwrap();
    for case in vectors()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["expected"] != "accept")
    {
        let c = caller(case["tenant"].as_str().unwrap());
        assert!(
            store
                .intake(&c)
                .submit(&Submission {
                    envelope: case["envelope"].as_str().unwrap().into()
                })
                .is_err()
        );
    }
    assert_eq!(store.reader(&alpha).list().unwrap().len(), 1);
    assert_eq!(
        store
            .reader(&alpha)
            .resolve(&query("alpha"))
            .unwrap()
            .envelope(),
        submission("alpha").envelope
    );
    let beta = caller("beta");
    store.intake(&beta).submit(&submission("beta")).unwrap();
    assert_eq!(store.reader(&beta).list().unwrap().len(), 1);
}

#[test]
fn contract_bundle_is_pinned_and_vendored_without_changes() {
    let lock: Value =
        serde_json::from_str(include_str!("../contracts/registry-v2/bundle-lock.json")).unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("contracts/registry-v2");
    let mut aggregate = String::new();
    for (name, expected) in lock["files"].as_object().unwrap() {
        assert!(!name.contains('/') && !name.contains('\\'));
        let bytes = std::fs::read(root.join(name)).unwrap();
        let normalized = String::from_utf8(bytes).unwrap().replace("\r\n", "\n");
        let hash = format!("{:x}", Sha256::digest(normalized.as_bytes()));
        assert_eq!(&hash, expected.as_str().unwrap(), "{name}");
        aggregate.push_str(&format!("{name}\0{hash}\n"));
    }
    assert_eq!(
        format!("{:x}", Sha256::digest(aggregate.as_bytes())),
        CONTRACT_DIGEST
    );
    assert_eq!(lock["bundle_sha256"], CONTRACT_DIGEST);
}

#[test]
fn malformed_envelopes_are_bounded_before_decoding_and_never_admitted() {
    let valid = submission("alpha").envelope;
    let parts: Vec<_> = valid.split('.').collect();
    let bad = [
        "x".repeat(90_001),
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(vec![b'x'; 513]),
            parts[1],
            parts[2]
        ),
        format!(
            "{}.{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(vec![b'x'; 65_537]),
            parts[2]
        ),
        format!(
            "{}.{}.{}",
            parts[0],
            parts[1],
            URL_SAFE_NO_PAD.encode(vec![0; 65])
        ),
        format!("{valid}.extra"),
        format!(
            "{}.{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(b"{\"x\":\"\xff\"}"),
            parts[2]
        ),
    ];
    let mut store = registry();
    let alpha = caller("alpha");
    for envelope in bad {
        assert_eq!(
            store
                .intake(&alpha)
                .submit(&Submission { envelope })
                .unwrap_err(),
            Error::InvalidArtifact
        );
        assert!(store.reader(&alpha).list().unwrap().is_empty());
    }
}
