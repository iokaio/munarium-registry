// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "sqlite")]
use munarium_registry::{
    activation_store::{Authority, Store, VerifiedArtifact},
    candidate::Error,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
fn vectors() -> Value {
    serde_json::from_str(include_str!("../contracts/stage2-v1/vectors.json")).unwrap()
}
fn digest(domain: &str, value: &Value) -> String {
    format!(
        "sha256:{:x}",
        Sha256::digest(
            format!(
                "munarium:stage2:{domain}:v1\0{}",
                serde_json::to_string(value).unwrap()
            )
            .as_bytes()
        )
    )
}
fn auth(v: &Value) -> Authority {
    let t = &v["records"]["activation"];
    Authority {
        scope: t["scope"].clone(),
        ratified_digest: digest("activation", t),
        ratification: t["ratification"].clone(),
        pause: v["records"]["pause"].clone(),
        artifacts: t["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| VerifiedArtifact {
                kind: a["kind"].as_str().unwrap().into(),
                digest: a["digest"].as_str().unwrap().into(),
                profile: "stage2-single-cell-v1".into(),
                retired: false,
            })
            .collect(),
        now: 1000,
    }
}
fn init(s: &mut Store, t: &Value) {
    s.initialize(
        &t["scope"],
        1,
        t["prior_artifact_set_digest"].as_str().unwrap(),
        &json!([]),
    )
    .unwrap();
}
#[test]
fn exact_receipt_survives_restart_and_cannot_imply_cell_resume() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.sqlite");
    let v = vectors();
    let t = &v["records"]["activation"];
    let a = auth(&v);
    let mut s = Store::open(&p).unwrap();
    init(&mut s, t);
    let receipt = s.apply(&a, t).unwrap();
    assert_eq!(receipt, v["records"]["registry-receipt"]);
    drop(s);
    let mut s = Store::open(&p).unwrap();
    assert_eq!(s.apply(&a, t).unwrap(), receipt);
    assert_eq!(s.lookup(&a.scope, "transition-a").unwrap(), receipt);
    assert_eq!(s.head(&a.scope).unwrap()["epoch"], 2);
    assert_eq!(s.head(&a.scope).unwrap()["cell_resumed"], false);
    assert_eq!(s.pending(&a.scope).unwrap().len(), 1);
    assert_eq!(
        s.initialize(
            &a.scope,
            1,
            t["prior_artifact_set_digest"].as_str().unwrap(),
            &json!([])
        ),
        Err(Error::Conflict)
    );
    let mut other = a.scope.clone();
    other["tenant"] = json!("tenant-b");
    assert_eq!(s.lookup(&other, "transition-a"), Err(Error::NotFound));
}
#[test]
fn missing_pause_authority_compatibility_and_retired_artifacts_refuse() {
    let dir = tempfile::tempdir().unwrap();
    let v = vectors();
    let t = &v["records"]["activation"];
    let mut s = Store::open(&dir.path().join("a.sqlite")).unwrap();
    init(&mut s, t);
    let mut a = auth(&v);
    a.pause["participant"] = json!("registry");
    assert!(s.apply(&a, t).is_err());
    let mut a = auth(&v);
    a.ratified_digest = format!("sha256:{}", "0".repeat(64));
    assert!(s.apply(&a, t).is_err());
    let mut a = auth(&v);
    a.artifacts[0].retired = true;
    assert!(s.apply(&a, t).is_err());
    let mut a = auth(&v);
    a.artifacts[0].profile = "unknown".into();
    assert!(s.apply(&a, t).is_err());
    let mut a = auth(&v);
    a.now = 1299;
    assert!(s.apply(&a, t).is_err());
    let a = auth(&v);
    assert_eq!(s.head(&a.scope).unwrap()["epoch"], 1);
    assert!(s.pending(&a.scope).unwrap().is_empty());
}
#[test]
fn concurrent_transitions_share_one_expected_head() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.sqlite");
    let v = vectors();
    let t = &v["records"]["activation"];
    init(&mut Store::open(&p).unwrap(), t);
    let handles: Vec<_> = (0..2)
        .map(|i| {
            let p = p.clone();
            std::thread::spawn(move || {
                let mut v = vectors();
                v["records"]["activation"]["transition"]["id"] = json!(format!("transition-{i}"));
                let hash = digest("activation", &v["records"]["activation"]);
                v["records"]["pause"]["transition"] =
                    v["records"]["activation"]["transition"].clone();
                v["records"]["pause"]["transition_digest"] = json!(hash);
                Store::open(&p)
                    .unwrap()
                    .apply(&auth(&v), &v["records"]["activation"])
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(Error::Conflict)))
            .count(),
        1
    );
}

#[test]
fn explicit_retirement_survives_restart_and_cannot_be_unset_by_a_new_binding() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.sqlite");
    let v = vectors();
    let t = &v["records"]["activation"];
    let a = auth(&v);
    let mut store = Store::open(&path).unwrap();
    init(&mut store, t);
    store
        .retire(&a.scope, &a.artifacts[0].digest, "governing-revision-2")
        .unwrap();
    drop(store);
    let mut store = Store::open(&path).unwrap();
    assert_eq!(store.apply(&a, t), Err(Error::UntrustedPublisher));
    assert_eq!(store.head(&a.scope).unwrap()["epoch"], 1);
}

#[test]
fn delivery_retries_exact_event_and_rejects_wrong_custody() {
    let v = vectors();
    let t = &v["records"]["activation"];
    let a = auth(&v);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("delivery.sqlite");
    let mut db = Store::open(&path).unwrap();
    init(&mut db, t);
    db.apply(&a, t).unwrap();
    let registration = json!({"stream":"activation-delivery","generation":1});
    let event = db
        .delivery_next(&a.scope, &registration, 1001)
        .unwrap()
        .unwrap();
    drop(db);
    let mut db = Store::open(&path).unwrap();
    assert_eq!(
        db.delivery_next(&a.scope, &registration, 1099).unwrap(),
        Some(event.clone())
    );
    assert!(
        db.delivery_next(
            &a.scope,
            &json!({"stream":"activation-delivery","generation":2}),
            1099
        )
        .is_err()
    );
    let mut ack = vectors()["records"]["ack"].clone();
    ack["scope"] = a.scope.clone();
    ack["ledger"]["scope"] = a.scope.clone();
    ack["event_id"] = event["event_id"].clone();
    ack["payload_digest"] = event["payload_digest"].clone();
    ack["event_digest"] = json!(digest("accountability-event", &event));
    let mut wrong = ack.clone();
    wrong["position"] = json!(0);
    assert!(db.delivery_ack(&a.scope, &event, &wrong).is_err());
    wrong = ack.clone();
    wrong["event_id"] = json!("wrong");
    assert!(db.delivery_ack(&a.scope, &event, &wrong).is_err());
    wrong = ack.clone();
    wrong["ledger"]["scope"]["tenant"] = json!("foreign");
    assert!(db.delivery_ack(&a.scope, &event, &wrong).is_err());
    assert_eq!(
        db.delivery_next(&a.scope, &registration, 1100).unwrap(),
        Some(event.clone())
    );
    db.delivery_ack(&a.scope, &event, &ack).unwrap();
    db.delivery_ack(&a.scope, &event, &ack).unwrap();
    assert!(
        db.delivery_next(&a.scope, &registration, 1101)
            .unwrap()
            .is_none()
    );
    assert!(!db.pending(&a.scope).unwrap().is_empty());
}
