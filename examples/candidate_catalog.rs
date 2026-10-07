// SPDX-License-Identifier: Apache-2.0
//! Disposable in-process recipe using public fixtures; no listener or activation.
use munarium_registry::{
    candidate::{Caller, Permission, Query, Registry, Submission, TrustSnapshot},
    catalog::CatalogReader,
    intake::CandidateIntake,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let trust: serde_json::Value =
        serde_json::from_str(include_str!("../contracts/registry-v2/trust.json"))?;
    let mut registry = Registry::new(
        TrustSnapshot::from_canonical_json(&serde_json::to_vec(&trust)?)?,
        32,
    );
    let caller = Caller::from_verified_identity(
        "alpha",
        &[Permission::Submit, Permission::Read, Permission::List],
    )?;
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../contracts/registry-v2/signed-vectors.json"))?;
    let envelope = vectors["cases"][0]["envelope"]
        .as_str()
        .ok_or("missing fixture")?;
    let admitted = registry.intake(&caller).submit(&Submission {
        envelope: envelope.into(),
    })?;
    let resolved = registry.reader(&caller).resolve(&Query {
        manifest_digest: admitted.manifest_digest().into(),
        artifact_digest: Some(admitted.artifact_digest().into()),
    })?;
    assert_eq!(resolved.envelope(), envelope);
    println!(
        "Resolved exact candidate bytes: {}",
        resolved.manifest_digest()
    );
    println!(
        "Tenant inventory: {} inert candidate; activation unavailable",
        registry.reader(&caller).list()?.len()
    );
    Ok(())
}
