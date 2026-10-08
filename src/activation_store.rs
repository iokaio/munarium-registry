// SPDX-License-Identifier: Apache-2.0
//! Durable artifact-set transitions, separated from candidate submission.
use crate::{candidate::Error, validation as v};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};
mod delivery;
use std::{collections::BTreeSet, path::Path, sync::LazyLock};
type Result<T> = std::result::Result<T, Error>;
fn storage(_: rusqlite::Error) -> Error {
    Error::StorageUnavailable
}
pub(crate) fn raw(value: &Value) -> Result<String> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::InvalidArtifact)?;
    v::canonical(&bytes, v::MAX_JSON)?;
    String::from_utf8(bytes).map_err(|_| Error::InvalidArtifact)
}
pub(crate) fn digest(domain: &str, value: &Value) -> Result<String> {
    Ok(v::digest(
        &format!("munarium:stage2:{domain}:v1"),
        raw(value)?.as_bytes(),
    ))
}
pub(crate) fn decoded(raw: &str) -> Result<Value> {
    v::canonical(raw.as_bytes(), v::MAX_JSON)
}
static SCHEMA: LazyLock<Option<jsonschema::Validator>> = LazyLock::new(|| {
    jsonschema::validator_for(
        &serde_json::from_str::<Value>(include_str!("../contracts/stage2-v1/schema.json")).ok()?,
    )
    .ok()
});
pub(crate) fn shape(value: &Value, kind: &str) -> Result<()> {
    raw(value)?;
    if value["type"] != kind
        || !SCHEMA
            .as_ref()
            .ok_or(Error::InvalidManifest)?
            .is_valid(value)
    {
        return Err(Error::InvalidArtifact);
    }
    Ok(())
}
pub(crate) fn scoped(value: &Value, scope: &Value) -> Result<()> {
    match value {
        Value::Object(m) => {
            if m.get("scope").is_some_and(|s| s != scope) {
                return Err(Error::Unauthorized);
            }
            for c in m.values() {
                scoped(c, scope)?;
            }
        }
        Value::Array(a) => {
            for c in a {
                scoped(c, scope)?;
            }
        }
        _ => {}
    }
    Ok(())
}
/// Artifact independently verified by the trusted service adapter, never caller DTOs.
pub struct VerifiedArtifact {
    /// Closed artifact family (manifest or policy in this profile).
    pub kind: String,
    /// Exact admitted artifact digest.
    pub digest: String,
    /// Declared compatibility with the action profile.
    pub profile: String,
    /// Current retirement disposition from authority.
    pub retired: bool,
}
/// Current authenticated transition authority and independent artifact evidence.
pub struct Authority {
    /// Qualified tenant/deployment/cell.
    pub scope: Value,
    /// Exact transition ratified through authenticated Council lookup.
    pub ratified_digest: String,
    /// Independently authenticated Council ratification reference.
    pub ratification: Value,
    /// Independently verified artifacts and current compatibility/retirement.
    pub artifacts: Vec<VerifiedArtifact>,
    /// Authenticated Gate pause receipt for this transition.
    pub pause: Value,
    /// Current bounded UTC time.
    pub now: u64,
}
/// Registry's own operational transition store; no shared-table writes.
pub struct Store {
    db: Connection,
}
impl Store {
    /// Retain an explicit retirement supplied by current governing authority.
    /// Supersession alone never retires an artifact or prohibits a governed rollback.
    pub fn retire(
        &mut self,
        scope: &Value,
        artifact: &str,
        authority_revision: &str,
    ) -> Result<()> {
        if !v::is_digest(artifact) || authority_revision.is_empty() {
            return Err(Error::InvalidTrust);
        }
        self.db
            .execute(
                "INSERT OR IGNORE INTO retired VALUES(?1,?2,?3)",
                params![raw(scope)?, artifact, authority_revision],
            )
            .map_err(storage)?;
        Ok(())
    }
    /// Create/open additive tables with synchronous local transactions.
    pub fn open(path: &Path) -> Result<Self> {
        let db = Connection::open(path).map_err(storage)?;
        db.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(storage)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
          CREATE TABLE IF NOT EXISTS active_sets(scope TEXT PRIMARY KEY,epoch INTEGER NOT NULL,digest TEXT NOT NULL,artifacts TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS transitions(scope TEXT NOT NULL,id TEXT NOT NULL,digest TEXT NOT NULL,record TEXT NOT NULL,receipt TEXT NOT NULL,PRIMARY KEY(scope,id));
          CREATE TABLE IF NOT EXISTS retired(scope TEXT NOT NULL,digest TEXT NOT NULL,transition_id TEXT NOT NULL,PRIMARY KEY(scope,digest));
          CREATE TABLE IF NOT EXISTS activation_outbox(scope TEXT NOT NULL,id TEXT NOT NULL,record TEXT NOT NULL,receipt TEXT NOT NULL,PRIMARY KEY(scope,id));").map_err(storage)?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS activation_delivery(scope TEXT NOT NULL,id TEXT NOT NULL,sequence INTEGER NOT NULL,event TEXT NOT NULL,acknowledgement TEXT,PRIMARY KEY(scope,id),UNIQUE(scope,sequence));").map_err(storage)?;
        Ok(Self { db })
    }
    /// Install only the independently enrolled initial head. Reopening cannot replace it.
    pub fn initialize(
        &mut self,
        scope: &Value,
        epoch: u64,
        set_digest: &str,
        artifacts: &Value,
    ) -> Result<()> {
        if epoch == 0
            || epoch > 9007199254740991
            || !v::is_digest(set_digest)
            || !artifacts.is_array()
        {
            return Err(Error::InvalidTrust);
        }
        // The initial authority may name a pre-existing set without locally available old bytes.
        let scope = raw(scope)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let existing: Option<(u64, String)> = tx
            .query_row(
                "SELECT epoch,digest FROM active_sets WHERE scope=?1",
                [&scope],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(storage)?;
        if let Some((old, digest)) = existing {
            if old != epoch || digest != set_digest {
                return Err(Error::Conflict);
            }
        } else {
            tx.execute(
                "INSERT INTO active_sets VALUES(?1,?2,?3,?4)",
                params![
                    scope,
                    epoch,
                    set_digest,
                    serde_json::to_string(artifacts).map_err(|_| Error::InvalidArtifact)?
                ],
            )
            .map_err(storage)?;
        }
        tx.commit().map_err(storage)
    }
    /// Compare-and-set a ratified, paused transition and retain its exact receipt atomically.
    pub fn apply(&mut self, auth: &Authority, transition: &Value) -> Result<Value> {
        validate(auth, transition)?;
        let scope = raw(&auth.scope)?;
        let id = v::text(&transition["transition"], "id")?;
        let hash = digest("activation", transition)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let old: Option<(String, String)> = tx
            .query_row(
                "SELECT digest,receipt FROM transitions WHERE scope=?1 AND id=?2",
                params![scope, id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(storage)?;
        if let Some((prior, receipt)) = old {
            return if prior == hash {
                decoded(&receipt)
            } else {
                Err(Error::Conflict)
            };
        }
        let (epoch, head): (u64, String) = tx
            .query_row(
                "SELECT epoch,digest FROM active_sets WHERE scope=?1",
                [&scope],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(storage)?
            .ok_or(Error::TrustUnavailable)?;
        if transition["prior_epoch"] != epoch || transition["prior_artifact_set_digest"] != head {
            return Err(Error::Conflict);
        }
        for artifact in transition["artifacts"]
            .as_array()
            .ok_or(Error::InvalidArtifact)?
        {
            let retired: u64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM retired WHERE scope=?1 AND digest=?2",
                    params![scope, v::text(artifact, "digest")?],
                    |r| r.get(0),
                )
                .map_err(storage)?;
            if retired != 0 {
                return Err(Error::UntrustedPublisher);
            }
        }
        let receipt = json!({"schema_version":1,"profile":"stage2-single-cell-v1","type":"activation-receipt","transition":transition["transition"],"transition_digest":hash,"participant":"registry","phase":"applied","prior_epoch":transition["prior_epoch"],"successor_epoch":transition["successor_epoch"],"artifact_set_digest":transition["artifact_set_digest"],"participant_set_digest":transition["participant_set_digest"]});
        shape(&receipt, "activation-receipt")?;
        let record_raw = raw(transition)?;
        let receipt_raw = raw(&receipt)?;
        tx.execute(
            "UPDATE active_sets SET epoch=?2,digest=?3,artifacts=?4 WHERE scope=?1",
            params![
                scope,
                transition["successor_epoch"]
                    .as_u64()
                    .ok_or(Error::InvalidArtifact)?,
                v::text(transition, "artifact_set_digest")?,
                serde_json::to_string(&transition["artifacts"])
                    .map_err(|_| Error::InvalidArtifact)?
            ],
        )
        .map_err(storage)?;
        tx.execute(
            "INSERT INTO transitions VALUES(?1,?2,?3,?4,?5)",
            params![scope, id, hash, record_raw, receipt_raw],
        )
        .map_err(storage)?;
        tx.execute(
            "INSERT INTO activation_outbox VALUES(?1,?2,?3,?4)",
            params![scope, id, record_raw, receipt_raw],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(receipt)
    }
    /// Retain lookup as evidence only; an active Registry set cannot resume Gate.
    pub fn lookup(&self, scope: &Value, id: &str) -> Result<Value> {
        let receipt: String = self
            .db
            .query_row(
                "SELECT receipt FROM transitions WHERE scope=?1 AND id=?2",
                params![raw(scope)?, id],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage)?
            .ok_or(Error::NotFound)?;
        decoded(&receipt)
    }
    /// Report the participant's current state separately from cell activation.
    pub fn head(&self, scope: &Value) -> Result<Value> {
        let (epoch, digest, artifacts): (u64, String, String) = self
            .db
            .query_row(
                "SELECT epoch,digest,artifacts FROM active_sets WHERE scope=?1",
                [raw(scope)?],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(storage)?
            .ok_or(Error::NotFound)?;
        Ok(
            json!({"scope":scope,"epoch":epoch,"artifact_set_digest":digest,"artifacts":serde_json::from_str::<Value>(&artifacts).map_err(|_|Error::StorageUnavailable)?,"participant":"registry","cell_resumed":false}),
        )
    }
    /// Retained transition/receipt outbox for acknowledged delivery by the owning adapter.
    pub fn pending(&self, scope: &Value) -> Result<Vec<Value>> {
        let mut stmt=self.db.prepare("SELECT record,receipt FROM activation_outbox WHERE scope=?1 ORDER BY rowid LIMIT 100").map_err(storage)?;
        let rows = stmt
            .query_map([raw(scope)?], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })
            .map_err(storage)?;
        rows.map(|r| {
            let (record, receipt) = r.map_err(storage)?;
            Ok(json!({"transition":decoded(&record)?,"receipt":decoded(&receipt)?}))
        })
        .collect()
    }
}
fn validate(auth: &Authority, t: &Value) -> Result<()> {
    shape(t, "activation")?;
    scoped(t, &auth.scope)?;
    let profile: Value = serde_json::from_str(include_str!("../contracts/stage2-v1/profile.json"))
        .map_err(|_| Error::InvalidManifest)?;
    if auth.ratified_digest != digest("activation", t)?
        || t["ratification"] != auth.ratification
        || t["profile_digest"] != digest("profile", &profile)?
        || t["participants"] != profile["participants"]
        || t["artifact_set_digest"] != digest("artifact-set", &json!({"artifacts":t["artifacts"]}))?
        || t["participant_set_digest"]
            != digest("participants", &json!({"participants":t["participants"]}))?
    {
        return Err(Error::Unauthorized);
    }
    let before = t["not_before"].as_u64().ok_or(Error::InvalidArtifact)?;
    let expires = t["expires_at"].as_u64().ok_or(Error::InvalidArtifact)?;
    if auth.now < before.saturating_add(2)
        || auth.now.saturating_add(2) >= expires
        || t["successor_epoch"].as_u64() <= t["prior_epoch"].as_u64()
    {
        return Err(Error::StaleTrust);
    }
    shape(&auth.pause, "activation-receipt")?;
    scoped(&auth.pause, &auth.scope)?;
    if auth.pause["participant"] != "gate"
        || auth.pause["phase"] != "paused"
        || auth.pause["transition_digest"] != auth.ratified_digest
    {
        return Err(Error::Unauthorized);
    }
    for key in [
        "transition",
        "prior_epoch",
        "successor_epoch",
        "artifact_set_digest",
        "participant_set_digest",
    ] {
        if auth.pause[key] != t[key] {
            return Err(Error::Unauthorized);
        }
    }
    let artifacts = t["artifacts"].as_array().ok_or(Error::InvalidArtifact)?;
    let mut kinds = BTreeSet::new();
    for a in artifacts {
        let kind = v::text(a, "kind")?;
        if !["manifest", "policy"].contains(&kind)
            || !kinds.insert(kind)
            || !auth.artifacts.iter().any(|v| {
                v.kind == kind
                    && a["digest"] == v.digest
                    && v.profile == "stage2-single-cell-v1"
                    && !v.retired
            })
        {
            return Err(Error::MissingReference);
        }
    }
    if kinds != BTreeSet::from(["manifest", "policy"]) {
        return Err(Error::MissingReference);
    }
    Ok(())
}
