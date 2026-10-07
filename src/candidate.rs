// SPDX-License-Identifier: Apache-2.0
//! Experimental in-process candidate catalog. The embedding host is trusted.
//!
//! The host supplies already verified callers and governing trust snapshots.
//! This module does not authenticate network clients or activate policy. SQLite custody is optional.
//! Intake and reader handles cannot modify host trust or acquire activation authority.

use crate::{catalog::CatalogReader, intake::CandidateIntake, validation as v};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::OnceLock,
};

/// Digest of the exact candidate contract bundle consumed by this implementation.
pub const CONTRACT_DIGEST: &str =
    "2e121d86c8dd4061ef1bdbc9dc073dceebfebf7305cf7a50d5d0e59385eaf0fc";

/// Typed refusals; errors contain no foreign inventory or submitted content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Caller lacks the required tenant permission.
    Unauthorized,
    /// Malformed, noncanonical, oversized or incorrectly signed artifact.
    InvalidArtifact,
    /// Unsupported or invalid manifest shape or consequence semantics.
    InvalidManifest,
    /// Publisher, key, owner or permitted publisher scope is not trusted.
    UntrustedPublisher,
    /// An operation, classification or verified schema reference is missing.
    MissingReference,
    /// No current host-provided trust snapshot is available.
    TrustUnavailable,
    /// Governing snapshot is malformed or contains ambiguous records.
    InvalidTrust,
    /// A trust revision was reused or moved backwards.
    StaleTrust,
    /// Same tenant, identity and version already names different bytes.
    Conflict,
    /// No matching candidate exists in the caller's tenant.
    NotFound,
    /// The caller's bounded in-memory candidate inventory is full.
    Capacity,
    /// Durable storage, its exclusive custody lock or committed history is unavailable.
    StorageUnavailable,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

/// Permissions asserted by the trusted host after identity verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permission {
    /// Submit an inert candidate.
    Submit,
    /// Resolve candidate bytes.
    Read,
    /// List the caller's candidate inventory.
    List,
}

/// Verified caller context supplied by the trusted embedding host, never intake JSON.
#[derive(Clone, Debug)]
pub struct Caller {
    tenant: String,
    permissions: Vec<Permission>,
}
impl Caller {
    /// Adapt an already authenticated and authorized identity.
    ///
    /// This constructor does not verify identity. Exposing it to an untrusted caller
    /// would bypass the embedding host's authentication boundary.
    ///
    /// # Errors
    /// Rejects an invalid tenant identifier.
    pub fn from_verified_identity(tenant: &str, permissions: &[Permission]) -> Result<Self, Error> {
        if !v::identifier(tenant) {
            return Err(Error::Unauthorized);
        }
        Ok(Self {
            tenant: tenant.into(),
            permissions: permissions.to_vec(),
        })
    }
    fn check(&self, permission: Permission) -> Result<(), Error> {
        if self.permissions.contains(&permission) {
            Ok(())
        } else {
            Err(Error::Unauthorized)
        }
    }
}

fn contract() -> &'static Value {
    static CONTRACT: OnceLock<Value> = OnceLock::new();
    CONTRACT.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../contracts/registry-v2/registry.schema.json"
        ))
        .expect("bundled contract is checked by contract integrity tests")
    })
}

pub(crate) fn decode(s: &str, max: usize) -> Result<Vec<u8>, Error> {
    if s.len() > max.div_ceil(3) * 4 || !s.is_ascii() {
        return Err(Error::InvalidArtifact);
    }
    let raw = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| Error::InvalidArtifact)?;
    if raw.len() > max || URL_SAFE_NO_PAD.encode(&raw) != s {
        return Err(Error::InvalidArtifact);
    }
    Ok(raw)
}

pub(crate) fn key(s: &str) -> Result<VerifyingKey, Error> {
    let bytes: [u8; 32] = decode(s, 32)?.try_into().map_err(|_| Error::InvalidTrust)?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| Error::InvalidTrust)?;
    if key.is_weak() {
        return Err(Error::InvalidTrust);
    }
    Ok(key)
}

/// Immutable, validated governing input. Creation does not activate a manifest.
#[derive(Clone, Debug)]
pub struct TrustSnapshot {
    value: Value,
    revision: u64,
}
impl TrustSnapshot {
    /// Validate host-provisioned canonical JSON, bounded to 65,536 bytes.
    ///
    /// # Errors
    /// Rejects malformed schemas, keys, ambiguous identities or substituted schema bytes.
    pub fn from_canonical_json(raw: &[u8]) -> Result<Self, Error> {
        let value = v::canonical(raw, v::MAX_JSON).map_err(|_| Error::InvalidTrust)?;
        v::shape(&value, &contract()["$defs"]["trust"], contract())
            .map_err(|_| Error::InvalidTrust)?;
        let checked = || -> Result<(), Error> {
            let mut tenants = BTreeSet::new();
            for tenant in v::array(&value, "tenants")? {
                if !tenants.insert(v::text(tenant, "id")?) {
                    return Err(Error::InvalidTrust);
                }
                unique(tenant, "owners", &["id"])?;
                unique(tenant, "publishers", &["id", "kid"])?;
                unique(tenant, "schemas", &["digest"])?;
                unique(
                    tenant,
                    "operations",
                    &["target_id", "environment", "operation_id"],
                )?;
                for publisher in v::array(tenant, "publishers")? {
                    key(v::text(publisher, "public_key")?)?;
                    if v::array(publisher, "owner_ids")?.iter().any(|id| {
                        !tenant["owners"]
                            .as_array()
                            .is_some_and(|owners| owners.iter().any(|o| &o["id"] == id))
                    }) {
                        return Err(Error::InvalidTrust);
                    }
                    if v::array(publisher, "operations")?.iter().any(|op| {
                        !tenant["operations"]
                            .as_array()
                            .is_some_and(|ops| ops.contains(op))
                    }) {
                        return Err(Error::InvalidTrust);
                    }
                }
                for schema in v::array(tenant, "schemas")? {
                    let raw = v::text(schema, "canonical")?.as_bytes();
                    v::capability_schema(raw)?;
                    if v::digest("munarium:capability-schema:v1", raw) != v::text(schema, "digest")?
                    {
                        return Err(Error::InvalidTrust);
                    }
                }
                for op in v::array(tenant, "operations")? {
                    for field in ["parameter_schema_digest", "result_schema_digest"] {
                        if !v::array(tenant, "schemas")?
                            .iter()
                            .any(|s| s["digest"] == op[field])
                        {
                            return Err(Error::InvalidTrust);
                        }
                    }
                }
            }
            Ok(())
        };
        checked().map_err(|_| Error::InvalidTrust)?;
        let revision = value["revision"].as_u64().ok_or(Error::InvalidTrust)?;
        Ok(Self { value, revision })
    }
    /// Revision supplied by the independently governing host.
    pub fn revision(&self) -> u64 {
        self.revision
    }
    fn tenant(&self, name: &str) -> Result<&Value, Error> {
        v::array(&self.value, "tenants")?
            .iter()
            .find(|t| t["id"] == name)
            .ok_or(Error::Unauthorized)
    }
}

fn unique(value: &Value, name: &str, fields: &[&str]) -> Result<(), Error> {
    let mut seen = BTreeSet::new();
    for entry in v::array(value, name)? {
        let identity = fields
            .iter()
            .map(|f| v::text(entry, f))
            .collect::<Result<Vec<_>, _>>()?;
        if !seen.insert(identity) {
            return Err(Error::InvalidTrust);
        }
    }
    Ok(())
}

/// Exact admitted candidate bytes with current verification metadata, never activation.
#[derive(Clone, Debug)]
pub struct Candidate {
    manifest: Value,
    envelope: String,
    payload: Vec<u8>,
    manifest_digest: String,
    artifact_digest: String,
    admission_revision: u64,
    verified_revision: u64,
}
impl Candidate {
    /// Canonical manifest, without any activation field.
    pub fn manifest(&self) -> &Value {
        &self.manifest
    }
    /// Exact compact JWS bytes retained on admission.
    pub fn envelope(&self) -> &str {
        &self.envelope
    }
    /// Exact canonical signed payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    /// Domain-separated content digest.
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }
    /// Domain-separated digest of the complete signed envelope.
    pub fn artifact_digest(&self) -> &str {
        &self.artifact_digest
    }
    /// Trust revision at the original admission, including on identical retries.
    pub fn admission_revision(&self) -> u64 {
        self.admission_revision
    }
    /// Current trust revision checked for this returned result.
    pub fn verified_revision(&self) -> u64 {
        self.verified_revision
    }
}

fn verify(envelope: &str, caller: &Caller, trust: &TrustSnapshot) -> Result<Candidate, Error> {
    let tenant = trust.tenant(&caller.tenant)?;
    if envelope.len() > 90_000 || !envelope.is_ascii() {
        return Err(Error::InvalidArtifact);
    }
    let parts: Vec<_> = envelope.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
        return Err(Error::InvalidArtifact);
    }
    let header = v::canonical(&decode(parts[0], 512)?, 512)?;
    v::shape(&header, &contract()["$defs"]["header"], contract())
        .map_err(|_| Error::InvalidArtifact)?;
    let payload = decode(parts[1], v::MAX_JSON)?;
    let manifest = v::canonical(&payload, v::MAX_JSON)?;
    v::shape(&manifest, &contract()["$defs"]["manifest"], contract())?;
    if manifest["tenant"] != caller.tenant {
        return Err(Error::Unauthorized);
    }
    for modifier in v::array(&manifest, "modifiers")? {
        if v::text(modifier, "raise_to")? <= v::text(&manifest, "base_consequence")? {
            return Err(Error::InvalidManifest);
        }
    }
    let publisher = v::array(tenant, "publishers")?
        .iter()
        .find(|p| {
            p["id"] == manifest["publisher_id"] && p["kid"] == header["kid"] && p["enabled"] == true
        })
        .ok_or(Error::UntrustedPublisher)?;
    let sig = Signature::from_slice(&decode(parts[2], 64)?).map_err(|_| Error::InvalidArtifact)?;
    let signing_len = parts[0].len() + 1 + parts[1].len();
    key(v::text(publisher, "public_key")?)?
        .verify_strict(&envelope.as_bytes()[..signing_len], &sig)
        .map_err(|_| Error::InvalidArtifact)?;
    if !v::array(tenant, "owners")?
        .iter()
        .any(|o| o["id"] == manifest["owner_id"])
        || !v::array(publisher, "owner_ids")?.contains(&manifest["owner_id"])
    {
        return Err(Error::UntrustedPublisher);
    }
    let matches = |op: &&Value| {
        [
            "target_id",
            "environment",
            "operation_id",
            "credential_audience",
            "capability_id",
            "parameter_schema_digest",
            "result_schema_digest",
        ]
        .iter()
        .all(|f| op[*f] == manifest[*f])
    };
    let operation = v::array(tenant, "operations")?
        .iter()
        .find(matches)
        .ok_or(Error::MissingReference)?;
    if !v::array(publisher, "operations")?.contains(operation) {
        return Err(Error::UntrustedPublisher);
    }
    if v::array(&manifest, "data_classifications")?
        .iter()
        .any(|c| {
            !tenant["classifications"]
                .as_array()
                .is_some_and(|classes| classes.contains(c))
        })
    {
        return Err(Error::MissingReference);
    }
    Ok(Candidate {
        manifest_digest: v::digest("munarium:manifest:v2", &payload),
        artifact_digest: v::digest("munarium:manifest-artifact:v2", envelope.as_bytes()),
        manifest,
        envelope: envelope.into(),
        payload,
        admission_revision: trust.revision,
        verified_revision: trust.revision,
    })
}

/// Trusted host's bounded store; expose only scoped handles to intake/read adapters.
pub struct Registry {
    trust: Option<TrustSnapshot>,
    last_revision: u64,
    entries: BTreeMap<(String, String, String), Candidate>,
    capacity: usize,
    #[cfg(feature = "sqlite")]
    durable: Option<Durable>,
}
#[cfg(feature = "sqlite")]
struct Durable {
    connection: rusqlite::Connection,
    _custody: std::fs::File,
}
#[cfg(feature = "sqlite")]
fn persist_trust(connection: &rusqlite::Connection, trust: &TrustSnapshot) -> Result<(), Error> {
    use rusqlite::OptionalExtension;
    let tx = connection
        .unchecked_transaction()
        .map_err(|_| Error::StorageUnavailable)?;
    let floor: Option<u64> = tx
        .query_row(
            "SELECT revision FROM catalog_revision WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| Error::StorageUnavailable)?;
    let pin: Option<String> = tx
        .query_row(
            "SELECT digest FROM catalog_trust_pins WHERE revision=?1",
            [trust.revision],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| Error::StorageUnavailable)?;
    let digest = v::digest(
        "munarium:registry-trust:v2",
        &serde_json::to_vec(&trust.value).map_err(|_| Error::InvalidTrust)?,
    );
    // A pre-pin database must advance to a new operator revision; inventing a digest
    // for its old revision would silently bless potentially substituted authority.
    if floor.is_some_and(|r| {
        trust.revision < r || (trust.revision == r && pin.as_deref() != Some(&digest))
    }) {
        return Err(Error::StaleTrust);
    }
    if pin.as_ref().is_some_and(|old| old != &digest) {
        return Err(Error::StaleTrust);
    }
    tx.execute("INSERT INTO catalog_trust_pins(revision,digest) VALUES(?1,?2) ON CONFLICT(revision) DO NOTHING",
        rusqlite::params![trust.revision,digest]).map_err(|_| Error::StorageUnavailable)?;
    tx.execute("INSERT INTO catalog_revision VALUES(1,?1) ON CONFLICT(singleton) DO UPDATE SET revision=excluded.revision",[trust.revision])
        .map_err(|_| Error::StorageUnavailable)?;
    tx.commit().map_err(|_| Error::StorageUnavailable)
}
impl Registry {
    /// Construct a bounded local catalog with no active artifacts or activation writer.
    pub fn new(trust: TrustSnapshot, capacity: usize) -> Self {
        Self {
            last_revision: trust.revision,
            trust: Some(trust),
            entries: BTreeMap::new(),
            capacity,
            #[cfg(feature = "sqlite")]
            durable: None,
        }
    }
    /// Open an exclusively owned durable catalog. Every read still verifies current trust.
    /// Exact signed bytes, first-admission revision and the trust revision floor survive restart.
    /// This profile supports one process per database; another opener refuses while it is held.
    #[cfg(feature = "sqlite")]
    pub fn open(
        path: &std::path::Path,
        trust: TrustSnapshot,
        capacity: usize,
    ) -> Result<Self, Error> {
        let unavailable = |_| Error::StorageUnavailable;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(unavailable)?;
        let canonical = path.canonicalize().map_err(unavailable)?;
        let mut lock_path = canonical.into_os_string();
        lock_path.push(".lock");
        let custody = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(std::path::PathBuf::from(lock_path))
            .map_err(unavailable)?;
        custody.try_lock().map_err(|_| Error::StorageUnavailable)?;
        drop(file);
        let connection = rusqlite::Connection::open(path).map_err(|_| Error::StorageUnavailable)?;
        connection
            .busy_timeout(std::time::Duration::from_millis(500))
            .map_err(|_| Error::StorageUnavailable)?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS candidates(tenant TEXT NOT NULL, id TEXT NOT NULL, version TEXT NOT NULL,
                envelope TEXT NOT NULL CHECK(length(envelope)<=90000), admission_revision INTEGER NOT NULL,
                PRIMARY KEY(tenant,id,version));
            CREATE TABLE IF NOT EXISTS catalog_revision(singleton INTEGER PRIMARY KEY CHECK(singleton=1), revision INTEGER NOT NULL);
            CREATE TRIGGER IF NOT EXISTS candidates_no_update BEFORE UPDATE ON candidates BEGIN SELECT RAISE(ABORT,'immutable candidate'); END;
            CREATE TRIGGER IF NOT EXISTS candidates_no_delete BEFORE DELETE ON candidates BEGIN SELECT RAISE(ABORT,'immutable candidate'); END;
            CREATE TRIGGER IF NOT EXISTS revision_monotonic BEFORE UPDATE ON catalog_revision WHEN NEW.revision<OLD.revision BEGIN SELECT RAISE(ABORT,'revision regression'); END;
            CREATE TRIGGER IF NOT EXISTS revision_no_delete BEFORE DELETE ON catalog_revision BEGIN SELECT RAISE(ABORT,'immutable revision floor'); END;")
            .map_err(|_| Error::StorageUnavailable)?;
        // Additive extension; existing candidate history and revision floors are retained.
        connection.execute_batch("CREATE TABLE IF NOT EXISTS catalog_trust_pins(revision INTEGER PRIMARY KEY,digest TEXT NOT NULL);
            CREATE TRIGGER IF NOT EXISTS trust_pins_no_update BEFORE UPDATE ON catalog_trust_pins BEGIN SELECT RAISE(ABORT,'immutable trust pin'); END;
            CREATE TRIGGER IF NOT EXISTS trust_pins_no_delete BEFORE DELETE ON catalog_trust_pins BEGIN SELECT RAISE(ABORT,'immutable trust pin'); END;")
            .map_err(|_| Error::StorageUnavailable)?;
        persist_trust(&connection, &trust)?;
        let mut registry = Self::new(trust, capacity);
        {
            let mut statement = connection.prepare("SELECT tenant,id,version,envelope,admission_revision FROM candidates ORDER BY tenant,id,version").map_err(|_|Error::StorageUnavailable)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, u64>(4)?,
                    ))
                })
                .map_err(|_| Error::StorageUnavailable)?;
            let mut counts = BTreeMap::<String, usize>::new();
            for row in rows {
                let (tenant, id, version, envelope, revision) =
                    row.map_err(|_| Error::StorageUnavailable)?;
                let count = counts.entry(tenant.clone()).or_default();
                *count += 1;
                if *count > capacity {
                    return Err(Error::Capacity);
                }
                if envelope.len() > 90000 {
                    return Err(Error::StorageUnavailable);
                }
                let parts: Vec<_> = envelope.split('.').collect();
                if parts.len() != 3 {
                    return Err(Error::StorageUnavailable);
                }
                let payload = decode(parts[1], v::MAX_JSON)?;
                let manifest = v::canonical(&payload, v::MAX_JSON)?;
                if manifest["tenant"] != tenant
                    || manifest["id"] != id
                    || manifest["version"] != version
                    || revision > registry.last_revision
                {
                    return Err(Error::StorageUnavailable);
                }
                // Stored inventory is not authority. Reader::resolve/list reverify signatures,
                // publisher status, classification and schema references against current trust.
                let candidate = Candidate {
                    manifest_digest: v::digest("munarium:manifest:v2", &payload),
                    artifact_digest: v::digest(
                        "munarium:manifest-artifact:v2",
                        envelope.as_bytes(),
                    ),
                    manifest,
                    envelope,
                    payload,
                    admission_revision: revision,
                    verified_revision: 0,
                };
                registry.entries.insert((tenant, id, version), candidate);
            }
        }
        registry.durable = Some(Durable {
            connection,
            _custody: custody,
        });
        Ok(registry)
    }
    /// Host-only trust refresh. None makes all subsequent operations fail closed.
    ///
    /// Mutable borrowing excludes admission/read handles during this transition.
    /// Snapshot revisions must increase, including after an unavailable interval.
    ///
    /// # Errors
    /// Rejects reused or decreasing revisions without changing the current state.
    pub fn replace_trust(&mut self, trust: Option<TrustSnapshot>) -> Result<(), Error> {
        if let Some(snapshot) = &trust {
            if snapshot.revision <= self.last_revision {
                return Err(Error::StaleTrust);
            }
            #[cfg(feature = "sqlite")]
            if let Some(durable) = &self.durable
                && persist_trust(&durable.connection, snapshot).is_err()
            {
                self.trust = None;
                return Err(Error::StorageUnavailable);
            }
            self.last_revision = snapshot.revision;
        }
        self.trust = trust;
        Ok(())
    }
    /// Borrow a read-only candidate interface with a verified caller context.
    pub fn reader<'a>(&'a self, caller: &'a Caller) -> Reader<'a> {
        Reader {
            registry: self,
            caller,
        }
    }
    /// Borrow an inert intake interface, which cannot update trust or activate.
    pub fn intake<'a>(&'a mut self, caller: &'a Caller) -> Intake<'a> {
        Intake {
            registry: self,
            caller,
        }
    }
    fn current(&self) -> Result<&TrustSnapshot, Error> {
        self.trust.as_ref().ok_or(Error::TrustUnavailable)
    }
}

/// A candidate submission carries only a signed artifact, never caller authority.
pub struct Submission {
    /// Complete compact JWS supplied by the caller.
    pub envelope: String,
}

/// Tenant-scoped intake; no activation or trust-update method is exposed.
///
/// Intake cannot implement the governing activation interface:
///
/// ```compile_fail
/// use munarium_registry::{activation::ActivationStore, candidate::Intake};
/// fn requires_activation<T: ActivationStore>() {}
/// requires_activation::<Intake<'static>>();
/// ```
pub struct Intake<'a> {
    registry: &'a mut Registry,
    caller: &'a Caller,
}
impl CandidateIntake for Intake<'_> {
    type Candidate = Submission;
    type CandidateReference = Candidate;
    type Error = Error;
    fn submit(&mut self, input: &Submission) -> Result<Candidate, Error> {
        self.caller.check(Permission::Submit)?;
        let mut candidate = verify(&input.envelope, self.caller, self.registry.current()?)?;
        let identity = (
            self.caller.tenant.clone(),
            v::text(&candidate.manifest, "id")?.into(),
            v::text(&candidate.manifest, "version")?.into(),
        );
        if let Some(original) = self.registry.entries.get(&identity) {
            if original.envelope != candidate.envelope {
                return Err(Error::Conflict);
            }
            candidate.admission_revision = original.admission_revision;
            return Ok(candidate);
        }
        if self
            .registry
            .entries
            .keys()
            .filter(|(tenant, _, _)| tenant == &self.caller.tenant)
            .count()
            >= self.registry.capacity
        {
            return Err(Error::Capacity);
        }
        #[cfg(feature = "sqlite")]
        if let Some(durable) = &self.registry.durable
            && durable.connection.execute("INSERT INTO candidates(tenant,id,version,envelope,admission_revision) VALUES(?1,?2,?3,?4,?5)",
                rusqlite::params![identity.0,identity.1,identity.2,candidate.envelope,candidate.admission_revision]).is_err() {
                self.registry.trust = None;
                return Err(Error::StorageUnavailable);
            }
        self.registry.entries.insert(identity, candidate.clone());
        Ok(candidate)
    }
}

/// A required content digest plus optional exact-envelope binding.
pub struct Query {
    /// Content digest, with no implicit latest-version fallback.
    pub manifest_digest: String,
    /// When present, require this exact signed artifact as well.
    pub artifact_digest: Option<String>,
}

/// Read-only view. Current trust is rechecked; a candidate is never active authority.
pub struct Reader<'a> {
    registry: &'a Registry,
    caller: &'a Caller,
}
impl CatalogReader for Reader<'_> {
    type Query = Query;
    type Artifact = Candidate;
    type Error = Error;
    fn resolve(&self, query: &Query) -> Result<Candidate, Error> {
        self.caller.check(Permission::Read)?;
        let trust = self.registry.current()?;
        trust.tenant(&self.caller.tenant)?;
        let stored = self
            .registry
            .entries
            .iter()
            .find(|((tenant, _, _), c)| {
                tenant == &self.caller.tenant
                    && c.manifest_digest == query.manifest_digest
                    && query
                        .artifact_digest
                        .as_ref()
                        .is_none_or(|d| &c.artifact_digest == d)
            })
            .map(|(_, c)| c)
            .ok_or(Error::NotFound)?;
        let mut result = verify(&stored.envelope, self.caller, trust)?;
        result.admission_revision = stored.admission_revision;
        Ok(result)
    }
}
impl Reader<'_> {
    /// List only currently verifiable candidates for the authorized tenant.
    ///
    /// # Errors
    /// Refuses missing list permission, unavailable trust, or any invalid tenant entry;
    /// no partial success is returned.
    pub fn list(&self) -> Result<Vec<Candidate>, Error> {
        self.caller.check(Permission::List)?;
        let trust = self.registry.current()?;
        trust.tenant(&self.caller.tenant)?;
        self.registry
            .entries
            .iter()
            .filter(|((t, _, _), _)| t == &self.caller.tenant)
            .map(|(_, stored)| {
                let mut result = verify(&stored.envelope, self.caller, trust)?;
                result.admission_revision = stored.admission_revision;
                Ok(result)
            })
            .collect()
    }
}
