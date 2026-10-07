// SPDX-License-Identifier: Apache-2.0
//! Receiving-side decision identity verification and candidate access.
//!
//! The host supplies current authority, a qualified clock and authenticated peer.
//! Every operation verifies the complete chain again. No provider, transport,
//! attribution exchange, bootstrap or activation authority is implemented.

use crate::{
    candidate::{self, Caller, Candidate, Error, Permission, Query, Registry, Submission},
    catalog::CatalogReader,
    intake::CandidateIntake,
    validation as v,
};
use ed25519_dalek::Signature;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
};

/// Unchanged foundation bundle at platform c46f864.
pub const FOUNDATION_DIGEST: &str =
    "5ee201e48a2390b7cf66fdf6aa8750f751f1ec9241e9e04131b6632745612238";
/// Unchanged Warden admission bundle at the same platform revision.
pub const ADMISSION_DIGEST: &str =
    "9ed4a12563d064e5d2068658b903a8b8813ffe49e8cd66356931af1447080283";

/// Current host-provisioned principal key; separate from manifest publishers.
#[derive(Clone)]
pub struct IssuerKey {
    /// Canonical base64url Ed25519 public key, never signing material.
    pub public_key: String,
    /// Exact permitted issuer.
    pub issuer: String,
    /// Current authorization to verify decision assertions under this key.
    pub decision: bool,
}

/// Independently selected, currently admitted task or target-policy restrictions.
#[derive(Clone)]
pub struct Authority {
    /// Exact immutable task/policy revision.
    pub digest: String,
    /// Earliest allowed assertion validity.
    pub not_before: i64,
    /// Exclusive end of allowed assertion validity.
    pub expires: i64,
    /// Explicit permitted read/evaluate/propose scopes.
    pub scopes: Vec<String>,
    /// Exact registered resources; no wildcards or hierarchy.
    pub resources: Vec<String>,
}

/// Host admission for one candidate API operation.
#[derive(Clone)]
pub struct AccessRule {
    /// Separate local submit, resolve or list permission.
    pub permission: Permission,
    /// Exact registered resource required in the verified signed authority.
    pub resource: String,
}

/// Trusted receiving-service context, never deserialized from a request.
///
/// Supply a fresh context for every operation. The host selects task, policy,
/// registrations and access rules independently of submitted evidence. It obtains
/// the peer from authenticated transport and the tenant from its trusted routing.
/// The public fields are a host adapter, not an untrusted configuration API.
#[derive(Clone)]
pub struct Context {
    /// Expected deployment.
    pub deployment: String,
    /// Expected tenant.
    pub tenant: String,
    /// Actual receiving service.
    pub audience: String,
    /// Actual authenticated transport peer.
    pub peer_service: String,
    /// Unix seconds with a host-qualified uncertainty of at most two seconds.
    pub now: i64,
    /// False when current authority cannot be obtained.
    pub available: bool,
    /// True during recovery quarantine.
    pub restore_quarantined: bool,
    /// Current non-retired issuer keys indexed by kid.
    pub keys: BTreeMap<String, IssuerKey>,
    /// Current registered task, independently selected by the host.
    pub task: Authority,
    /// Current target policy, independently selected by the host.
    pub policy: Authority,
    /// Maximum delegation edges allowed by the task, zero through four.
    pub maximum_depth: usize,
    /// At most 128 admitted ADR-0005 delegation-registration objects.
    pub registrations: Vec<Value>,
    /// Explicit permission/resource mapping for each local operation.
    pub access: Vec<AccessRule>,
}

/// Evidence of one verification; never an enduring authorization handle.
///
/// Has no caller conversion or deserialization API. Candidate operations below
/// reverify the original chain and current context rather than accepting this value.
pub struct VerifiedIdentity {
    leaf: Value,
    digest: String,
    registrations: Vec<String>,
    task_digest: String,
    policy_digest: String,
}
impl VerifiedIdentity {
    /// Exact validated leaf fields, including preserved nonhuman origin.
    pub fn principal(&self) -> &Value {
        &self.leaf
    }
    /// SHA-256 of the complete compact leaf JWS, without a domain prefix.
    pub fn principal_digest(&self) -> &str {
        &self.digest
    }
    /// Ordered admitted registrations for the verified chain.
    pub fn registration_ids(&self) -> &[String] {
        &self.registrations
    }
    /// Current task revision checked in this verification.
    pub fn task_digest(&self) -> &str {
        &self.task_digest
    }
    /// Current policy revision checked in this verification.
    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }
}

fn schemas() -> &'static (Value, Value) {
    static SCHEMAS: OnceLock<(Value, Value)> = OnceLock::new();
    SCHEMAS.get_or_init(|| {
        (
            serde_json::from_str(include_str!(
                "../contracts/identity-v1/foundation.schema.json"
            ))
            .expect("pinned foundation schema"),
            serde_json::from_str(include_str!(
                "../contracts/identity-v1/warden-admission.schema.json"
            ))
            .expect("pinned admission schema"),
        )
    })
}

fn current(nbf: i64, exp: i64, now: i64) -> bool {
    nbf >= 0
        && exp <= 9_007_199_254_740_991
        && now.checked_sub(2).is_some_and(|n| nbf <= n)
        && now.checked_add(2).is_some_and(|n| n < exp)
}
fn number(value: &Value, field: &str) -> Result<i64, Error> {
    value[field].as_i64().ok_or(Error::Unauthorized)
}
fn contained(p: &Value, a: &Authority) -> bool {
    ["scopes", "resources"].iter().all(|field| {
        let permitted = if *field == "scopes" {
            &a.scopes
        } else {
            &a.resources
        };
        p[*field].as_array().is_some_and(|items| {
            items.iter().all(|item| {
                item.as_str()
                    .is_some_and(|s| permitted.iter().any(|v| v == s))
            })
        })
    }) && p["nbf"].as_i64().is_some_and(|n| n >= a.not_before)
        && p["exp"].as_i64().is_some_and(|n| n <= a.expires)
}
fn subset(child: &Value, parent: &Value, name: &str) -> bool {
    child[name].as_array().is_some_and(|items| {
        parent[name]
            .as_array()
            .is_some_and(|allowed| items.iter().all(|item| allowed.contains(item)))
    })
}
fn valid_authority(a: &Authority, now: i64) -> bool {
    v::is_digest(&a.digest)
        && current(a.not_before, a.expires, now)
        && !a.scopes.is_empty()
        && a.scopes.len() <= 3
        && a.scopes
            .iter()
            .all(|s| matches!(s.as_str(), "read" | "evaluate" | "propose"))
        && !a.resources.is_empty()
        && a.resources.len() <= 32
        && a.resources.iter().all(|r| v::identifier(r))
        && a.resources.iter().collect::<BTreeSet<_>>().len() == a.resources.len()
        && a.scopes.iter().collect::<BTreeSet<_>>().len() == a.scopes.len()
}

/// Verify complete, canonical decision evidence against the current recipient context.
///
/// # Errors
/// Refuses unavailable/quarantined authority or any invalid, ambiguous, expired,
/// widened or misbound evidence. Error values never include submitted bytes.
pub fn verify(chain: &[String], context: &Context) -> Result<VerifiedIdentity, Error> {
    if !context.available || context.restore_quarantined {
        return Err(Error::TrustUnavailable);
    }
    verify_current(chain, context).map_err(|_| Error::Unauthorized)
}

fn verify_current(chain: &[String], c: &Context) -> Result<VerifiedIdentity, Error> {
    if chain.is_empty()
        || chain.len() > 5
        || c.maximum_depth > 4
        || chain.len() - 1 > c.maximum_depth
        || chain
            .iter()
            .try_fold(0usize, |n, s| n.checked_add(s.len()))
            .is_none_or(|n| n > 65_536)
        || ![&c.deployment, &c.tenant, &c.audience, &c.peer_service]
            .iter()
            .all(|s| v::identifier(s))
        || !valid_authority(&c.task, c.now)
        || !valid_authority(&c.policy, c.now)
        || c.registrations.len() > 128
    {
        return Err(Error::Unauthorized);
    }
    let (foundation, admission) = schemas();
    let mut ids = BTreeSet::new();
    for registration in &c.registrations {
        v::shape(
            registration,
            &admission["$defs"]["delegation_registration"],
            admission,
        )?;
        if !ids.insert(v::text(registration, "registration_id")?) {
            return Err(Error::Unauthorized);
        }
    }
    let mut previous: Option<Value> = None;
    let mut previous_digest: Option<String> = None;
    let mut actors = BTreeSet::new();
    let mut evidence = Vec::new();
    for token in chain {
        if !token.is_ascii() {
            return Err(Error::Unauthorized);
        }
        let parts: Vec<_> = token.split('.').collect();
        if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
            return Err(Error::Unauthorized);
        }
        let header = v::canonical(&candidate::decode(parts[0], 512)?, 512)?;
        if header.as_object().is_none_or(|h| h.len() != 3)
            || header["alg"] != "Ed25519"
            || header["typ"] != "munarium-principal+jws"
        {
            return Err(Error::Unauthorized);
        }
        let key = c
            .keys
            .get(v::text(&header, "kid")?)
            .ok_or(Error::Unauthorized)?;
        if !key.decision {
            return Err(Error::Unauthorized);
        }
        let sig = Signature::from_slice(&candidate::decode(parts[2], 64)?)
            .map_err(|_| Error::Unauthorized)?;
        candidate::key(&key.public_key)?
            .verify_strict(
                &token.as_bytes()[..parts[0].len() + 1 + parts[1].len()],
                &sig,
            )
            .map_err(|_| Error::Unauthorized)?;
        let p = v::canonical(&candidate::decode(parts[1], v::MAX_JSON)?, v::MAX_JSON)?;
        v::shape(&p, &foundation["$defs"]["principal"], foundation)?;
        let nbf = number(&p, "nbf")?;
        let exp = number(&p, "exp")?;
        let iat = number(&p, "iat")?;
        if p["purpose"] != "decision"
            || !p["bootstrap"].is_null()
            || !matches!(v::text(&p, "origin_kind")?, "agent" | "service")
            || p["issuer"] != key.issuer
            || p["deployment"] != c.deployment
            || p["tenant"] != c.tenant
            || p["audience"] != c.audience
            || iat > nbf
            || exp - iat > 60
            || !current(nbf, exp, c.now)
            || !contained(&p, &c.task)
            || !contained(&p, &c.policy)
            || !actors.insert(v::text(&p, "actor")?.to_owned())
        {
            return Err(Error::Unauthorized);
        }
        if let Some(parent) = &previous {
            if p["origin"] != parent["origin"]
                || p["origin_kind"] != parent["origin_kind"]
                || p["parent_digest"].as_str() != previous_digest.as_deref()
                || nbf < number(parent, "nbf")?
                || exp > number(parent, "exp")?
                || !subset(&p, parent, "scopes")
                || !subset(&p, parent, "resources")
            {
                return Err(Error::Unauthorized);
            }
            let matches: Vec<_> = c
                .registrations
                .iter()
                .filter(|r| {
                    r["deployment"] == c.deployment
                        && r["tenant"] == c.tenant
                        && r["origin"] == p["origin"]
                        && r["origin_kind"] == p["origin_kind"]
                        && r["from_actor"] == parent["actor"]
                        && r["to_actor"] == p["actor"]
                        && r["presenter_service"] == p["service"]
                        && r["audience"] == c.audience
                        && r["task_digest"] == c.task.digest
                        && r["policy_digest"] == c.policy.digest
                })
                .collect();
            if matches.len() != 1 {
                return Err(Error::Unauthorized);
            }
            let r = matches[0];
            if !current(number(r, "nbf")?, number(r, "exp")?, c.now)
                || nbf < number(r, "nbf")?
                || exp > number(r, "exp")?
                || chain.len() - 1 > number(r, "max_depth")? as usize
                || !subset(&p, r, "scopes")
                || !subset(&p, r, "resources")
            {
                return Err(Error::Unauthorized);
            }
            evidence.push(v::text(r, "registration_id")?.to_owned());
        } else if !p["parent_digest"].is_null() || p["actor"] != p["origin"] {
            return Err(Error::Unauthorized);
        }
        previous_digest = Some(format!("sha256:{:x}", Sha256::digest(token.as_bytes())));
        previous = Some(p);
    }
    let leaf = previous.ok_or(Error::Unauthorized)?;
    if leaf["service"] != c.peer_service {
        return Err(Error::Unauthorized);
    }
    Ok(VerifiedIdentity {
        leaf,
        digest: previous_digest.ok_or(Error::Unauthorized)?,
        registrations: evidence,
        task_digest: c.task.digest.clone(),
        policy_digest: c.policy.digest.clone(),
    })
}

fn caller(chain: &[String], c: &Context, permission: Permission) -> Result<Caller, Error> {
    let verified = verify(chain, c)?;
    let rules: Vec<_> = c
        .access
        .iter()
        .filter(|r| r.permission == permission)
        .collect();
    if rules.len() != 1 || !v::identifier(&rules[0].resource) {
        return Err(Error::Unauthorized);
    }
    let scope = if permission == Permission::Submit {
        "propose"
    } else {
        "read"
    };
    if !v::array(&verified.leaf, "scopes")?
        .iter()
        .any(|v| v == scope)
        || !v::array(&verified.leaf, "resources")?
            .iter()
            .any(|v| v == &rules[0].resource)
    {
        return Err(Error::Unauthorized);
    }
    Caller::from_verified_identity(&c.tenant, &[permission])
}

/// Reverify identity and submit an inert candidate under independently admitted access.
///
/// # Errors
/// Refuses identity/access failure or any candidate admission failure without mutation.
pub fn submit(
    registry: &mut Registry,
    chain: &[String],
    c: &Context,
    input: &Submission,
) -> Result<Candidate, Error> {
    let caller = caller(chain, c, Permission::Submit)?;
    registry.intake(&caller).submit(input)
}

/// Reverify identity and resolve exact bytes within the verified tenant.
///
/// # Errors
/// Refuses identity/access failure, missing bytes or current artifact-trust failure.
pub fn resolve(
    registry: &Registry,
    chain: &[String],
    c: &Context,
    query: &Query,
) -> Result<Candidate, Error> {
    let caller = caller(chain, c, Permission::Read)?;
    registry.reader(&caller).resolve(query)
}

/// Reverify identity and list currently verifiable candidates with separate list access.
///
/// # Errors
/// Refuses identity/access failure or any unverified candidate; returns no partial list.
pub fn list(registry: &Registry, chain: &[String], c: &Context) -> Result<Vec<Candidate>, Error> {
    let caller = caller(chain, c, Permission::List)?;
    registry.reader(&caller).list()
}
