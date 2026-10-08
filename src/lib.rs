// SPDX-License-Identifier: Apache-2.0
//! Munarium Registry: Stage 1 candidate catalog.
//!
//! Inventory of immutable artifacts, inert candidates, and separately authorized activations.
//!
//! The candidate module validates signed artifacts against a pinned hub candidate,
//! stores exact bytes in memory or SQLite and provides tenant-scoped read/intake handles.
//! Its identity adapter rechecks signed decision chains at each candidate operation.
//! The embedding host supplies authenticated peer context and current authority.
//! The separate service binary supplies mTLS admission; candidate custody grants no activation authority.
//! See `docs/architecture.md` and `docs/implementation-plan.md` in this repository.
//!
//! The interfaces are provisional and may change before the first release.
//! Formal contract acceptance and platform qualification remain pending.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod activation;
#[cfg(feature = "sqlite")]
pub mod activation_store;
pub mod candidate;
pub mod catalog;
pub mod identity;
pub mod intake;
mod validation;

#[path = "../vendor/warden-identity/identity-core/lib.rs"]
mod verifier;
pub use verifier::{encoding, error, policy, principal};
