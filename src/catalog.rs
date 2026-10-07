// SPDX-License-Identifier: Apache-2.0
//! Read an immutable artifact through a tenant-scoped query.
//!
//! Readers must distinguish authentic bytes from currently authorized capability. Effective views require activation epoch, freshness, and revocation context.
//!
//! The experimental [`crate::candidate::Reader`] implements candidate-only lookup.

/// Proposed boundary for: read an immutable artifact through a tenant-scoped query.
///
/// The candidate implementation uses a pinned, unreleased hub contract.
/// This declaration does not enforce authentication, authorization, or durability.
pub trait CatalogReader {
    /// Implementation-specific lookup constraints.
    type Query;
    /// Artifact and its implementation-specific verification evidence.
    type Artifact;
    /// Failure reported without manufacturing a successful or authorized result.
    type Error;

    /// Read an immutable artifact through a tenant-scoped query.
    ///
    /// # Errors
    ///
    /// Implementations must report failed validation or unavailable required dependencies.
    fn resolve(&self, input: &Self::Query) -> Result<Self::Artifact, Self::Error>;
}
