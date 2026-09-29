// SPDX-License-Identifier: Apache-2.0
//! Read an immutable artifact through a tenant-scoped query.
//!
//! Readers must distinguish authentic bytes from currently authorized capability. Effective views require activation epoch, freshness, and revocation context.
//!
//! Proposed local interface only. No implementation or wire format is provided.

/// Proposed boundary for: read an immutable artifact through a tenant-scoped query.
///
/// Implementations and concrete types await the component design and hub contracts.
/// This declaration does not enforce authentication, authorization, or durability.
pub trait CatalogReader {
    /// Input whose concrete shape and validation rules are still to be specified.
    type Query;
    /// Output whose concrete shape and evidence requirements are still to be specified.
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
