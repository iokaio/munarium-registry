// SPDX-License-Identifier: Apache-2.0
//! Record an inert candidate for later review.
//!
//! Discovery and agent submission cannot alter the effective catalog; candidate identifiers are not activation attestations.
//!
//! Proposed local interface only. No implementation or wire format is provided.

/// Proposed boundary for: record an inert candidate for later review.
///
/// Implementations and concrete types await the component design and hub contracts.
/// This declaration does not enforce authentication, authorization, or durability.
pub trait CandidateIntake {
    /// Input whose concrete shape and validation rules are still to be specified.
    type Candidate;
    /// Output whose concrete shape and evidence requirements are still to be specified.
    type CandidateReference;
    /// Failure reported without manufacturing a successful or authorized result.
    type Error;

    /// Record an inert candidate for later review.
    ///
    /// # Errors
    ///
    /// Implementations must report failed validation or unavailable required dependencies.
    fn submit(&mut self, input: &Self::Candidate) -> Result<Self::CandidateReference, Self::Error>;
}
