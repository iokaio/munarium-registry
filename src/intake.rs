// SPDX-License-Identifier: Apache-2.0
//! Record an inert candidate for later review.
//!
//! Discovery and agent submission cannot alter the effective catalog; candidate identifiers are not activation attestations.
//!
//! The experimental [`crate::candidate::Intake`] implements candidate-only admission.

/// Proposed boundary for: record an inert candidate for later review.
///
/// The candidate implementation uses a pinned, unreleased hub contract.
/// This declaration does not enforce authentication, authorization, or durability.
pub trait CandidateIntake {
    /// Implementation-specific candidate submission.
    type Candidate;
    /// Candidate reference with implementation-specific admission evidence.
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
