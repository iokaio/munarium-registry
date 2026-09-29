// SPDX-License-Identifier: Apache-2.0
//! Apply an independently authorized transition against expected prior state.
//!
//! Implementations must validate authority, tenant, environment, digest, and expected activation before a durable compare-and-set transition.
//!
//! Proposed local interface only. No implementation or wire format is provided.

/// Proposed boundary for: apply an independently authorized transition against expected prior state.
///
/// Implementations and concrete types await the component design and hub contracts.
/// This declaration does not enforce authentication, authorization, or durability.
pub trait ActivationStore {
    /// Input whose concrete shape and validation rules are still to be specified.
    type AuthorizedTransition;
    /// Output whose concrete shape and evidence requirements are still to be specified.
    type ActivationRecord;
    /// Failure reported without manufacturing a successful or authorized result.
    type Error;

    /// Apply an independently authorized transition against expected prior state.
    ///
    /// # Errors
    ///
    /// Implementations must report failed validation or unavailable required dependencies.
    fn activate(
        &mut self,
        input: &Self::AuthorizedTransition,
    ) -> Result<Self::ActivationRecord, Self::Error>;
}
