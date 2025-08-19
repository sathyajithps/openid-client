use crate::types::{Header, Payload};

/// # ValidatedJwt
/// Represents the ValidatedJwt
pub struct ValidatedJwt {
    /// Decoded header
    pub header: Header,
    /// Decoded payload
    pub payload: Payload,
}
