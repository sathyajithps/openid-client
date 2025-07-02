use crate::tokenset::TokenSet;

/// # CibaGrantResponse
/// Response of the CibaHandle::grant_async() method
#[derive(Debug)]
pub enum CibaGrantResponse {
    /// Indicates that the AS is being polled much more frequent than allowed
    SlowDown,
    /// User authorization is pending
    AuthorizationPending,
    /// Auth request id expired
    ExpiredToken,
    /// User denied the authorization request
    AccessDenied,
    /// Indicates that Grant called before the interval time has passed
    Debounced,
    /// Authorization Succeeded.
    Successful(Box<TokenSet>),
}
