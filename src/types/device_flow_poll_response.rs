use crate::tokenset::TokenSet;

/// # DeviceFlowPollResponse
/// Response of the DeviceFlowHandle::poll method
#[derive(Debug)]
pub enum DeviceFlowGrantResponse {
    /// Indicates that the AS is being polled much more frequent than allowed
    SlowDown,
    /// User authorization is pending
    AuthorizationPending,
    /// Indicates that Grant called before the interval time has passed
    Debounced,
    /// Authorization Succeeded.
    Successful(Box<TokenSet>),
}
