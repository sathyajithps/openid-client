use crate::tokenset::TokenSet;

/// # DeviceFlowGrantResponse
/// Response of the [`crate::client::device_flow_handle::DeviceFlowHandle::grant_async()`] method
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
