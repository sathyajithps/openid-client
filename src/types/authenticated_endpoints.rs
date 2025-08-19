/// # AuthenticatedEndpoints
/// Represents the AuthenticatedEndpoints
#[derive(Debug)]
pub enum AuthenticatedEndpoints {
    /// Token Endpoint
    Token,
    /// Introspection Endpoint
    Introspection,
    /// Revocation Endpoint
    Revocation,
    /// Pushed Authorization Endpoint
    PushedAuthorization,
    /// Device Authorization Endpoint
    DeviceAuthorization,
    /// Backchannel Authentication Endpoint
    BackChannelAuthentication,
}
