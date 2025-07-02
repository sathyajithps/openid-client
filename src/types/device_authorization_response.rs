use serde::Deserialize;

/// # DeviceAuthorizationResponse
/// The response from OP for a Device Authorization.
#[derive(Deserialize, Debug)]
pub struct DeviceAuthorizationResponse {
    /// The end-user verification URI on the authorization
    ///  server.  The URI should be short and easy to remember as end users
    ///  will be asked to manually type it into their user agent.
    pub verification_uri: String,
    /// A verification URI that includes the "user_code" (or
    /// other information with the same function as the "user_code"),
    /// which is designed for non-textual transmission.
    pub verification_uri_complete: Option<String>,
    /// The end user verification code
    pub user_code: String,
    /// The device code
    pub device_code: String,
    /// The lifetime in seconds of the "device_code" and "user_code".
    pub expires_in: u64,
    /// The minimum amount of time in seconds that the client
    /// waits between polling requests to the token endpoint.  If no
    /// value is provided, 5 seconds is used by default
    pub interval: Option<u64>,
}
