use std::collections::HashMap;

use josekit::jwk::Jwk;
use serde_json::Value;

/// # PushedAuthorizationRequestParams
/// Parameters for Pushed Authorization Request
pub struct PushedAuthorizationRequestExtras<'a> {
    /// Additional claims to be added in the client assertion payload
    pub client_assertion_payload: Option<HashMap<String, Value>>,
    /// When provided the client will send a DPoP Proof JWT.
    pub dpop: Option<&'a Jwk>,
}
