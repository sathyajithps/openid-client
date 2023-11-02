use std::collections::HashMap;

use serde_json::Value;

/// # PushedAuthorizationRequestParams
/// Parameters for Pushed Authorization Request
pub struct PushedAuthorizationRequestParams {
    /// Additional claims to be added in the client assertion payload
    pub client_assertion_payload: Option<HashMap<String, Value>>,
}
