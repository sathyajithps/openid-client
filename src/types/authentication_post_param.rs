use std::collections::HashMap;

use josekit::jwk::Jwk;
use serde_json::Value;

/// # AuthenticationPostParams
/// Parameters for customizing Authentication Post request
#[derive(Debug, Default, Clone)]
pub struct AuthenticationPostParams<'a> {
    /// Additional claims to be added in the client assertion payload
    pub client_assertion_payload: Option<&'a HashMap<String, Value>>,
    /// Specific endpoint auth method to use
    pub endpoint_auth_method: Option<&'a str>,
    /// Private key belonging to the client for Dynamic Proof of Posession
    pub dpop: Option<&'a Jwk>,
}
