use std::collections::HashMap;

use josekit::jwk::Jwk;
use serde_json::Value;

/// # GrantExtras
/// Parameters for customizing Grant request
#[derive(Debug, Default, Clone)]
pub struct GrantExtras<'a> {
    /// Additional claims to be added in the client assertion payload
    pub client_assertion_payload: Option<HashMap<String, Value>>,
    /// Specific endpoint auth method to use
    pub endpoint_auth_method: Option<&'a str>,
    /// Private key belonging to the client for Dynamic Proof of Posession
    pub dpop: Option<&'a Jwk>,
}
