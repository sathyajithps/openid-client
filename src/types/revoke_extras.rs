use std::collections::HashMap;

use serde_json::Value;

/// # RevokeRequestParams
/// Parameters for customizing Token Revocation request
pub struct RevokeExtras {
    /// Additional claims to be added in the client assertion payload
    pub client_assertion_payload: Option<HashMap<String, Value>>,
    /// Additional body params to sent with the revocation request
    pub revocation_body: Option<HashMap<String, String>>,
}
