use std::collections::HashMap;

use serde_json::Value;

/// # RefreshParams
/// Parameters for the Client's `refresh_async` request
pub struct RefreshTokenRequestParams {
    /// Additional claims to be added in the client assertion payload
    pub client_assertion_payload: Option<HashMap<String, Value>>,
    /// Additional body params to sent with the exchange request
    pub exchange_body: Option<HashMap<String, Value>>,
}
