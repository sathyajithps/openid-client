use std::collections::HashMap;

use josekit::jwk::Jwk;
use serde_json::Value;

/// # RefreshParams
/// Parameters for the Client's `refresh_async` request
pub struct RefreshTokenExtras {
    /// Additional claims to be added in the client assertion payload
    pub client_assertion_payload: Option<HashMap<String, Value>>,
    /// Additional body params to sent with the exchange request
    pub exchange_body: Option<HashMap<String, String>>,
    /// When provided the client will send a DPoP Proof JWT.
    pub dpop: Option<Jwk>,
}
