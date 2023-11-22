use std::collections::HashMap;

use josekit::jwk::Jwk;
use reqwest::Method;

/// # UserinfoRequestParams
/// Parameters for customizing Userinfo request
pub struct UserinfoOptions {
    /// Request method
    pub method: Method,
    /// How to send the access token. Valid values: `header` or `body` (POST request)
    pub via: String,
    /// Additional params to sent with the userinfo request
    pub params: Option<HashMap<String, String>>,
    /// When provided the client will send a DPoP Proof JWT.
    pub dpop: Option<Jwk>,
}

impl Default for UserinfoOptions {
    fn default() -> Self {
        Self {
            method: Method::GET,
            via: "header".to_string(),
            params: None,
            dpop: None,
        }
    }
}
