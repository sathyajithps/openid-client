use std::collections::HashMap;

use josekit::jwk::Jwk;

/// # UserinfoRequestParams
/// Parameters for customizing Userinfo request
pub struct UserinfoOptions<'a> {
    /// Request method: POST or GET
    pub method: &'a str,
    /// How to send the access token. Valid values: `header` or `body` (POST request)
    pub via: &'a str,
    /// Additional params to sent with the userinfo request
    pub params: Option<HashMap<String, String>>,
    /// When provided the client will send a DPoP Proof JWT.
    pub dpop: Option<&'a Jwk>,
}

impl Default for UserinfoOptions<'_> {
    fn default() -> Self {
        Self {
            method: "GET",
            via: "header",
            params: None,
            dpop: None,
        }
    }
}
