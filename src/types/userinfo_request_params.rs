use std::collections::HashMap;

use reqwest::Method;
use serde_json::Value;

/// # UserinfoRequestParams
/// Parameters for customizing Userinfo request
pub struct UserinfoRequestParams {
    /// Request method
    pub method: Method,
    /// How to send the access token. Valid values: `header` or `body` (POST request)
    pub via: String,
    /// Additional params to sent with the userinfo request
    pub params: Option<HashMap<String, Value>>,
}

impl Default for UserinfoRequestParams {
    fn default() -> Self {
        Self {
            method: Method::GET,
            via: "header".to_string(),
            params: None,
        }
    }
}
