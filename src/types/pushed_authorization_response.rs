use serde_json::Value;
use std::collections::HashMap;

use serde::Deserialize;

/// # PushedAuthorizationResponse
/// The response of a pushed authorization request
#[derive(Deserialize)]
pub struct PushedAuthorizationResponse {
    /// Seconds in which the request_uri is valid for
    pub expires_in: u64,
    /// The authorization request uri
    pub request_uri: String,
    /// Extra key-value sent by the server
    #[serde(flatten)]
    pub others: HashMap<String, Value>,
}
