use std::collections::HashMap;

use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize, Debug)]
/// # ParResponse
/// The response of a pushed authorization request
pub struct ParResponse {
    /// Seconds in which the request_uri is valid for
    pub expires_in: u64,
    /// The authorization request uri
    pub request_uri: String,
    /// Extra key-value sent by the server
    #[serde(flatten)]
    pub others: HashMap<String, Value>,
}
