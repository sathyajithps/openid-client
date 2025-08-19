use std::collections::HashMap;

use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize, Debug, Clone)]
/// # CibaAuthResponse
/// The response of a CIBA Authentication Request
pub struct CibaAuthResponse {
    /// Auth id
    pub auth_req_id: String,
    /// Seconds in which the auth_req_id is valid for
    pub expires_in: u64,
    /// Seconds a client should wait in between poll requests.
    pub interval: Option<u64>,
    /// Extra key-value sent by the server
    #[serde(flatten)]
    pub others: HashMap<String, Value>,
}
