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
    /// Unix timestamp of when the auth response was received
    pub timestamp: Option<u64>,
    /// Extra key-value sent by the server
    #[serde(flatten)]
    pub others: HashMap<String, Value>,
}

impl CibaAuthResponse {
    /// Returns a reference to the authentication request identifier (`auth_req_id`).
    pub fn get_auth_req_id(&self) -> &str {
        &self.auth_req_id
    }

    /// Returns the number of seconds for which the authentication request identifier is valid.
    pub fn get_expires_in(&self) -> u64 {
        self.expires_in
    }

    /// Returns the recommended polling interval (in seconds), if specified.
    pub fn get_interval(&self) -> Option<u64> {
        self.interval
    }

    /// Returns a reference to the value associated with the given key in the extras map, if it exists.
    ///
    /// # Arguments
    /// * `key` - The key to look up in the extras map.
    pub fn get_key(&self, key: &str) -> Option<&Value> {
        self.others.get(key)
    }
}
