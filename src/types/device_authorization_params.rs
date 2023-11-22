use std::collections::HashMap;

use serde_json::Value;

/// # DeviceAuthorizationParams
/// Parameters for performing Device Authorization
#[derive(Default)]
pub struct DeviceAuthorizationParams {
    /// Client id for making the Device authorization request
    pub client_id: Option<String>,
    /// Scopes to request with
    pub scope: Option<Vec<String>>,
    /// Max age allowed for token in seconds
    pub max_age: Option<u64>,
    /// Other values that needs to be sent with the request
    pub other: HashMap<String, Value>,
}
