use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Represents the payload of a JWE or JWS message.
///
/// The payload contains the claims or data being transmitted or protected.
/// Fields are stored as a JSON object, allowing arbitrary claim sets.
#[derive(Serialize, Deserialize)]
pub struct Payload {
    /// The payload fields as a JSON map (key-value pairs).
    #[serde(flatten)]
    pub params: Map<String, Value>,
}
