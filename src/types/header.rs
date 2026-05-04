use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Represents a JOSE header used in JWE/JWS operations.
///
/// The header contains algorithm and parameter fields as defined by the JOSE standards.
/// Fields are stored as a JSON object for flexibility and extensibility.
#[derive(Serialize, Deserialize)]
pub struct Header {
    /// The raw collection of header fields stored as a JSON map.
    #[serde(flatten)]
    pub params: Map<String, Value>,
}

impl Header {
    /// Extracts and parses the "alg" header parameter.
    pub fn alg(&self) -> Option<String> {
        self.params
            .get("alg")
            .and_then(|alg| alg.as_str().map(|alg_str| alg_str.to_owned()))
    }
}
