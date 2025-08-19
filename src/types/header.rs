use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::types::{JweAlg, JwtSigningAlg};

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
    /// Extracts and parses the "alg" header parameter specifically for JWS signing.
    pub fn alg(&self) -> Option<JwtSigningAlg> {
        self.params
            .get("alg")
            .and_then(|alg| alg.as_str())
            .and_then(JwtSigningAlg::from_alg_str)
    }

    /// Extracts and parses the "alg" header parameter specifically for JWE encryption.
    pub fn jwe_alg(&self) -> Option<JweAlg> {
        self.params
            .get("alg")
            .and_then(|alg| alg.as_str())
            .and_then(JweAlg::from_alg_str)
    }
}
