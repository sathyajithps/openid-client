use std::collections::HashMap;

use serde::{Deserialize, Deserializer};
use serde_json::Value;

use crate::helpers::base64_url_decode;

/// # TokenSet
/// Represents a set of tokens retrieved from either authorization callback or successful token endpoint grant call.
/// - If there are other properties present, it will be stored in `other` field.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct TokenSet {
    /// Access token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    /// Type of access token (normalized to lowercase per RFC 6749 Section 5.1)
    #[serde(
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_token_type",
        default
    )]
    pub token_type: Option<String>,
    /// Id token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    /// Refresh token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Access token expiry in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    /// Session state of the user
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_state: Option<String>,
    /// Scope of access token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Extra fields received
    #[serde(skip_serializing_if = "Option::is_none", flatten)]
    pub other: Option<HashMap<String, Value>>,
}

/// Deserializes token_type and normalizes to lowercase per RFC 6749 Section 5.1
fn deserialize_token_type<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    Ok(opt.map(|s| s.to_lowercase()))
}

impl TokenSet {
    /// Get claims from the id_token
    /// - This method just decodes and returns the found claims. Does not validate
    pub fn claims(&self) -> Option<HashMap<String, Value>> {
        if let Some(id_token) = &self.id_token {
            let id_token_components: Vec<&str> = id_token.split('.').collect();
            let payload = id_token_components.get(1)?;
            return match base64_url_decode(payload) {
                Ok(decoded) => {
                    serde_json::from_slice::<HashMap<String, Value>>(decoded.as_bytes()).ok()
                }
                Err(_) => None,
            };
        }
        None
    }
}
