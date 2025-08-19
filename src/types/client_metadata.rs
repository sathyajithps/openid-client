use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::types::{JweAlg, JweEncAlg, JwtSigningAlg};

/// # Client Metadata
/// Options of a configured client instance
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientMetadata {
    /// Client Id
    pub client_id: String,

    /// Post logout redirect uri
    pub post_logout_redirect_uri: Option<String>,

    /// Client requires tls bound access tokens
    pub tls_client_certificate_bound_access_tokens: Option<bool>,

    /// Jarm supported alg value
    pub authorization_signed_response_alg: Option<JwtSigningAlg>,

    /// Algorithm for signing the ID Token issued
    pub id_token_signed_response_alg: Option<JwtSigningAlg>,

    /// Algorithm for encrypting ID Token responses
    pub id_token_encrypted_response_alg: Option<JweAlg>,

    /// Content encryption algorithm for ID Token
    pub id_token_encrypted_response_enc: Option<JweEncAlg>,

    /// Default Maximum Authentication Age
    pub default_max_age: Option<u64>,

    /// Boolean value specifying whether the auth_time Claim in the ID Token is required
    pub require_auth_time: Option<bool>,

    /// Algorithm for signing UserInfo JWT responses
    pub userinfo_signed_response_alg: Option<JwtSigningAlg>,

    /// Algorithm for encrypting UserInfo responses
    pub userinfo_encrypted_response_alg: Option<JweAlg>,

    /// Content encryption algorithm for UserInfo
    pub userinfo_encrypted_response_enc: Option<JweEncAlg>,

    /// Algorithm for signing request objects
    pub request_object_signing_alg: Option<JwtSigningAlg>,

    /// Algorithm for encrypting request objects
    pub request_object_encryption_alg: Option<JweAlg>,

    /// Content encryption algorithm for request objects
    pub request_object_encryption_enc: Option<JweEncAlg>,

    /// Extra key values
    #[serde(flatten, skip_serializing_if = "HashMap::is_empty")]
    pub additional_data: HashMap<String, Value>,
}

// use serde::{Deserialize, Serialize};
// use std::collections::HashMap;

// #[derive(Debug, Serialize, Deserialize)]
// pub struct ClientRegistration {
//     pub redirect_uris: Vec<String>,

//     /// OPTIONAL. List of OAuth 2.0 response_type values
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub response_types: Option<Vec<String>>,

//     /// OPTIONAL. List of OAuth 2.0 Grant Types
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub grant_types: Option<Vec<String>>,

//     /// OPTIONAL. Application type (web | native)
//     #[serde(default = "default_application_type")]
//     pub application_type: String,

//     /// OPTIONAL. Contact emails
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub contacts: Option<Vec<String>>,

//     /// OPTIONAL. Client name (can support multilingual versions via map)
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub client_name: Option<String>,

//     /// OPTIONAL. Logo URI
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub logo_uri: Option<String>,

//     /// OPTIONAL. Client home page
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub client_uri: Option<String>,

//     /// OPTIONAL. Policy page URI
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub policy_uri: Option<String>,

//     /// OPTIONAL. Terms of Service URI
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub tos_uri: Option<String>,

//     /// OPTIONAL. JWKS URI
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub jwks_uri: Option<String>,

//     /// OPTIONAL. JWK Set (inline)
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub jwks: Option<serde_json::Value>,

//     /// OPTIONAL. Sector Identifier URI
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub sector_identifier_uri: Option<String>,

//     /// OPTIONAL. subject_type (pairwise | public)
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub subject_type: Option<String>,

//     /// OPTIONAL. ID Token signing algorithm
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub id_token_signed_response_alg: Option<String>,

//     /// OPTIONAL. ID Token encryption alg
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub id_token_encrypted_response_alg: Option<String>,

//     /// OPTIONAL. ID Token encryption enc
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub id_token_encrypted_response_enc: Option<String>,

//     /// OPTIONAL. UserInfo signing algorithm
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub userinfo_signed_response_alg: Option<String>,

//     /// OPTIONAL. UserInfo encryption alg
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub userinfo_encrypted_response_alg: Option<String>,

//     /// OPTIONAL. UserInfo encryption enc
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub userinfo_encrypted_response_enc: Option<String>,

//     /// OPTIONAL. Request Object signing alg
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub request_object_signing_alg: Option<String>,

//     /// OPTIONAL. Request Object encryption alg
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub request_object_encryption_alg: Option<String>,

//     /// OPTIONAL. Request Object encryption enc
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub request_object_encryption_enc: Option<String>,

//     /// OPTIONAL. Token endpoint authentication method
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub token_endpoint_auth_method: Option<String>,

//     /// OPTIONAL. Token endpoint signing algorithm
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub token_endpoint_auth_signing_alg: Option<String>,

//     /// OPTIONAL. Default max authentication age (in seconds)
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub default_max_age: Option<u64>,

//     /// OPTIONAL. Require auth_time claim in ID Token
//     #[serde(default)]
//     pub require_auth_time: bool,

//     /// OPTIONAL. Default ACR values
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub default_acr_values: Option<Vec<String>>,

//     /// OPTIONAL. Initiate login URI
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub initiate_login_uri: Option<String>,

//     /// OPTIONAL. Request URIs
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub request_uris: Option<Vec<String>>,

//     #[serde(flatten, skip_serializing_if = "HashMap::is_empty")]
//     pub other_fields: HashMap<String, Value>,
// }

// /// Default for application_type
// fn default_application_type() -> String {
//     "web".to_string()
// }
