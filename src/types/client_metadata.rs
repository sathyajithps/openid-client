use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    jwk::{Jwk, Jwks},
    types::ClientRegistrationResponse,
};

/// # Client Metadata
/// Options of a configured client instance
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientMetadata {
    /// Client Id
    pub client_id: String,

    /// Post logout redirect uri
    pub post_logout_redirect_uri: Option<String>,

    /// Backchannel logout URI
    pub backchannel_logout_uri: Option<String>,

    /// Specifying whether the RP requires a sid claim in the Logout Token
    pub backchannel_logout_session_required: Option<bool>,

    /// Client requires tls bound access tokens
    pub tls_client_certificate_bound_access_tokens: Option<bool>,

    /// Jarm supported alg value
    pub authorization_signed_response_alg: Option<String>,

    /// Algorithm for signing the ID Token issued
    pub id_token_signed_response_alg: Option<String>,

    /// Algorithm for encrypting ID Token responses
    pub id_token_encrypted_response_alg: Option<String>,

    /// Content encryption algorithm for ID Token
    pub id_token_encrypted_response_enc: Option<String>,

    /// Default Maximum Authentication Age
    pub default_max_age: Option<u64>,

    /// Boolean value specifying whether the auth_time Claim in the ID Token is required
    pub require_auth_time: Option<bool>,

    /// Algorithm for signing UserInfo JWT responses
    pub userinfo_signed_response_alg: Option<String>,

    /// Algorithm for encrypting UserInfo responses
    pub userinfo_encrypted_response_alg: Option<String>,

    /// Content encryption algorithm for UserInfo
    pub userinfo_encrypted_response_enc: Option<String>,

    /// Algorithm for signing request objects
    pub request_object_signing_alg: Option<String>,

    /// Algorithm for encrypting request objects
    pub request_object_encryption_alg: Option<String>,

    /// Content encryption algorithm for request objects
    pub request_object_encryption_enc: Option<String>,

    /// Client's Jwks
    pub jwks: Option<Jwks>,

    /// Client Jwks uri
    pub jwks_uri: Option<String>,

    /// Extra key values
    #[serde(flatten, skip_serializing_if = "HashMap::is_empty")]
    pub additional_data: HashMap<String, Value>,
}

impl From<ClientRegistrationResponse> for ClientMetadata {
    fn from(value: ClientRegistrationResponse) -> Self {
        let mut metadata = value.metadata;

        Self {
            client_id: value.client_id,
            post_logout_redirect_uri: take_string(&mut metadata, "post_logout_redirect_uri")
                .or_else(|| take_first_string(&mut metadata, "post_logout_redirect_uris")),
            backchannel_logout_uri: take_string(&mut metadata, "backchannel_logout_uri"),
            backchannel_logout_session_required: take_bool(
                &mut metadata,
                "backchannel_logout_session_required",
            ),
            tls_client_certificate_bound_access_tokens: take_bool(
                &mut metadata,
                "tls_client_certificate_bound_access_tokens",
            ),
            authorization_signed_response_alg: take_string(
                &mut metadata,
                "authorization_signed_response_alg",
            ),
            id_token_signed_response_alg: take_string(
                &mut metadata,
                "id_token_signed_response_alg",
            ),
            id_token_encrypted_response_alg: take_string(
                &mut metadata,
                "id_token_encrypted_response_alg",
            ),
            id_token_encrypted_response_enc: take_string(
                &mut metadata,
                "id_token_encrypted_response_enc",
            ),
            default_max_age: take_u64(&mut metadata, "default_max_age"),
            require_auth_time: take_bool(&mut metadata, "require_auth_time"),
            userinfo_signed_response_alg: take_string(
                &mut metadata,
                "userinfo_signed_response_alg",
            ),
            userinfo_encrypted_response_alg: take_string(
                &mut metadata,
                "userinfo_encrypted_response_alg",
            ),
            userinfo_encrypted_response_enc: take_string(
                &mut metadata,
                "userinfo_encrypted_response_enc",
            ),
            request_object_signing_alg: take_string(&mut metadata, "request_object_signing_alg"),
            request_object_encryption_alg: take_string(
                &mut metadata,
                "request_object_encryption_alg",
            ),
            request_object_encryption_enc: take_string(
                &mut metadata,
                "request_object_encryption_enc",
            ),
            jwks: take_jwks(&mut metadata, "jwks"),
            jwks_uri: take_string(&mut metadata, "jwks_uri"),
            additional_data: metadata,
        }
    }
}

#[inline]
fn take_string(metadata: &mut HashMap<String, Value>, key: &str) -> Option<String> {
    match metadata.remove(key) {
        Some(Value::String(value)) => Some(value),
        Some(value) => {
            metadata.insert(key.to_owned(), value);
            None
        }
        None => None,
    }
}

#[inline]
fn take_first_string(metadata: &mut HashMap<String, Value>, key: &str) -> Option<String> {
    match metadata.remove(key) {
        Some(Value::String(value)) => Some(value),
        Some(Value::Array(values)) => {
            let mut values = values.into_iter();

            match values.next() {
                Some(Value::String(value)) => Some(value),
                Some(value) => {
                    let mut original = Vec::with_capacity(values.size_hint().0 + 1);
                    original.push(value);
                    original.extend(values);
                    metadata.insert(key.to_owned(), Value::Array(original));
                    None
                }
                None => {
                    metadata.insert(key.to_owned(), Value::Array(Vec::new()));
                    None
                }
            }
        }
        Some(value) => {
            metadata.insert(key.to_owned(), value);
            None
        }
        None => None,
    }
}

#[inline]
fn take_bool(metadata: &mut HashMap<String, Value>, key: &str) -> Option<bool> {
    match metadata.remove(key) {
        Some(Value::Bool(value)) => Some(value),
        Some(value) => {
            metadata.insert(key.to_owned(), value);
            None
        }
        None => None,
    }
}

#[inline]
fn take_u64(metadata: &mut HashMap<String, Value>, key: &str) -> Option<u64> {
    match metadata.remove(key) {
        Some(Value::Number(value)) => match value.as_u64() {
            Some(value) => Some(value),
            None => {
                metadata.insert(key.to_owned(), Value::Number(value));
                None
            }
        },
        Some(value) => {
            metadata.insert(key.to_owned(), value);
            None
        }
        None => None,
    }
}

#[inline]
fn take_jwks(metadata: &mut HashMap<String, Value>, key: &str) -> Option<Jwks> {
    match metadata.remove(key) {
        Some(Value::Object(mut object)) => match object.remove("keys") {
            Some(Value::Array(values)) => values_to_jwks(values),
            Some(value) => {
                object.insert("keys".to_owned(), value);
                metadata.insert(key.to_owned(), Value::Object(object));
                None
            }
            None => {
                metadata.insert(key.to_owned(), Value::Object(object));
                None
            }
        },
        Some(value) => {
            metadata.insert(key.to_owned(), value);
            None
        }
        None => None,
    }
}

#[inline]
fn values_to_jwks(values: Vec<Value>) -> Option<Jwks> {
    let mut jwks = Vec::with_capacity(values.len());

    for value in values {
        match value {
            Value::Object(params) => jwks.push(Jwk { params }),
            _ => return None,
        }
    }

    Some(Jwks { keys: jwks })
}
