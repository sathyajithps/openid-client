use std::collections::HashMap;

use josekit::{jwk::Jwk, jwt::JwtPayload};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::helpers::get_serde_value_as_string;

/// # CallbackParams
/// These are the fields that is recieved from the Authorization server to the client.
/// Which of these fields are present will depend up on the type of authorization request
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct CallbackParams {
    /// Access token obtained
    pub access_token: Option<String>,
    /// Authorization code for exchanging at token endpoint
    pub code: Option<String>,
    /// Error recieved from the Auth server. [See RFC](https://datatracker.ietf.org/doc/html/rfc6749#appendix-A.7)
    pub error: Option<String>,
    /// Error description recieved from the Auth server. [See RFC](https://datatracker.ietf.org/doc/html/rfc6749#appendix-A.7)
    pub error_description: Option<String>,
    /// Error uri recieved from the Auth server. [See RFC](https://datatracker.ietf.org/doc/html/rfc6749#appendix-A.7)
    pub error_uri: Option<String>,
    /// Token expiry
    pub expires_in: Option<String>,
    /// Id token
    pub id_token: Option<String>,
    /// State that was recieved from the Auth server
    pub state: Option<String>,
    /// Specified the access token type
    pub token_type: Option<String>,
    /// Session state
    pub session_state: Option<String>,
    /// The JARM response
    pub response: Option<String>,
    /// Issuer url
    pub iss: Option<String>,
    /// Other fields received from Auth server
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub other: Option<HashMap<String, Value>>,
}

impl CallbackParams {
    pub(crate) fn from_jwt_payload(payload: &JwtPayload) -> Self {
        let mut params = Self {
            access_token: Self::json_value_to_string_option(payload.claim("access_token")),
            code: Self::json_value_to_string_option(payload.claim("code")),
            error: Self::json_value_to_string_option(payload.claim("error")),
            error_description: Self::json_value_to_string_option(
                payload.claim("error_description"),
            ),
            error_uri: Self::json_value_to_string_option(payload.claim("error_uri")),
            expires_in: Self::json_value_to_string_option(payload.claim("exp")),
            id_token: Self::json_value_to_string_option(payload.claim("id_token")),
            state: Self::json_value_to_string_option(payload.claim("state")),
            token_type: Self::json_value_to_string_option(payload.claim("token_type")),
            session_state: Self::json_value_to_string_option(payload.claim("session_state")),
            response: Self::json_value_to_string_option(payload.claim("response")),
            iss: Self::json_value_to_string_option(payload.claim("iss")),
            other: None,
        };

        let mut other = HashMap::<String, Value>::new();

        for (k, v) in payload.claims_set().iter() {
            other.insert(k.to_string(), v.to_owned());
        }

        params.other = Some(other);

        params
    }

    fn json_value_to_string_option(value: Option<&Value>) -> Option<String> {
        if let Some(v) = value {
            return get_serde_value_as_string(v).ok();
        }

        None
    }
}

/// # CallbackExtras
/// Extra details to be used for the callback
pub struct CallbackExtras {
    /// Extra request body properties to be sent to the AS during code exchange.
    pub exchange_body: Option<HashMap<String, Value>>,
    /// Extra client assertion payload parameters to be sent as part of a client JWT assertion.
    /// This is only used when the client's token_endpoint_auth_method is either client_secret_jwt or private_key_jwt
    pub client_assertion_payload: Option<HashMap<String, Value>>,
    /// When provided the client will send a DPoP Proof JWT.
    /// The DPoP Proof JWT's algorithm is determined automatically based on the type of key and the issuer metadata.
    pub dpop: Option<Jwk>,
}

/// # OAuthCallbackChecks
/// Checks that needs to be performed against the OAuth [CallbackParams] recieved from the Auth server.
#[derive(Default, Serialize, Deserialize, Clone)]
pub struct OAuthCallbackChecks {
    /// When provided the authorization response will be checked for presence of required parameters for a given response_type. Use of this check is recommended.
    pub response_type: Option<String>,
    /// Expected state from the response
    pub state: Option<String>,
    /// PKCE code verified to be sent to the token endpoint  
    pub code_verifier: Option<String>,
    /// Specifies that the response will be a JARM response
    pub jarm: Option<bool>,
}

/// # OpenIDCallbackChecks
/// Checks that needs to be performed against the Oidc [CallbackParams] recieved from the Auth server.
#[derive(Default, Serialize, Deserialize)]
pub struct OpenIDCallbackChecks {
    /// When provided the authorization response's ID Token auth_time parameter will be checked to be conform to the max_age value. Use of this check is required if you sent a max_age parameter into an authorization request. Default: uses client's default_max_age.
    pub max_age: Option<u64>,
    /// When provided the authorization response's ID Token nonce parameter will be checked to be the this expected one.
    pub nonce: Option<String>,
    /// See [OAuthCallbackChecks]
    pub oauth_checks: Option<OAuthCallbackChecks>,
}
