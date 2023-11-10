use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::jwks::Jwks;

/// # Client Metadata
#[derive(Debug, Serialize, Deserialize, Default, PartialEq, Clone)]
pub struct ClientMetadata {
    /// Client Id
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Client secret
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// [Registration Access Token](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_access_token: Option<String>,
    /// [Registration Client Uri](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_client_uri: Option<String>,
    /// [Client Id Issued At](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id_issued_at: Option<i64>,
    /// [Secret Expiry](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    /// Epoch Seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<i64>,
    /// [Authentication method](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    /// used by the client for authenticating with the OP
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,
    /// [Algorithm](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    /// used for signing the JWT used to authenticate
    /// the client at the token endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg: Option<String>,
    /// [Authentication method](https://www.rfc-editor.org/rfc/rfc8414.html#section-2)
    /// used by the client for introspection endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint_auth_method: Option<String>,
    /// [Algorithm](https://www.rfc-editor.org/rfc/rfc8414.html#section-2)
    /// used for signing the JWT used to authenticate
    /// the client at the introspection endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint_auth_signing_alg: Option<String>,
    /// [Authentication method](https://www.rfc-editor.org/rfc/rfc8414.html#section-2)
    /// used by the client for revocation endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint_auth_method: Option<String>,
    /// [Algorithm](https://www.rfc-editor.org/rfc/rfc8414.html#section-2)
    /// used for signing the JWT used to authenticate
    /// the client at the revocation endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint_auth_signing_alg: Option<String>,
    /// The [redirect uri](https://openid.net/specs/openid-connect-http-redirect-1_0-01.html#rf_prep)
    /// where response will be sent
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    /// A list of acceptable [redirect uris](https://openid.net/specs/openid-connect-http-redirect-1_0-01.html#rf_prep)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uris: Option<Vec<String>>,
    /// [Response type](https://openid.net/specs/openid-connect-http-redirect-1_0-01.html#rf_prep) supported by the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_type: Option<String>,
    /// List of [Response type](https://openid.net/specs/openid-connect-http-redirect-1_0-01.html#rf_prep) supported by the client
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_types: Option<Vec<String>>,
    /// [Grant Types](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types: Option<Vec<String>>,
    /// [Jwks Uri](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    /// [JWKS](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<Jwks>,
    /// [Sector Identifier Uri](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sector_identifier_uri: Option<String>,
    /// [Subject Type](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_type: Option<String>,
    /// [Id Token Signed Response Algorithm](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_signed_response_alg: Option<String>,
    /// [Id Token Encrypted Response Algorithm](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_alg: Option<String>,
    /// [Id Token Encrypted Response Algorithm](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_enc: Option<String>,
    /// [Userinfo Signed Response Algorithm](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_signed_response_alg: Option<String>,
    /// [Userinfo Encrypted Response Algorithm](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encrypted_response_alg: Option<String>,
    /// [Userinfo Encrypted Response Algorithm](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encrypted_response_enc: Option<String>,
    /// [Request Object Signing Algorithm](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg: Option<String>,
    /// [Request Object Encryption Algorithm](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_alg: Option<String>,
    /// [Request Object Encryption Algorithm](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_enc: Option<String>,
    /// [Default Max Age](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_max_age: Option<u64>,
    /// [Require Auth Time](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_auth_time: Option<bool>,
    /// [Default Acr Values](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_acr_values: Option<Vec<String>>,
    /// [Initiate Login Uri](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiate_login_uri: Option<String>,
    /// [Request Uris](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_uris: Option<String>,
    /// Client's intention to use [mutual-TLS client certificate-bound access tokens](https://datatracker.ietf.org/doc/html/rfc8705#name-client-registration-metadata-2)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_client_certificate_bound_access_tokens: Option<bool>,
    /// Client's allowed redirect uris after a logout
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_logout_redirect_uris: Option<Vec<String>>,
    /// Algorithm used for signing authorization responses.
    /// If this is specified, the response will be signed using JWS and the configured algorithm.
    /// The algorithm none is not allowed. The default, if omitted, is RS256
    /// [See JARM Spec](https://openid.net/specs/openid-financial-api-jarm.html#client-metadata)
    pub authorization_signed_response_alg: Option<String>,
    /// Algorithm used for encrypting authorization responses.
    /// If both signing and encryption are requested, the response will be signed then encrypted,
    /// with the result being a Nested JWT, as defined in JWT RFC7519.
    /// The default, if omitted, is that no encryption is performed.
    /// [See JARM Spec](https://openid.net/specs/openid-financial-api-jarm.html#client-metadata)
    pub authorization_encrypted_response_alg: Option<String>,
    /// Algoritm for encrypting authorization responses.
    /// If authorization_encrypted_response_alg is specified, the default for this value is A128CBC-HS256.
    ///  When authorization_encrypted_response_enc is included, authorization_encrypted_response_alg MUST
    /// also be provided.
    /// [See JARM Spec](https://openid.net/specs/openid-financial-api-jarm.html#client-metadata)
    pub authorization_encrypted_response_enc: Option<String>,
    /// A boolean value specifying whether the client always uses DPoP for token requests. If omitted, the default value is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_bound_access_tokens: Option<bool>,
    /// Extra key values
    #[serde(flatten, skip_serializing_if = "HashMap::is_empty")]
    pub other_fields: HashMap<String, serde_json::Value>,
}
