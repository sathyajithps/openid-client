use std::collections::HashMap;

use serde::Deserialize;

/// #MtlsEndpoints
/// Alternative endpoints that can be used by a client with mTLS to access
/// 1. `token_endpoint`
/// 2. `userinfo_endpoint`
/// 3. `revocation_endpoint`
/// 4. `introspection_endpoint`
/// 5. `device_authorization_endpoint`
/// All the endpoints are optional
#[derive(Deserialize, Debug)]
pub struct MtlsEndpoints {
    /// mTLS token endpoint
    pub token_endpoint: Option<String>,
    /// mTLS userinfo endpoint
    pub userinfo_endpoint: Option<String>,
    /// mTLS revocation endpoint
    pub revocation_endpoint: Option<String>,
    /// mTLS introspection endpoint
    pub introspection_endpoint: Option<String>,
    /// mTLS device authorization endpoint
    pub device_authorization_endpoint: Option<String>,
}

/// # IssuerMetadata
/// Metadata about the OIDC Authorization Server. [OIDC Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse).
#[derive(Debug, Deserialize)]
pub struct IssuerMetadata {
    /// Issuer url. [RFC8414 - Obtaining Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414.html#section-3).
    pub issuer: String,
    /// Authorization Endpoint. [RFC6749 - Authorization Endpoint](https://www.rfc-editor.org/rfc/rfc6749#section-3.1).
    pub authorization_endpoint: Option<String>,
    /// Endpoint to obtain the access/refresh/id tokens. [RFC6749 - Token Endpoint](https://www.rfc-editor.org/rfc/rfc6749#section-3.2).
    pub token_endpoint: Option<String>,
    /// URL of the authorization server's JWK Set. [See](https://www.rfc-editor.org/rfc/rfc8414.html#section-2)
    pub jwks_uri: Option<String>,
    /// OpenID Connect [Userinfo Endpoint](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo).
    pub userinfo_endpoint: Option<String>,
    /// Endpoint for revoking refresh tokes and access tokens. [Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414.html#section-2).
    pub revocation_endpoint: Option<String>,
    /// Endpoint to initiate an end session request.
    pub end_session_endpoint: Option<String>,
    /// Dynamic client registration endpoint
    pub registration_endpoint: Option<String>,
    /// [Token introspection endpoint](https://www.rfc-editor.org/rfc/rfc7662)
    pub introspection_endpoint: Option<String>,
    /// List of client [authentication methods](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#token-endpoint-auth-method) supported by the Authorization Server.
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// List of JWS signing algorithms supported by the token endpoint for the signature of the JWT
    /// that the client uses to authenticate.
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    /// List of client [authentication methods](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#token-endpoint-auth-method) supported by the Authorization Server.
    pub introspection_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// List of JWS signing algorithms supported by the introspection endpoint for the signature of
    /// the JWT that the client uses to authenticate.
    pub introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    /// List of client [authentication methods](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#token-endpoint-auth-method) supported by the Authorization Server.
    pub revocation_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// List of JWS signing algorithms supported by the revocation endpoint for the signature of the
    /// JWT that the client uses to authenticate.
    pub revocation_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    /// List of JWS signing algorithms supported by the Authorization Server for signing [Request Object](https://openid.net/specs/openid-connect-core-1_0.html#RequestObject).
    pub request_object_signing_alg_values_supported: Option<Vec<String>>,
    /// Alternative endpoints that can be used by a client with mTLS to access. See [MtlsEndpoints]
    pub mtls_endpoint_aliases: Option<MtlsEndpoints>,
    /// Any extra data that was read from the discovery document
    #[serde(flatten)]
    pub other_fields: HashMap<String, serde_json::Value>,
}

impl Default for IssuerMetadata {
    /// This default value serves only one purpose, just so that you dont have to assign every value
    /// as none if you just to get started with a couple of values.
    fn default() -> Self {
        Self {
            issuer: "".to_string(),
            authorization_endpoint: None,
            token_endpoint: None,
            jwks_uri: None,
            userinfo_endpoint: None,
            revocation_endpoint: None,
            end_session_endpoint: None,
            registration_endpoint: None,
            introspection_endpoint: None,
            token_endpoint_auth_methods_supported: None,
            token_endpoint_auth_signing_alg_values_supported: None,
            introspection_endpoint_auth_methods_supported: None,
            introspection_endpoint_auth_signing_alg_values_supported: None,
            revocation_endpoint_auth_methods_supported: None,
            revocation_endpoint_auth_signing_alg_values_supported: None,
            request_object_signing_alg_values_supported: None,
            mtls_endpoint_aliases: None,
            other_fields: Default::default(),
        }
    }
}
