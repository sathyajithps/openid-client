use std::collections::HashMap;

use serde::Deserialize;
use serde_json::Value;

/// # MtlsEndpoints
/// [OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://datatracker.ietf.org/doc/html/rfc8705)
#[derive(Deserialize, Debug, Clone, Default)]
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
#[derive(Debug, Deserialize, Default, Clone)]
pub struct IssuerMetadata {
    /// Issuer url. [RFC8414 - Obtaining Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414.html#section-3).
    pub issuer: String,
    /// Authorization Endpoint. [RFC6749 - Authorization Endpoint](https://www.rfc-editor.org/rfc/rfc6749#section-3.1).
    pub authorization_endpoint: Option<String>,
    ///  Device authorization endpoint
    pub device_authorization_endpoint: Option<String>,
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
    /// Alternative endpoints that can be used by a client with mTLS to access. See [MtlsEndpoints]
    pub mtls_endpoint_aliases: Option<MtlsEndpoints>,
    /// OP support of returning the OP id in auth response. [RFC](https://www.ietf.org/archive/id/draft-meyerzuselhausen-oauth-iss-auth-resp-02.html#name-providing-the-issuer-identi)
    pub authorization_response_iss_parameter_supported: Option<bool>,
    /// A JSON array containing a list of the JWS alg values supported by the authorization server for DPoP proof JWTs
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,
    /// The URL of the pushed authorization request endpoint at which client can post an authorization request to exchange for a "request_uri" value usable at the authorization server.  
    pub pushed_authorization_request_endpoint: Option<String>,
    /// Boolean parameter indicating whether the authorization server accepts authorization request data only via PAR.  If omitted, the default value is "false".
    #[serde(default)]
    pub require_pushed_authorization_requests: bool,
    /// Token delivery modes supported for CIBA
    pub backchannel_token_delivery_modes_supported: Option<Vec<String>>,
    /// CIBA authentication endpont
    pub backchannel_authentication_endpoint: Option<String>,
    /// CIBA authentication request signing algorithms supported.
    pub backchannel_authentication_request_signing_alg_values_supported: Option<Vec<String>>,
    /// Wether CIBA user_code is supported
    pub backchannel_user_code_parameter_supported: Option<bool>,
    /// Any extra data that was read from the discovery document
    #[serde(flatten)]
    pub other_fields: HashMap<String, Value>,
}
