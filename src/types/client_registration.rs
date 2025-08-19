use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// # Client Registration Request
///
/// Request body for dynamic client registration (RFC 7591).
/// This struct contains the client metadata to be submitted during registration.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ClientRegistrationRequest {
    /// Array of redirection URI strings for use in redirect-based flows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uris: Option<Vec<String>>,

    /// Array of OAuth 2.0 response_type values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_types: Option<Vec<String>>,

    /// Array of OAuth 2.0 grant_type values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types: Option<Vec<String>>,

    /// Kind of the application (web, native).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_type: Option<String>,

    /// Array of e-mail addresses of people responsible for this client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contacts: Option<Vec<String>>,

    /// Human-readable name of the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,

    /// URL of a web page providing information about the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,

    /// URL of the home page of the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,

    /// URL that the client provides to inform the user about how profile data will be used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,

    /// URL that the client provides to inform the user about the terms of service.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tos_uri: Option<String>,

    /// URL referencing the client's JSON Web Key Set document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,

    /// Client's JSON Web Key Set document value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<Value>,

    /// URL using the https scheme to be used in calculating Pseudonymous Identifiers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sector_identifier_uri: Option<String>,

    /// Subject type requested for responses to this client (pairwise, public).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_type: Option<String>,

    /// Requested authentication method for the token endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,

    /// JWS algorithm that must be used for signing the JWT for token endpoint authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg: Option<String>,

    /// Default Maximum Authentication Age.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_max_age: Option<u64>,

    /// Boolean value specifying whether the auth_time Claim is required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_auth_time: Option<bool>,

    /// Default requested Authentication Context Class Reference values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_acr_values: Option<Vec<String>>,

    /// URI using the https scheme that the RP will use to initiate login.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiate_login_uri: Option<String>,

    /// Array of request_uri values that are pre-registered by the RP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_uris: Option<Vec<String>>,

    /// JWS algorithm for signing the ID Token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_signed_response_alg: Option<String>,

    /// JWE algorithm for encrypting the ID Token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_alg: Option<String>,

    /// JWE enc algorithm for encrypting the ID Token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_enc: Option<String>,

    /// JWS algorithm for signing UserInfo responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_signed_response_alg: Option<String>,

    /// JWE algorithm for encrypting UserInfo responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encrypted_response_alg: Option<String>,

    /// JWE enc algorithm for encrypting UserInfo responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encrypted_response_enc: Option<String>,

    /// JWS algorithm for signing Request Objects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg: Option<String>,

    /// JWE algorithm for encrypting Request Objects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_alg: Option<String>,

    /// JWE enc algorithm for encrypting Request Objects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_enc: Option<String>,

    /// JWS algorithm for signing authorization responses (JARM).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_signed_response_alg: Option<String>,

    /// JWE algorithm for encrypting authorization responses (JARM).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_encrypted_response_alg: Option<String>,

    /// JWE enc algorithm for encrypting authorization responses (JARM).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_encrypted_response_enc: Option<String>,

    /// Boolean indicating client's use of mTLS certificate-bound access tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_client_certificate_bound_access_tokens: Option<bool>,

    /// Boolean indicating client always uses DPoP for token requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_bound_access_tokens: Option<bool>,

    /// Array of URLs to which the RP is requesting that the OP redirect after logout.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_logout_redirect_uris: Option<Vec<String>>,

    /// CIBA token delivery mode (poll, ping, push).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_token_delivery_mode: Option<String>,

    /// Client notification endpoint for CIBA.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_client_notification_endpoint: Option<String>,

    /// JWS algorithm for signing CIBA authentication requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_authentication_request_signing_alg: Option<String>,

    /// Boolean indicating support for user_code parameter in CIBA.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_user_code_parameter: Option<bool>,

    /// Additional fields not explicitly defined.
    #[serde(flatten, skip_serializing_if = "HashMap::is_empty")]
    pub additional_fields: HashMap<String, Value>,
}

/// # Client Registration Response
///
/// Response from dynamic client registration containing the issued credentials.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ClientRegistrationResponse {
    /// Unique Client Identifier (REQUIRED).
    pub client_id: String,

    /// Client Secret (OPTIONAL - not issued for public clients).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,

    /// Registration Access Token for subsequent operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_access_token: Option<String>,

    /// Location of the Client Configuration Endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_client_uri: Option<String>,

    /// Time at which the Client Identifier was issued (Unix timestamp).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id_issued_at: Option<u64>,

    /// Time at which the client_secret will expire (Unix timestamp), or 0 if never.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<u64>,

    /// Token endpoint authentication method.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,

    /// All other fields from the registration response.
    #[serde(flatten)]
    pub metadata: HashMap<String, Value>,
}

impl ClientRegistrationRequest {
    /// Create a new empty registration request.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set redirect URIs.
    pub fn redirect_uris(mut self, uris: Vec<String>) -> Self {
        self.redirect_uris = Some(uris);
        self
    }

    /// Add a redirect URI.
    pub fn add_redirect_uri(mut self, uri: impl Into<String>) -> Self {
        self.redirect_uris
            .get_or_insert_with(Vec::new)
            .push(uri.into());
        self
    }

    /// Set response types.
    pub fn response_types(mut self, types: Vec<String>) -> Self {
        self.response_types = Some(types);
        self
    }

    /// Set grant types.
    pub fn grant_types(mut self, types: Vec<String>) -> Self {
        self.grant_types = Some(types);
        self
    }

    /// Set client name.
    pub fn client_name(mut self, name: impl Into<String>) -> Self {
        self.client_name = Some(name.into());
        self
    }

    /// Set token endpoint auth method.
    pub fn token_endpoint_auth_method(mut self, method: impl Into<String>) -> Self {
        self.token_endpoint_auth_method = Some(method.into());
        self
    }

    /// Set application type.
    pub fn application_type(mut self, app_type: impl Into<String>) -> Self {
        self.application_type = Some(app_type.into());
        self
    }

    /// Set contacts.
    pub fn contacts(mut self, contacts: Vec<String>) -> Self {
        self.contacts = Some(contacts);
        self
    }

    /// Set JWKS URI.
    pub fn jwks_uri(mut self, uri: impl Into<String>) -> Self {
        self.jwks_uri = Some(uri.into());
        self
    }

    /// Set JWKS directly.
    pub fn jwks(mut self, jwks: Value) -> Self {
        self.jwks = Some(jwks);
        self
    }

    /// Set post-logout redirect URIs.
    pub fn post_logout_redirect_uris(mut self, uris: Vec<String>) -> Self {
        self.post_logout_redirect_uris = Some(uris);
        self
    }

    /// Enable TLS client certificate-bound access tokens.
    pub fn tls_client_certificate_bound_access_tokens(mut self, enabled: bool) -> Self {
        self.tls_client_certificate_bound_access_tokens = Some(enabled);
        self
    }

    /// Enable DPoP-bound access tokens.
    pub fn dpop_bound_access_tokens(mut self, enabled: bool) -> Self {
        self.dpop_bound_access_tokens = Some(enabled);
        self
    }

    /// Add an additional field.
    pub fn additional_field(mut self, key: impl Into<String>, value: Value) -> Self {
        self.additional_fields.insert(key.into(), value);
        self
    }
}
