use crate::{
    issuer::Issuer,
    jwks::Jwks,
    types::{ClientOptions, RequestInterceptor},
};

use super::Client;

/// Getter & Setter method implementations for Client
impl Client {
    /// Get client id
    pub fn get_client_id(&self) -> String {
        self.client_id.clone()
    }

    /// Get client secret
    pub fn get_client_secret(&self) -> Option<String> {
        self.client_secret.clone()
    }

    /// Get grant types
    pub fn get_grant_types(&self) -> Vec<String> {
        self.grant_types.to_vec()
    }

    /// Get registration access token
    pub fn get_registration_access_token(&self) -> Option<String> {
        self.registration_access_token.clone()
    }

    /// Get registration client uri
    pub fn get_registration_client_uri(&self) -> Option<String> {
        self.registration_client_uri.clone()
    }

    /// Get client id issued at. Epoch(seconds)
    pub fn get_client_id_issued_at(&self) -> Option<i64> {
        self.client_id_issued_at
    }

    /// Get client secret exprires at. Epoch(seconds)
    pub fn get_client_secret_expires_at(&self) -> Option<i64> {
        self.client_secret_expires_at
    }

    /// Get id token signed response algorithm
    pub fn get_id_token_signed_response_alg(&self) -> String {
        self.id_token_signed_response_alg.clone()
    }

    /// Get response types. See [crate::types::ClientMetadata].
    pub fn get_response_types(&self) -> Vec<String> {
        self.response_types.to_vec()
    }

    /// Get token endpoint authentication method. See [crate::types::ClientMetadata].
    pub fn get_token_endpoint_auth_method(&self) -> String {
        self.token_endpoint_auth_method.clone()
    }

    /// Get token endpoint authentication signing alg. See [crate::types::ClientMetadata].
    pub fn get_token_endpoint_auth_signing_alg(&self) -> Option<String> {
        self.token_endpoint_auth_signing_alg.clone()
    }

    /// Get introspection endpoint authentication method. See [crate::types::ClientMetadata].
    pub fn get_introspection_endpoint_auth_method(&self) -> Option<String> {
        self.introspection_endpoint_auth_method.clone()
    }

    /// Get introspection endpoint authentication signing alg. See [crate::types::ClientMetadata].
    pub fn get_introspection_endpoint_auth_signing_alg(&self) -> Option<String> {
        self.introspection_endpoint_auth_signing_alg.clone()
    }

    /// Get revocation endpoint authentication method. See [crate::types::ClientMetadata].
    pub fn get_revocation_endpoint_auth_method(&self) -> Option<String> {
        self.revocation_endpoint_auth_method.clone()
    }

    /// Get revocation endpoint authentication signing alg. See [crate::types::ClientMetadata].
    pub fn get_revocation_endpoint_auth_signing_alg(&self) -> Option<String> {
        self.revocation_endpoint_auth_signing_alg.clone()
    }

    /// Get authorization encrypted response alg
    pub fn get_authorization_encrypted_response_alg(&self) -> Option<String> {
        self.authorization_encrypted_response_alg.clone()
    }

    /// Get authorization encrypted respnse enc
    pub fn get_authorization_encrypted_response_enc(&self) -> Option<String> {
        self.authorization_encrypted_response_enc.clone()
    }

    /// Get authorization signed response alg
    pub fn get_authorization_signed_response_alg(&self) -> Option<String> {
        self.authorization_signed_response_alg.clone()
    }

    /// Gets a field from `other_fields`
    pub fn get_field(&self, key: &str) -> Option<&serde_json::Value> {
        self.other_fields.get(key)
    }

    /// Get redirect uri. See [crate::types::ClientMetadata].
    pub fn get_redirect_uri(&self) -> Option<String> {
        self.redirect_uri.clone()
    }

    /// Get redirect uris. See [crate::types::ClientMetadata].
    pub fn get_redirect_uris(&self) -> Option<Vec<String>> {
        Some(self.redirect_uris.clone()?.to_vec())
    }

    /// Get response type
    pub fn get_response_type(&self) -> Option<String> {
        self.response_type.clone()
    }

    /// Get application type
    pub fn get_application_type(&self) -> Option<String> {
        self.application_type.clone()
    }

    /// Get contacts
    pub fn get_contacts(&self) -> Option<Vec<String>> {
        Some(self.contacts.clone()?.to_vec())
    }

    /// Get client name
    pub fn get_client_name(&self) -> Option<String> {
        self.client_name.clone()
    }

    /// Get logo uri
    pub fn get_logo_uri(&self) -> Option<String> {
        self.logo_uri.clone()
    }

    /// Get client uri
    pub fn get_client_uri(&self) -> Option<String> {
        self.client_uri.clone()
    }

    /// Get policy uri
    pub fn get_policy_uri(&self) -> Option<String> {
        self.policy_uri.clone()
    }

    /// Get tos uri
    pub fn get_tos_uri(&self) -> Option<String> {
        self.tos_uri.clone()
    }

    /// Get jwks uri
    pub fn get_jwks_uri(&self) -> Option<String> {
        self.jwks_uri.clone()
    }

    /// Get sector identifier uri
    pub fn get_sector_identifier_uri(&self) -> Option<String> {
        self.sector_identifier_uri.clone()
    }

    /// Get subject type
    pub fn get_subject_type(&self) -> Option<String> {
        self.subject_type.clone()
    }

    /// Get id token encrypted response algorithm
    pub fn get_id_token_encrypted_response_alg(&self) -> Option<String> {
        self.id_token_encrypted_response_alg.clone()
    }

    /// Get id token encrypted response algorithm
    pub fn get_id_token_encrypted_response_enc(&self) -> Option<String> {
        self.id_token_encrypted_response_enc.clone()
    }

    /// Get userinfo signed response algorithm
    pub fn get_userinfo_signed_response_alg(&self) -> Option<String> {
        self.userinfo_signed_response_alg.clone()
    }

    /// Get userinfo encrypted response algorithm
    pub fn get_userinfo_encrypted_response_alg(&self) -> Option<String> {
        self.userinfo_encrypted_response_alg.clone()
    }

    /// Get userinfo encrypted response algorithm
    pub fn get_userinfo_encrypted_response_enc(&self) -> Option<String> {
        self.userinfo_encrypted_response_enc.clone()
    }

    /// Get request object signing algorithm
    pub fn get_request_object_signing_alg(&self) -> Option<String> {
        self.request_object_signing_alg.clone()
    }

    /// Get request object encryption algorithm
    pub fn get_request_object_encryption_alg(&self) -> Option<String> {
        self.request_object_encryption_alg.clone()
    }

    /// Get request object encryption algorithm
    pub fn get_request_object_encryption_enc(&self) -> Option<String> {
        self.request_object_encryption_enc.clone()
    }

    /// Get default max age
    pub fn get_default_max_age(&self) -> Option<i64> {
        self.default_max_age
    }

    /// Get require auth time
    pub fn get_require_auth_time(&self) -> Option<bool> {
        self.require_auth_time
    }

    /// Get default acr values
    pub fn get_default_acr_values(&self) -> Option<Vec<String>> {
        Some(self.default_acr_values.clone()?.to_vec())
    }

    /// Get initiate login uri
    pub fn get_initiate_login_uri(&self) -> Option<String> {
        self.initiate_login_uri.clone()
    }

    /// Get request uris
    pub fn get_request_uris(&self) -> Option<String> {
        self.request_uris.clone()
    }

    /// Get jwks
    pub fn get_jwks(&self) -> Option<Jwks> {
        self.jwks.clone()
    }

    /// Gets the issuer that the client was created with.
    pub fn get_issuer(&self) -> Option<&Issuer> {
        self.issuer.as_ref()
    }

    /// Gets the private jwks
    pub fn get_private_jwks(&self) -> Option<Jwks> {
        self.private_jwks.clone()
    }

    /// Gets the client options the client was created with
    pub fn get_client_options(&self) -> Option<ClientOptions> {
        self.client_options.clone()
    }

    /// Sets a new [RequestInterceptor] on the client
    pub fn set_request_interceptor(&mut self, interceptor: RequestInterceptor) {
        self.request_interceptor = Some(interceptor);
    }
}
