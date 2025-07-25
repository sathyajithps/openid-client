use std::{collections::HashMap, time::Duration};

use serde_json::Value;

use crate::{
    helpers::{convert_json_to, now, validate_url},
    http::request_async,
    issuer::Issuer,
    jwks::Jwks,
    types::{
        http_client::HttpMethod, ClientMetadata, ClientOptions, ClientRegistrationOptions, Fapi,
        HttpRequest, OidcClientError, OidcHttpClient, OidcReturnType,
    },
};

use super::dpop_nonce_cache::DPoPNonceCache;

/// # Client instance
#[derive(Debug)]
pub struct Client {
    pub(crate) client_id: String,
    pub(crate) client_secret: Option<String>,
    pub(crate) registration_access_token: Option<String>,
    pub(crate) registration_client_uri: Option<String>,
    pub(crate) client_id_issued_at: Option<i64>,
    pub(crate) client_secret_expires_at: Option<i64>,
    pub(crate) token_endpoint_auth_method: Option<String>,
    pub(crate) token_endpoint_auth_signing_alg: Option<String>,
    pub(crate) introspection_endpoint_auth_method: Option<String>,
    pub(crate) introspection_endpoint_auth_signing_alg: Option<String>,
    pub(crate) revocation_endpoint_auth_method: Option<String>,
    pub(crate) revocation_endpoint_auth_signing_alg: Option<String>,
    pub(crate) redirect_uri: Option<String>,
    pub(crate) redirect_uris: Option<Vec<String>>,
    pub(crate) response_type: Option<String>,
    pub(crate) response_types: Vec<String>,
    pub(crate) grant_types: Vec<String>,
    pub(crate) jwks_uri: Option<String>,
    pub(crate) jwks: Option<Jwks>,
    pub(crate) sector_identifier_uri: Option<String>,
    pub(crate) subject_type: Option<String>,
    pub(crate) id_token_signed_response_alg: String,
    pub(crate) id_token_encrypted_response_alg: Option<String>,
    pub(crate) id_token_encrypted_response_enc: Option<String>,
    pub(crate) userinfo_signed_response_alg: Option<String>,
    pub(crate) userinfo_encrypted_response_alg: Option<String>,
    pub(crate) userinfo_encrypted_response_enc: Option<String>,
    pub(crate) request_object_signing_alg: Option<String>,
    pub(crate) request_object_encryption_alg: Option<String>,
    pub(crate) request_object_encryption_enc: Option<String>,
    pub(crate) default_max_age: Option<u64>,
    pub(crate) require_auth_time: Option<bool>,
    pub(crate) default_acr_values: Option<Vec<String>>,
    pub(crate) initiate_login_uri: Option<String>,
    pub(crate) request_uris: Option<String>,
    pub(crate) tls_client_certificate_bound_access_tokens: Option<bool>,
    pub(crate) post_logout_redirect_uris: Option<Vec<String>>,
    pub(crate) authorization_encrypted_response_alg: Option<String>,
    pub(crate) authorization_encrypted_response_enc: Option<String>,
    pub(crate) authorization_signed_response_alg: Option<String>,
    pub(crate) private_jwks: Option<Jwks>,
    pub(crate) issuer: Option<Issuer>,
    pub(crate) client_options: Option<ClientOptions>,
    pub(crate) skip_max_age_check: bool,
    pub(crate) skip_nonce_check: bool,
    pub(crate) clock_tolerance: Duration,
    pub(crate) fapi: Option<Fapi>,
    pub(crate) dpop_nonce_cache: DPoPNonceCache,
    pub(crate) dpop_bound_access_tokens: Option<bool>,
    pub(crate) backchannel_token_delivery_mode: Option<String>,
    pub(crate) backchannel_client_notification_endpoint: Option<String>,
    pub(crate) backchannel_authentication_request_signing_alg: Option<String>,
    pub(crate) backchannel_user_code_parameter: Option<bool>,
    pub(crate) other_fields: HashMap<String, Value>,
    pub(crate) now: fn() -> u64,
}

impl Client {
    pub(crate) fn default(fapi: Option<Fapi>) -> Self {
        let mut client = Self {
            client_id: String::new(),
            client_secret: None,
            registration_access_token: None,
            registration_client_uri: None,
            client_id_issued_at: None,
            client_secret_expires_at: None,
            token_endpoint_auth_method: Some("client_secret_basic".to_string()),
            token_endpoint_auth_signing_alg: None,
            introspection_endpoint_auth_method: None,
            introspection_endpoint_auth_signing_alg: None,
            revocation_endpoint_auth_method: None,
            revocation_endpoint_auth_signing_alg: None,
            redirect_uri: None,
            redirect_uris: None,
            response_type: None,
            response_types: vec!["code".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            jwks_uri: None,
            jwks: None,
            sector_identifier_uri: None,
            subject_type: None,
            id_token_signed_response_alg: "RS256".to_string(),
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: Some("A128CBC-HS256".to_string()),
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            request_object_signing_alg: None,
            request_object_encryption_alg: None,
            request_object_encryption_enc: None,
            default_max_age: None,
            require_auth_time: None,
            default_acr_values: None,
            initiate_login_uri: None,
            request_uris: None,
            private_jwks: None,
            issuer: None,
            tls_client_certificate_bound_access_tokens: None,
            post_logout_redirect_uris: None,
            authorization_encrypted_response_alg: None,
            authorization_encrypted_response_enc: None,
            authorization_signed_response_alg: None,
            other_fields: HashMap::new(),
            client_options: None,
            skip_max_age_check: false,
            skip_nonce_check: false,
            clock_tolerance: Duration::from_secs(0),
            fapi: None,
            dpop_nonce_cache: DPoPNonceCache::new(),
            dpop_bound_access_tokens: None,
            backchannel_token_delivery_mode: None,
            backchannel_client_notification_endpoint: None,
            backchannel_authentication_request_signing_alg: None,
            backchannel_user_code_parameter: None,
            now,
        };

        match fapi.as_ref() {
            Some(Fapi::V1) => {
                client.grant_types = vec!["authorization_code".to_string(), "implicit".to_string()];
                client.id_token_signed_response_alg = "PS256".to_string();
                client.authorization_signed_response_alg = Some("PS256".to_string());
                client.response_types = vec!["code".to_string(), "id_token".to_string()];
                client.tls_client_certificate_bound_access_tokens = Some(true);
                client.token_endpoint_auth_method = None;
            }
            Some(Fapi::V2) => {
                client.id_token_signed_response_alg = "PS256".to_string();
                client.authorization_signed_response_alg = Some("PS256".to_string());
                client.token_endpoint_auth_method = None;
            }
            None => {}
        };

        client.fapi = fapi;

        client
    }

    pub(crate) fn from_internal(
        metadata: ClientMetadata,
        issuer: Option<&Issuer>,
        jwks: Option<Jwks>,
        options: Option<ClientOptions>,
        fapi: Option<Fapi>,
    ) -> OidcReturnType<Self> {
        let mut valid_client_id = true;

        if let Some(client_id) = &metadata.client_id {
            if client_id.is_empty() {
                valid_client_id = false;
            }
        } else {
            valid_client_id = false;
        }

        if !valid_client_id {
            return Err(Box::new(OidcClientError::new_type_error(
                "client_id is required",
                None,
            )));
        }

        let mut client = Self {
            client_id: metadata.client_id.unwrap(),
            client_secret: metadata.client_secret,
            sector_identifier_uri: metadata.sector_identifier_uri,
            subject_type: metadata.subject_type,
            registration_access_token: metadata.registration_access_token,
            registration_client_uri: metadata.registration_client_uri,
            client_id_issued_at: metadata.client_id_issued_at,
            client_secret_expires_at: metadata.client_secret_expires_at,
            id_token_encrypted_response_alg: metadata.id_token_encrypted_response_alg,
            userinfo_signed_response_alg: metadata.userinfo_signed_response_alg,
            userinfo_encrypted_response_alg: metadata.userinfo_encrypted_response_alg,
            userinfo_encrypted_response_enc: metadata.userinfo_encrypted_response_enc,
            request_object_signing_alg: metadata.request_object_signing_alg,
            request_object_encryption_alg: metadata.request_object_encryption_alg,
            request_object_encryption_enc: metadata.request_object_encryption_enc,
            jwks_uri: metadata.jwks_uri,
            jwks: metadata.jwks,
            default_max_age: metadata.default_max_age,
            require_auth_time: metadata.require_auth_time,
            default_acr_values: metadata.default_acr_values,
            initiate_login_uri: metadata.initiate_login_uri,
            request_uris: metadata.request_uris,
            post_logout_redirect_uris: metadata.post_logout_redirect_uris,
            authorization_encrypted_response_alg: metadata.authorization_encrypted_response_alg,
            authorization_encrypted_response_enc: metadata.authorization_encrypted_response_enc,
            dpop_bound_access_tokens: metadata.dpop_bound_access_tokens,
            backchannel_authentication_request_signing_alg: metadata
                .backchannel_authentication_request_signing_alg,
            backchannel_client_notification_endpoint: metadata
                .backchannel_client_notification_endpoint,
            backchannel_token_delivery_mode: metadata.backchannel_token_delivery_mode,
            backchannel_user_code_parameter: metadata.backchannel_user_code_parameter,
            other_fields: metadata.other_fields,
            ..Client::default(fapi)
        };

        if metadata
            .tls_client_certificate_bound_access_tokens
            .is_some()
        {
            client.tls_client_certificate_bound_access_tokens =
                metadata.tls_client_certificate_bound_access_tokens;
        }

        if metadata.authorization_signed_response_alg.is_some() {
            client.authorization_signed_response_alg = metadata.authorization_signed_response_alg;
        }

        client.client_options = options;

        if client.jwks_uri.is_some() && client.jwks.is_some() {
            client.jwks = None;
        }

        if metadata.response_type.is_some() && metadata.response_types.is_some() {
            return Err(Box::new(OidcClientError::new_type_error(
                "provide a response_type or response_types, not both",
                None,
            )));
        }

        if let Some(response_type) = &metadata.response_type {
            client.response_type = Some(response_type.clone());
            client.response_types = vec![response_type.clone()];
        }

        if let Some(response_types) = &metadata.response_types {
            client.response_types = response_types.clone().to_vec();
        }

        if metadata.redirect_uri.is_some() && metadata.redirect_uris.is_some() {
            return Err(Box::new(OidcClientError::new_type_error(
                "provide a redirect_uri or redirect_uris, not both",
                None,
            )));
        }

        if let Some(redirect_uri) = &metadata.redirect_uri {
            client.redirect_uri = Some(redirect_uri.clone());
            client.redirect_uris = Some(vec![redirect_uri.clone()])
        }

        if let Some(redirect_uris) = &metadata.redirect_uris {
            client.redirect_uris = Some(redirect_uris.clone().to_vec());
        }

        if let Some(team) = metadata.token_endpoint_auth_method {
            client.token_endpoint_auth_method = Some(team);
        } else if let Some(iss) = issuer {
            if let Some(teams) = &iss.token_endpoint_auth_methods_supported {
                if let Some(team) = &client.token_endpoint_auth_method {
                    if !teams.contains(team) && teams.contains(&"client_secret_post".to_string()) {
                        client.token_endpoint_auth_method = Some("client_secret_post".to_string());
                    }
                }
            }
        }

        if metadata.token_endpoint_auth_signing_alg.is_some() {
            client.token_endpoint_auth_signing_alg = metadata.token_endpoint_auth_signing_alg;
        }

        client.introspection_endpoint_auth_method = metadata
            .introspection_endpoint_auth_method
            .or(client.token_endpoint_auth_method.clone());

        client.introspection_endpoint_auth_signing_alg = metadata
            .introspection_endpoint_auth_signing_alg
            .or(client.token_endpoint_auth_signing_alg.clone());

        client.revocation_endpoint_auth_method = metadata
            .revocation_endpoint_auth_method
            .or(client.token_endpoint_auth_method.clone());

        client.revocation_endpoint_auth_signing_alg = metadata
            .revocation_endpoint_auth_signing_alg
            .or(client.token_endpoint_auth_signing_alg.clone());

        if let Some(iss) = issuer {
            if iss.token_endpoint.is_some() {
                Self::assert_signing_alg_values_support(
                    &client.token_endpoint_auth_method.clone(),
                    &client.token_endpoint_auth_signing_alg,
                    &iss.token_endpoint_auth_signing_alg_values_supported,
                    "token",
                )?;
            }

            if iss.introspection_endpoint.is_some() {
                Self::assert_signing_alg_values_support(
                    &client.introspection_endpoint_auth_method,
                    &client.introspection_endpoint_auth_signing_alg,
                    &iss.token_endpoint_auth_signing_alg_values_supported,
                    "introspection",
                )?;
            }

            if iss.revocation_endpoint.is_some() {
                Self::assert_signing_alg_values_support(
                    &client.revocation_endpoint_auth_method,
                    &client.revocation_endpoint_auth_signing_alg,
                    &iss.token_endpoint_auth_signing_alg_values_supported,
                    "revocation",
                )?;
            }

            client.issuer = Some(iss.clone());
        }

        if metadata.id_token_encrypted_response_enc.is_some() {
            client.id_token_encrypted_response_enc = metadata.id_token_encrypted_response_enc;
        }

        if jwks.is_some() {
            client.private_jwks = jwks;
        }

        if let Some(alg) = metadata.id_token_signed_response_alg {
            client.id_token_signed_response_alg = alg;
        }

        if client.is_fapi1() {
            match client.token_endpoint_auth_method.as_deref() {
                Some("private_key_jwt") => {
                    if client.private_jwks.is_none() {
                        return Err(Box::new(OidcClientError::new_type_error(
                            "jwks is required",
                            None,
                        )));
                    }
                }
                Some("self_signed_tls_client_auth") | Some("tls_client_auth") => {}
                Some(_) => {
                    return Err(Box::new(OidcClientError::new_type_error(
                        "invalid or unsupported token_endpoint_auth_method",
                        None,
                    )));
                }
                None => {
                    return Err(Box::new(OidcClientError::new_type_error(
                        "token_endpoint_auth_method is required",
                        None,
                    )));
                }
            };
        }

        if client.is_fapi2() {
            match (
                client.tls_client_certificate_bound_access_tokens.as_ref(),
                client.dpop_bound_access_tokens.as_ref(),
            ) {
                (Some(&false), Some(&false))
                | (Some(&false), None)
                | (None, Some(&false))
                | (None, None) => return Err(Box::new(OidcClientError::new_type_error(
                    "one of tls_client_certificate_bound_access_tokens or dpop_bound_access_tokens must be true",
                    None,
                ))),

                (Some(&true), Some(&true)) => return Err(Box::new(OidcClientError::new_type_error(
                    "only one of tls_client_certificate_bound_access_tokens or dpop_bound_access_tokens must be true",
                    None,
                ))),

                (_, _) => {}
            };
        }

        Ok(client)
    }

    fn assert_signing_alg_values_support(
        auth_method: &Option<String>,
        supported_alg: &Option<String>,
        issuer_supported_alg_values: &Option<Vec<String>>,
        endpoint: &str,
    ) -> OidcReturnType<()> {
        if let Some(am) = auth_method {
            if am.ends_with("_jwt")
                && supported_alg.is_none()
                && issuer_supported_alg_values.is_none()
            {
                return Err(Box::new(OidcClientError::new_type_error(
                    &format!("{endpoint}_endpoint_auth_signing_alg_values_supported must be configured on the issuer if {endpoint}_endpoint_auth_signing_alg is not defined on a client"),
                    None,
                )));
            }
        }
        Ok(())
    }

    /// Gets the extra fields in client
    pub fn get_other_fields(&self) -> &HashMap<String, Value> {
        &self.other_fields
    }
}

/// Implementation for Client Read Methods
impl Client {
    /// # Creates a client from the [Client Read Endpoint](https://openid.net/specs/openid-connect-registration-1_0.html#ReadRequest)
    ///
    /// Creates a [Client] from the Client read endpoint.
    ///
    /// - `http_client` - The http client to make the request
    /// - `registration_client_uri` - The client read endpoint
    /// - `issuer` - [Issuer]
    /// - `registration_access_token` - The access token to be sent with the request
    /// - `jwks` - Private [Jwks] of the client
    /// - `client_options` - The [ClientOptions]
    /// - `fapi` - [Fapi] version.
    pub async fn from_uri_async<T>(
        http_client: &T,
        registration_client_uri: &str,
        issuer: &Issuer,
        registration_access_token: Option<String>,
        jwks: Option<Jwks>,
        client_options: Option<ClientOptions>,
        fapi: Option<Fapi>,
    ) -> OidcReturnType<Self>
    where
        T: OidcHttpClient,
    {
        Self::jwks_only_private_keys_validation(jwks.as_ref())?;

        let url = validate_url(registration_client_uri)?;

        let mut headers = HashMap::new();
        headers.insert("accept".to_string(), vec!["application/json".to_string()]);

        if let Some(rat) = registration_access_token {
            headers.insert("authorization".to_string(), vec![format!("Bearer {rat}")]);
        }

        let req = HttpRequest::new()
            .url(url)
            .method(HttpMethod::GET)
            .expect_body(true)
            .expect_status_code(200)
            .expect_bearer(true)
            .headers(headers);

        let res = request_async(req, http_client).await?;

        let client_metadata = convert_json_to::<ClientMetadata>(res.body.as_ref().unwrap())
            .map_err(|_| {
                OidcClientError::new_op_error(
                    "invalid client metadata".to_string(),
                    Some("error while deserializing".to_string()),
                    None,
                    Some(res),
                )
            })?;

        Self::from_internal(client_metadata, Some(issuer), jwks, client_options, fapi)
    }
}

/// Implementations for Dynamic Client Registration
impl Client {
    /// # Dynamic Client Registration
    ///
    /// Attempts a Dynamic Client Registration using the Issuer's `registration_endpoint`
    ///
    /// - `http_client` - The http client to make the request
    /// - `issuer` - The [Issuer] client should be registered to.
    /// - `client_metadata` - The [ClientMetadata] to be sent using the registration request.
    /// - `register_options` - [ClientRegistrationOptions]
    /// - `fapi` - [Fapi] version.
    pub async fn register_async<T>(
        http_client: &T,
        issuer: &Issuer,
        mut client_metadata: ClientMetadata,
        register_options: Option<ClientRegistrationOptions>,
        fapi: Option<Fapi>,
    ) -> OidcReturnType<Self>
    where
        T: OidcHttpClient,
    {
        if issuer.registration_endpoint.is_none() {
            return Err(Box::new(OidcClientError::new_type_error(
                "registration_endpoint must be configured on the issuer",
                None,
            )));
        }

        let mut initial_access_token: Option<String> = None;
        let mut jwks: Option<Jwks> = None;
        let mut client_options: Option<ClientOptions> = None;

        if let Some(options) = &register_options {
            initial_access_token.clone_from(&options.initial_access_token);
            jwks.clone_from(&options.jwks);
            client_options = Some(options.client_options.clone());

            if options.jwks.is_some()
                && client_metadata.jwks_uri.is_none()
                && client_metadata.jwks.is_none()
            {
                if let Some(jwks) = options.jwks.as_ref() {
                    client_metadata.jwks = Some(jwks.get_public_jwks());
                }
            }
        }

        Self::jwks_only_private_keys_validation(jwks.as_ref())?;

        let url = validate_url(issuer.registration_endpoint.as_ref().unwrap())?;

        let body = serde_json::to_string(&client_metadata).map_err(|_| {
            OidcClientError::new_error("client metadata is an invalid json format", None)
        })?;

        let mut headers = HashMap::new();
        headers.insert("accept".to_string(), vec!["application/json".to_string()]);

        if let Some(iat) = initial_access_token {
            headers.insert("authorization".to_string(), vec![format!("Bearer {iat}")]);
        }

        let req = HttpRequest::new()
            .url(url)
            .method(HttpMethod::POST)
            .expect_body(true)
            .expect_status_code(201)
            .expect_bearer(true)
            .headers(headers)
            .json(body);

        let response = request_async(req, http_client).await?;

        let client_metadata = convert_json_to::<ClientMetadata>(response.body.as_ref().unwrap())
            .map_err(|_| {
                OidcClientError::new_op_error(
                    "invalid client metadata".to_string(),
                    None,
                    None,
                    Some(response),
                )
            })?;

        Self::from_internal(client_metadata, Some(issuer), jwks, client_options, fapi)
    }

    /// # Get Client Metadata
    /// Gets the [ClientMetadata] of this [Client] instance
    pub fn metadata(&self) -> ClientMetadata {
        ClientMetadata {
            client_id: Some(self.client_id.clone()),
            client_secret: self.client_secret.clone(),
            registration_access_token: self.registration_access_token.clone(),
            registration_client_uri: self.registration_client_uri.clone(),
            client_id_issued_at: self.client_id_issued_at,
            client_secret_expires_at: self.client_secret_expires_at,
            token_endpoint_auth_method: self.token_endpoint_auth_method.clone(),
            token_endpoint_auth_signing_alg: self.token_endpoint_auth_signing_alg.clone(),
            introspection_endpoint_auth_method: self.introspection_endpoint_auth_method.clone(),
            introspection_endpoint_auth_signing_alg: self
                .introspection_endpoint_auth_signing_alg
                .clone(),
            revocation_endpoint_auth_method: self.revocation_endpoint_auth_method.clone(),
            revocation_endpoint_auth_signing_alg: self.revocation_endpoint_auth_signing_alg.clone(),
            redirect_uri: self.redirect_uri.clone(),
            redirect_uris: self.redirect_uris.clone(),
            response_type: self.response_type.clone(),
            response_types: Some(self.response_types.clone()),
            grant_types: Some(self.grant_types.clone()),
            jwks_uri: self.jwks_uri.clone(),
            jwks: self.jwks.clone(),
            sector_identifier_uri: self.sector_identifier_uri.clone(),
            subject_type: self.subject_type.clone(),
            id_token_signed_response_alg: Some(self.id_token_signed_response_alg.clone()),
            id_token_encrypted_response_alg: self.id_token_encrypted_response_alg.clone(),
            id_token_encrypted_response_enc: self.id_token_encrypted_response_enc.clone(),
            userinfo_signed_response_alg: self.userinfo_signed_response_alg.clone(),
            userinfo_encrypted_response_alg: self.userinfo_encrypted_response_alg.clone(),
            userinfo_encrypted_response_enc: self.userinfo_encrypted_response_enc.clone(),
            request_object_signing_alg: self.request_object_signing_alg.clone(),
            request_object_encryption_alg: self.request_object_encryption_alg.clone(),
            request_object_encryption_enc: self.request_object_encryption_enc.clone(),
            default_max_age: self.default_max_age,
            require_auth_time: self.require_auth_time,
            default_acr_values: self.default_acr_values.clone(),
            initiate_login_uri: self.initiate_login_uri.clone(),
            request_uris: self.request_uris.clone(),
            tls_client_certificate_bound_access_tokens: self
                .tls_client_certificate_bound_access_tokens,
            post_logout_redirect_uris: self.post_logout_redirect_uris.clone(),
            authorization_signed_response_alg: self.authorization_signed_response_alg.clone(),
            authorization_encrypted_response_alg: self.authorization_encrypted_response_alg.clone(),
            authorization_encrypted_response_enc: self.authorization_encrypted_response_enc.clone(),
            dpop_bound_access_tokens: self.dpop_bound_access_tokens,
            backchannel_token_delivery_mode: self.backchannel_token_delivery_mode.clone(),
            backchannel_client_notification_endpoint: self
                .backchannel_client_notification_endpoint
                .clone(),
            backchannel_authentication_request_signing_alg: self
                .backchannel_authentication_request_signing_alg
                .clone(),
            backchannel_user_code_parameter: self.backchannel_user_code_parameter,
            other_fields: self.other_fields.clone(),
        }
    }

    /// Returs error if JWKS only has private keys
    pub(crate) fn jwks_only_private_keys_validation(jwks: Option<&Jwks>) -> OidcReturnType<()> {
        if let Some(jwks) = jwks {
            if !jwks.is_only_private_keys() || jwks.has_oct_keys() {
                return Err(Box::new(OidcClientError::new_error(
                    "jwks must only contain private keys",
                    None,
                )));
            }
        }
        Ok(())
    }
}

impl Clone for Client {
    fn clone(&self) -> Self {
        Self {
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            registration_access_token: self.registration_access_token.clone(),
            registration_client_uri: self.registration_client_uri.clone(),
            client_id_issued_at: self.client_id_issued_at,
            client_secret_expires_at: self.client_secret_expires_at,
            token_endpoint_auth_method: self.token_endpoint_auth_method.clone(),
            token_endpoint_auth_signing_alg: self.token_endpoint_auth_signing_alg.clone(),
            introspection_endpoint_auth_method: self.introspection_endpoint_auth_method.clone(),
            introspection_endpoint_auth_signing_alg: self
                .introspection_endpoint_auth_signing_alg
                .clone(),
            revocation_endpoint_auth_method: self.revocation_endpoint_auth_method.clone(),
            revocation_endpoint_auth_signing_alg: self.revocation_endpoint_auth_signing_alg.clone(),
            redirect_uri: self.redirect_uri.clone(),
            redirect_uris: self.redirect_uris.clone(),
            response_type: self.response_type.clone(),
            response_types: self.response_types.clone(),
            grant_types: self.grant_types.clone(),
            jwks_uri: self.jwks_uri.clone(),
            jwks: self.jwks.clone(),
            sector_identifier_uri: self.sector_identifier_uri.clone(),
            subject_type: self.subject_type.clone(),
            id_token_signed_response_alg: self.id_token_signed_response_alg.clone(),
            id_token_encrypted_response_alg: self.id_token_encrypted_response_alg.clone(),
            id_token_encrypted_response_enc: self.id_token_encrypted_response_enc.clone(),
            userinfo_signed_response_alg: self.userinfo_signed_response_alg.clone(),
            userinfo_encrypted_response_alg: self.userinfo_encrypted_response_alg.clone(),
            userinfo_encrypted_response_enc: self.userinfo_encrypted_response_enc.clone(),
            request_object_signing_alg: self.request_object_signing_alg.clone(),
            request_object_encryption_alg: self.request_object_encryption_alg.clone(),
            request_object_encryption_enc: self.request_object_encryption_enc.clone(),
            default_max_age: self.default_max_age,
            require_auth_time: self.require_auth_time,
            default_acr_values: self.default_acr_values.clone(),
            initiate_login_uri: self.initiate_login_uri.clone(),
            request_uris: self.request_uris.clone(),
            tls_client_certificate_bound_access_tokens: self
                .tls_client_certificate_bound_access_tokens,
            post_logout_redirect_uris: self.post_logout_redirect_uris.clone(),
            authorization_encrypted_response_alg: self.authorization_encrypted_response_alg.clone(),
            authorization_encrypted_response_enc: self.authorization_encrypted_response_enc.clone(),
            authorization_signed_response_alg: self.authorization_signed_response_alg.clone(),
            other_fields: self.other_fields.clone(),
            private_jwks: self.private_jwks.clone(),
            issuer: self.issuer.clone(),
            client_options: self.client_options.clone(),
            skip_max_age_check: self.skip_max_age_check,
            skip_nonce_check: self.skip_nonce_check,
            clock_tolerance: self.clock_tolerance,
            fapi: self.fapi.clone(),
            dpop_nonce_cache: self.dpop_nonce_cache.clone(),
            dpop_bound_access_tokens: self.dpop_bound_access_tokens,
            backchannel_token_delivery_mode: self.backchannel_token_delivery_mode.clone(),
            backchannel_client_notification_endpoint: self
                .backchannel_client_notification_endpoint
                .clone(),
            backchannel_authentication_request_signing_alg: self
                .backchannel_authentication_request_signing_alg
                .clone(),
            backchannel_user_code_parameter: self.backchannel_user_code_parameter,
            now: self.now,
        }
    }
}

#[cfg(test)]
#[path = "../tests/client/mod.rs"]
mod client_test;
