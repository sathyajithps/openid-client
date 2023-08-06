use std::collections::HashMap;

use crate::{
    helpers::{convert_json_to, validate_url},
    http::request_async,
    issuer::Issuer,
    jwks::Jwks,
    types::{
        ClientMetadata, ClientOptions, ClientRegistrationOptions, OidcClientError, Request,
        RequestInterceptor,
    },
};
use reqwest::{
    header::{HeaderMap, HeaderValue},
    StatusCode,
};

/// # Client instance
#[derive(Debug)]
pub struct Client {
    /// Client Id
    pub(crate) client_id: String,
    /// Client secret
    pub(crate) client_secret: Option<String>,
    /// [Registration Access Token](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) registration_access_token: Option<String>,
    /// [Registration Client Uri](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) registration_client_uri: Option<String>,
    /// [Client Id Issued At](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) client_id_issued_at: Option<i64>,
    /// [Secret Expiry](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    /// Epoch Seconds
    pub(crate) client_secret_expires_at: Option<i64>,
    /// [Authentication method](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    /// used by the client for authenticating with the OP
    pub(crate) token_endpoint_auth_method: String,
    /// [Algorithm](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    /// used for signing the JWT used to authenticate
    /// the client at the token endpoint.
    pub(crate) token_endpoint_auth_signing_alg: Option<String>,
    /// [Authentication method](https://www.rfc-editor.org/rfc/rfc8414.html#section-2)
    /// used by the client for introspection endpoint
    pub(crate) introspection_endpoint_auth_method: Option<String>,
    /// [Algorithm](https://www.rfc-editor.org/rfc/rfc8414.html#section-2)
    /// used for signing the JWT used to authenticate
    /// the client at the introspection endpoint.
    pub(crate) introspection_endpoint_auth_signing_alg: Option<String>,
    /// [Authentication method](https://www.rfc-editor.org/rfc/rfc8414.html#section-2)
    /// used by the client for revocation endpoint
    pub(crate) revocation_endpoint_auth_method: Option<String>,
    /// [Algorithm](https://www.rfc-editor.org/rfc/rfc8414.html#section-2)
    /// used for signing the JWT used to authenticate
    /// the client at the revocation endpoint.
    pub(crate) revocation_endpoint_auth_signing_alg: Option<String>,
    /// The [redirect uri](https://openid.net/specs/openid-connect-http-redirect-1_0-01.html#rf_prep)
    /// where response will be sent
    pub(crate) redirect_uri: Option<String>,
    /// A list of acceptable [redirect uris](https://openid.net/specs/openid-connect-http-redirect-1_0-01.html#rf_prep)
    pub(crate) redirect_uris: Option<Vec<String>>,
    /// [Response type](https://openid.net/specs/openid-connect-http-redirect-1_0-01.html#rf_prep) supported by the client.
    pub(crate) response_type: Option<String>,
    /// List of [Response type](https://openid.net/specs/openid-connect-http-redirect-1_0-01.html#rf_prep) supported by the client
    pub(crate) response_types: Vec<String>,
    /// [Grant Types](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) grant_types: Vec<String>,
    /// [Application Type](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) application_type: Option<String>,
    /// [Contacts](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) contacts: Option<Vec<String>>,
    /// [Client Name](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) client_name: Option<String>,
    /// [Logo Uri](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) logo_uri: Option<String>,
    /// [Client Uri](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) client_uri: Option<String>,
    /// [Policy Uri](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) policy_uri: Option<String>,
    /// [Tos Uri](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) tos_uri: Option<String>,
    /// [Jwks Uri](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) jwks_uri: Option<String>,
    /// [JWKS](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) jwks: Option<Jwks>,
    /// [Sector Identifier Uri](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) sector_identifier_uri: Option<String>,
    /// [Subject Type](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) subject_type: Option<String>,
    /// [Id Token Signed Response Algorithm](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) id_token_signed_response_alg: String,
    /// [Id Token Encrypted Response Algorithm](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) id_token_encrypted_response_alg: Option<String>,
    /// [Id Token Encrypted Response Algorithm](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) id_token_encrypted_response_enc: Option<String>,
    /// [Userinfo Signed Response Algorithm](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) userinfo_signed_response_alg: Option<String>,
    /// [Userinfo Encrypted Response Algorithm](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) userinfo_encrypted_response_alg: Option<String>,
    /// [Userinfo Encrypted Response Algorithm](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) userinfo_encrypted_response_enc: Option<String>,
    /// [Request Object Signing Algorithm](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) request_object_signing_alg: Option<String>,
    /// [Request Object Encryption Algorithm](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) request_object_encryption_alg: Option<String>,
    /// [Request Object Encryption Algorithm](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) request_object_encryption_enc: Option<String>,
    /// [Default Max Age](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) default_max_age: Option<i64>,
    /// [Require Auth Time](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) require_auth_time: Option<bool>,
    /// [Default Acr Values](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) default_acr_values: Option<Vec<String>>,
    /// [Initiate Login Uri](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) initiate_login_uri: Option<String>,
    /// [Request Uris](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    pub(crate) request_uris: Option<String>,
    /// [Client's intention to use mutual-TLS client certificate-bound access tokens](https://datatracker.ietf.org/doc/html/rfc8705#name-client-registration-metadata-2)
    pub tls_client_certificate_bound_access_tokens: Option<bool>,
    /// Client's allowed redirect uris after a logout
    pub post_logout_redirect_uris: Option<Vec<String>>,
    /// Extra key values
    pub(crate) other_fields: HashMap<String, serde_json::Value>,
    pub(crate) private_jwks: Option<Jwks>,
    pub(crate) request_interceptor: Option<RequestInterceptor>,
    pub(crate) issuer: Option<Issuer>,
    pub(crate) client_options: Option<ClientOptions>,
}

impl Client {
    pub(crate) fn default() -> Self {
        Self {
            client_id: String::new(),
            client_secret: None,
            registration_access_token: None,
            registration_client_uri: None,
            client_id_issued_at: None,
            client_secret_expires_at: None,
            token_endpoint_auth_method: "client_secret_basic".to_string(),
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
            application_type: None,
            contacts: None,
            client_name: None,
            logo_uri: None,
            client_uri: None,
            policy_uri: None,
            tos_uri: None,
            jwks_uri: None,
            jwks: None,
            sector_identifier_uri: None,
            subject_type: None,
            id_token_signed_response_alg: "RS256".to_string(),
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: None,
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
            request_interceptor: None,
            issuer: None,
            tls_client_certificate_bound_access_tokens: None,
            post_logout_redirect_uris: None,
            other_fields: HashMap::new(),
            client_options: None,
        }
    }

    /// # Internal documentation
    /// This method is used to create an instance of [Client] by:
    ///     - [`Issuer::client()`]
    ///     - [`Client::from_uri_async()`],
    ///     - [`Client::from_uri()`]
    ///     - [`Client::register()`]
    ///     - [`Client::register_async()`]
    pub(crate) fn from_internal(
        metadata: ClientMetadata,
        issuer: Option<&Issuer>,
        interceptor: Option<RequestInterceptor>,
        jwks: Option<Jwks>,
        options: Option<ClientOptions>,
    ) -> Result<Self, OidcClientError> {
        let mut valid_client_id = true;

        if let Some(client_id) = &metadata.client_id {
            if client_id.is_empty() {
                valid_client_id = false;
            }
        } else {
            valid_client_id = false;
        }

        if !valid_client_id {
            return Err(OidcClientError::new_type_error(
                "client_id is required",
                None,
            ));
        }

        let mut client = Self {
            client_id: metadata.client_id.unwrap(),
            client_secret: metadata.client_secret,
            logo_uri: metadata.logo_uri,
            tos_uri: metadata.tos_uri,
            client_uri: metadata.client_uri,
            policy_uri: metadata.policy_uri,
            sector_identifier_uri: metadata.sector_identifier_uri,
            subject_type: metadata.subject_type,
            registration_access_token: metadata.registration_access_token,
            registration_client_uri: metadata.registration_client_uri,
            client_id_issued_at: metadata.client_id_issued_at,
            client_secret_expires_at: metadata.client_secret_expires_at,
            id_token_encrypted_response_alg: metadata.id_token_encrypted_response_alg,
            id_token_encrypted_response_enc: metadata.id_token_encrypted_response_enc,
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
            tls_client_certificate_bound_access_tokens: metadata
                .tls_client_certificate_bound_access_tokens,
            post_logout_redirect_uris: metadata.post_logout_redirect_uris,
            other_fields: metadata.other_fields,
            ..Client::default()
        };

        client.client_options = options;

        if client.jwks_uri.is_some() && client.jwks.is_some() {
            client.jwks = None;
        }

        if metadata.response_type.is_some() && metadata.response_types.is_some() {
            return Err(OidcClientError::new_type_error(
                "provide a response_type or response_types, not both",
                None,
            ));
        }

        if let Some(response_type) = &metadata.response_type {
            client.response_type = Some(response_type.clone());
            client.response_types = vec![response_type.clone()];
        }

        if let Some(response_types) = &metadata.response_types {
            client.response_types = response_types.clone().to_vec();
        }

        if metadata.redirect_uri.is_some() && metadata.redirect_uris.is_some() {
            return Err(OidcClientError::new_type_error(
                "provide a redirect_uri or redirect_uris, not both",
                None,
            ));
        }

        if let Some(redirect_uri) = &metadata.redirect_uri {
            client.redirect_uri = Some(redirect_uri.clone());
            client.redirect_uris = Some(vec![redirect_uri.clone()])
        }

        if let Some(redirect_uris) = &metadata.redirect_uris {
            client.redirect_uris = Some(redirect_uris.clone().to_vec());
        }

        if let Some(team) = metadata.token_endpoint_auth_method {
            client.token_endpoint_auth_method = team;
        } else if let Some(iss) = issuer {
            if let Some(teams) = &iss.token_endpoint_auth_methods_supported {
                if !teams.contains(&client.get_token_endpoint_auth_method())
                    && teams.contains(&"client_secret_post".to_string())
                {
                    client.token_endpoint_auth_method = "client_secret_post".to_string();
                }
            }
        }

        if metadata.token_endpoint_auth_signing_alg.is_some() {
            client.token_endpoint_auth_signing_alg = metadata.token_endpoint_auth_signing_alg;
        }

        client.introspection_endpoint_auth_method = metadata
            .introspection_endpoint_auth_method
            .or(Some(client.get_token_endpoint_auth_method()));

        client.introspection_endpoint_auth_signing_alg = metadata
            .introspection_endpoint_auth_signing_alg
            .or(client.get_token_endpoint_auth_signing_alg());

        client.revocation_endpoint_auth_method = metadata
            .revocation_endpoint_auth_method
            .or(Some(client.get_token_endpoint_auth_method()));

        client.revocation_endpoint_auth_signing_alg = metadata
            .revocation_endpoint_auth_signing_alg
            .or(client.get_token_endpoint_auth_signing_alg());

        if let Some(iss) = issuer {
            Self::assert_signing_alg_values_support(
                &Some(client.token_endpoint_auth_method.clone()),
                &client.token_endpoint_auth_signing_alg,
                &iss.token_endpoint_auth_signing_alg_values_supported,
                "token",
            )?;

            Self::assert_signing_alg_values_support(
                &client.introspection_endpoint_auth_method,
                &client.introspection_endpoint_auth_signing_alg,
                &iss.token_endpoint_auth_signing_alg_values_supported,
                "introspection",
            )?;

            Self::assert_signing_alg_values_support(
                &client.revocation_endpoint_auth_method,
                &client.revocation_endpoint_auth_signing_alg,
                &iss.token_endpoint_auth_signing_alg_values_supported,
                "revocation",
            )?;

            client.issuer = Some(iss.clone());
        }

        if let Some(i) = interceptor {
            client.set_request_interceptor(i);
        }

        if jwks.is_some() {
            client.private_jwks = jwks;
        }

        if let Some(alg) = metadata.id_token_signed_response_alg {
            client.id_token_signed_response_alg = alg;
        }

        Ok(client)
    }

    fn assert_signing_alg_values_support(
        auth_method: &Option<String>,
        supported_alg: &Option<String>,
        issuer_supported_alg_values: &Option<Vec<String>>,
        endpoint: &str,
    ) -> Result<(), OidcClientError> {
        if let Some(am) = auth_method {
            if am.ends_with("_jwt")
                && supported_alg.is_none()
                && issuer_supported_alg_values.is_none()
            {
                return Err(OidcClientError::new_type_error(
                &format!("{0}_endpoint_auth_signing_alg_values_supported must be configured on the issuer if {0}_endpoint_auth_signing_alg is not defined on a client", endpoint),
                None
            ));
            }
        }
        Ok(())
    }
}

/// Implementation for Client Read Methods
impl Client {
    /// # Creates a client from the [Client Read Endpoint](https://openid.net/specs/openid-connect-registration-1_0.html#ReadRequest)
    ///
    /// Creates a [Client] from the Client read endpoint.
    ///
    /// - `registration_client_uri` - The client read endpoint
    /// - `registration_access_token` - The access token to be sent with the request
    /// - `jwks` - Private [Jwks] of the client
    /// - `client_options` - The [ClientOptions]
    /// - `issuer` - [Issuer]
    /// - `interceptor` - [RequestInterceptor]
    ///
    /// ### *Example:*
    ///
    /// ```rust
    ///     let _client = Client::from_uri_async(
    ///         "https://auth.example.com/client/id",
    ///         None,
    ///         None,
    ///         None,
    ///         None,
    ///         None,
    ///     )
    ///     .await
    ///     .unwrap();
    /// ```
    ///
    /// ### *Example: with all params*
    ///
    /// ```rust
    ///     let jwk = Jwk::generate_rsa_key(2048).unwrap();
    ///
    ///     let jwks = Jwks::from(vec![jwk]);
    ///
    ///     let client_options = ClientOptions {
    ///         additional_authorized_parties: Some(vec!["authParty".to_string()]),
    ///     };
    ///
    ///    #[derive(Debug, Clone)]
    ///    pub(crate) struct CustomInterceptor {
    ///        pub some_header: String,
    ///        pub some_header_value: String,
    ///    }
    ///
    ///    impl Interceptor for CustomInterceptor {
    ///        fn intercept(&mut self, _req: &Request) -> RequestOptions {
    ///            let mut headers: HeaderMap = HeaderMap::new();
    ///
    ///            let header = HeaderName::from_bytes(self.some_header.as_bytes()).unwrap();
    ///            let header_value = HeaderValue::from_bytes(self.some_header_value.as_bytes()).unwrap();
    ///
    ///            headers.append(header, header_value);
    ///
    ///            RequestOptions {
    ///                headers,
    ///                timeout: Duration::from_millis(5000),
    ///                ..Default::default()
    ///            }
    ///        }
    ///
    ///        fn clone_box(&self) -> Box<dyn Interceptor> {
    ///            Box::new(CustomInterceptor {
    ///                some_header: self.some_header.clone(),
    ///                some_header_value: self.some_header_value.clone(),
    ///            })
    ///        }
    ///    }
    ///
    ///    let interceptor = CustomInterceptor {
    ///        some_header: "foo".to_string(),
    ///        some_header_value: "bar".to_string(),
    ///    };
    ///
    ///     let issuer = Issuer::discover_async("https://auth.example.com", Some(Box::new(interceptor)))
    ///         .await
    ///         .unwrap();
    ///
    ///     let _client = Client::from_uri_async(
    ///         "https://auth.example.com/client/id",
    ///         Some("token".to_string()),
    ///         Some(jwks),
    ///         Some(client_options),
    ///         Some(&issuer),
    ///         Some(Box::new(interceptor)),
    ///     )
    ///     .await
    ///     .unwrap();
    ///```
    pub async fn from_uri_async(
        registration_client_uri: &str,
        registration_access_token: Option<String>,
        jwks: Option<Jwks>,
        client_options: Option<ClientOptions>,
        issuer: Option<&Issuer>,
        mut interceptor: Option<RequestInterceptor>,
    ) -> Result<Self, OidcClientError> {
        Self::jwks_only_private_keys_validation(jwks.as_ref())?;

        let url = validate_url(registration_client_uri)?;

        let mut headers = HeaderMap::new();
        headers.insert("Accept", HeaderValue::from_static("application/json"));

        if let Some(rat) = registration_access_token {
            let header_value = match HeaderValue::from_str(&format!("Bearer {}", rat)) {
                Ok(v) => v,
                Err(_) => {
                    return Err(OidcClientError::new_type_error(
                        &format!("registration_access_token {} is invalid", rat),
                        None,
                    ))
                }
            };
            headers.insert("Authorization", header_value);
        }

        let req = Request {
            url: url.to_string(),
            method: reqwest::Method::GET,
            expect_body: true,
            expected: StatusCode::OK,
            bearer: true,
            headers,
            ..Request::default()
        };

        let res = request_async(req, &mut interceptor).await?;

        let client_metadata = convert_json_to::<ClientMetadata>(res.body.as_ref().unwrap())
            .map_err(|_| {
                OidcClientError::new_op_error(
                    "invalid client metadata".to_string(),
                    Some("error while deserializing".to_string()),
                    None,
                    None,
                    None,
                    Some(res),
                )
            })?;

        Self::from_internal(client_metadata, issuer, interceptor, jwks, client_options)
    }
}

/// Implementations for Dynamic Client Registration
impl Client {
    /// # Dynamic Client Registration
    ///
    /// Attempts a Dynamic Client Registration using the Issuer's `registration_endpoint`
    ///
    /// - `issuer` - The [Issuer] client should be registered to.
    /// - `client_metadata` - The [ClientMetadata] to be sent using the registration request.
    /// - `register_options` - [ClientRegistrationOptions]
    /// - `interceptor` - [RequestInterceptor]
    ///
    /// ### *Example:*
    ///
    /// ```rust
    ///     let issuer = Issuer::discover_async("https://auth.example.com", None)
    ///         .await
    ///         .unwrap();
    ///
    ///     let metadata = ClientMetadata {
    ///         client_id: Some("identifier".to_string()),
    ///         ..ClientMetadata::default()
    ///     };
    ///
    ///     let _client = Client::register_async(&issuer, metadata, None, None)
    ///         .await
    ///         .unwrap();
    /// ```
    ///
    /// ### *Example: with all params*
    ///
    /// ```rust
    ///
    ///    #[derive(Debug, Clone)]
    ///    pub(crate) struct CustomInterceptor {
    ///        pub some_header: String,
    ///        pub some_header_value: String,
    ///    }
    ///
    ///    impl Interceptor for CustomInterceptor {
    ///        fn intercept(&mut self, _req: &Request) -> RequestOptions {
    ///            let mut headers: HeaderMap = HeaderMap::new();
    ///
    ///            let header = HeaderName::from_bytes(self.some_header.as_bytes()).unwrap();
    ///            let header_value = HeaderValue::from_bytes(self.some_header_value.as_bytes()).unwrap();
    ///
    ///            headers.append(header, header_value);
    ///
    ///            RequestOptions {
    ///                headers,
    ///                timeout: Duration::from_millis(5000),
    ///                ..Default::default()
    ///            }
    ///        }
    ///
    ///        fn clone_box(&self) -> Box<dyn Interceptor> {
    ///            Box::new(CustomInterceptor {
    ///                some_header: self.some_header.clone(),
    ///                some_header_value: self.some_header_value.clone(),
    ///            })
    ///        }
    ///    }
    ///
    ///    let interceptor1 = CustomInterceptor {
    ///        some_header: "foo".to_string(),
    ///        some_header_value: "bar".to_string(),
    ///    };
    ///
    ///     let interceptor2 = CustomInterceptor {
    ///         some_header: "foo".to_string(),
    ///         some_header_value: "bar".to_string(),
    ///     };
    ///
    ///     let issuer = Issuer::discover_async("https://auth.example.com", Some(Box::new(interceptor1)))
    ///         .await
    ///         .unwrap();
    ///
    ///     let metadata = ClientMetadata {
    ///         client_id: Some("identifier".to_string()),
    ///         ..ClientMetadata::default()
    ///     };
    ///
    ///     let jwk = Jwk::generate_rsa_key(2048).unwrap();
    ///
    ///     let registration_options = ClientRegistrationOptions {
    ///         initial_access_token: Some("initial_access_token".to_string()),
    ///         jwks: Some(Jwks::from(vec![jwk])),
    ///         client_options: Default::default(),
    ///     };
    ///
    ///     let _client = Client::register_async(
    ///         &issuer,
    ///         metadata,
    ///         Some(registration_options),
    ///         Some(Box::new(interceptor2)),
    ///     )
    ///     .await
    ///     .unwrap();
    /// ```
    ///
    pub async fn register_async(
        issuer: &Issuer,
        mut client_metadata: ClientMetadata,
        register_options: Option<ClientRegistrationOptions>,
        mut interceptor: Option<RequestInterceptor>,
    ) -> Result<Self, OidcClientError> {
        if issuer.registration_endpoint.is_none() {
            return Err(OidcClientError::new_type_error(
                "registration_endpoint must be configured on the issuer",
                None,
            ));
        }

        let mut initial_access_token: Option<String> = None;
        let mut jwks: Option<Jwks> = None;
        let mut client_options: Option<ClientOptions> = None;

        if let Some(options) = &register_options {
            initial_access_token = options.initial_access_token.clone();
            jwks = options.jwks.clone();
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

        let body = serde_json::to_value(client_metadata).map_err(|_| {
            OidcClientError::new_error("client metadata is an invalid json format", None)
        })?;

        let mut headers = HeaderMap::new();
        headers.insert("Accept", HeaderValue::from_static("application/json"));

        if let Some(iat) = initial_access_token {
            let header_value = match HeaderValue::from_str(&format!("Bearer {}", iat)) {
                Ok(v) => v,
                Err(_) => {
                    return Err(OidcClientError::new_error(
                        "access token is invalid. wtf?",
                        None,
                    ))
                }
            };
            headers.insert("Authorization", header_value);
        }

        let req = Request {
            url: url.to_string(),
            method: reqwest::Method::POST,
            expect_body: true,
            expected: StatusCode::CREATED,
            bearer: true,
            headers,
            json: Some(body),
            response_type: Some("json".to_string()),
            ..Request::default()
        };

        let response = request_async(req, &mut interceptor).await?;

        let client_metadata = convert_json_to::<ClientMetadata>(response.body.as_ref().unwrap())
            .map_err(|_| {
                OidcClientError::new_op_error(
                    "invalid client metadata".to_string(),
                    None,
                    None,
                    None,
                    None,
                    Some(response),
                )
            })?;

        Self::from_internal(
            client_metadata,
            Some(issuer),
            interceptor,
            jwks,
            client_options,
        )
    }

    /// Returs error if JWKS only has private keys
    pub(crate) fn jwks_only_private_keys_validation(
        jwks: Option<&Jwks>,
    ) -> Result<(), OidcClientError> {
        if let Some(jwks) = jwks {
            if !jwks.is_only_private_keys() || jwks.has_oct_keys() {
                return Err(OidcClientError::new_error(
                    "jwks must only contain private keys",
                    None,
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/client/mod.rs"]
mod client_test;
