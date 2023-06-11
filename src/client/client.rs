use std::collections::HashMap;

use reqwest::{
    header::{HeaderMap, HeaderValue},
    StatusCode,
};

use crate::{
    helpers::{convert_json_to, validate_url},
    http::{default_request_interceptor, request, request_async},
    types::{ClientMetadata, ClientOptions, Jwks},
    Issuer, OidcClientError, Request, RequestInterceptor, Response,
};

/// # Client instance
pub struct Client {
    client_id: String,
    client_secret: Option<String>,
    grant_types: Vec<String>,
    id_token_signed_response_alg: String,
    response_types: Vec<String>,
    token_endpoint_auth_method: String,
    token_endpoint_auth_signing_alg: Option<String>,
    introspection_endpoint_auth_method: Option<String>,
    introspection_endpoint_auth_signing_alg: Option<String>,
    revocation_endpoint_auth_method: Option<String>,
    revocation_endpoint_auth_signing_alg: Option<String>,
    redirect_uri: Option<String>,
    redirect_uris: Option<Vec<String>>,
    response_type: Option<String>,
    request_interceptor: RequestInterceptor,
    jwks: Option<Jwks>,
    other_fields: HashMap<String, serde_json::Value>,
    issuer: Option<Issuer>,
}

impl Client {
    pub(crate) fn default() -> Self {
        Self {
            client_id: String::new(),
            client_secret: None,
            grant_types: vec!["authorization_code".to_string()],
            id_token_signed_response_alg: "RS256".to_string(),
            response_types: vec!["code".to_string()],
            token_endpoint_auth_method: "client_secret_basic".to_string(),
            token_endpoint_auth_signing_alg: None,
            introspection_endpoint_auth_method: None,
            introspection_endpoint_auth_signing_alg: None,
            revocation_endpoint_auth_method: None,
            revocation_endpoint_auth_signing_alg: None,
            redirect_uri: None,
            redirect_uris: None,
            response_type: None,
            request_interceptor: Box::new(default_request_interceptor),
            jwks: None,
            other_fields: HashMap::new(),
            issuer: None,
        }
    }

    /// # Internal documentation
    /// This method is used by [`Isseur::client()`] and [`Client::new_with_interceptor()`]
    /// to create an instance of [Client].
    ///
    /// The `issuer` will be cloned using [`Issuer::clone_with_default_interceptor()`] method
    pub(crate) fn from_internal(
        metadata: ClientMetadata,
        issuer: Option<&Issuer>,
        interceptor: RequestInterceptor,
        _registration_client_uri: Option<String>,
        _registration_access_token: Option<String>,
        jwks: Option<Jwks>,
        _options: Option<ClientOptions>,
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
            return Err(OidcClientError::new(
                "MetadataError",
                "client_id is required",
                "client_id is required",
                None,
            ));
        }

        let mut client = Self {
            client_id: metadata.client_id.unwrap(),
            client_secret: metadata.client_secret,
            other_fields: metadata.other_fields,
            ..Client::default()
        };

        if metadata.response_type.is_some() && metadata.response_types.is_some() {
            return Err(OidcClientError::new(
                "TypeError",
                "invalid configuration",
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
            return Err(OidcClientError::new(
                "TypeError",
                "invalid configuration",
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
            assert_signing_alg_values_support(
                &Some(client.token_endpoint_auth_method.clone()),
                &client.token_endpoint_auth_signing_alg,
                &iss.token_endpoint_auth_methods_supported,
                "token",
            )?;

            assert_signing_alg_values_support(
                &client.introspection_endpoint_auth_method,
                &client.introspection_endpoint_auth_signing_alg,
                &iss.introspection_endpoint_auth_methods_supported,
                "introspection",
            )?;

            assert_signing_alg_values_support(
                &client.revocation_endpoint_auth_method,
                &client.revocation_endpoint_auth_signing_alg,
                &iss.revocation_endpoint_auth_methods_supported,
                "revocation",
            )?;

            client.issuer = Some(iss.clone_with_default_interceptor());
        }

        client.set_request_interceptor(interceptor);

        if let Some(jwks) = jwks {
            client.jwks = Some(jwks);
        }

        Ok(client)
    }
}

impl Client {
    /// # Creates a client from the [Client Read Endpoint](https://openid.net/specs/openid-connect-registration-1_0.html#ReadRequest)
    /// > `This is a blocking method.` Checkout [`Client::from_uri_async()`] for async version.
    ///
    /// Creates a [Client] from the Client read endpoint.
    ///
    /// The Jwks is completely ignored if the jwks_uri is present from the response.
    ///
    /// ```
    /// # use openid_client::Client;
    ///
    /// fn main() {
    ///     let client =
    ///         Client::from_uri("https://auth.example.com/client/id", None, None, None, None);
    /// }
    /// ```
    ///
    /// TODO: Document snippets using rest of the arguments
    pub fn from_uri(
        registration_client_uri: &str,
        registration_access_token: Option<String>,
        jwks: Option<Jwks>,
        client_options: Option<ClientOptions>,
        issuer: Option<&Issuer>,
    ) -> Result<Self, OidcClientError> {
        Self::from_uri_with_interceptor(
            registration_client_uri,
            Box::new(default_request_interceptor),
            registration_access_token,
            jwks,
            client_options,
            issuer,
        )
    }

    /// # Creates a client with request interceptor from the [Client Read Endpoint](https://openid.net/specs/openid-connect-registration-1_0.html#ReadRequest)
    /// > `This is a blocking method.` Checkout [`Client::from_uri_with_interceptor_async()`] for async version.
    ///
    /// ```
    /// # use openid_client::Client;
    ///
    /// fn main() {
    ///     let client =
    ///         Client::from_uri_with_interceptor("https://auth.example.com/client/id", None, None, None, None);
    /// }
    /// ```
    ///
    /// TODO: Document snippets using rest of the arguments
    pub fn from_uri_with_interceptor(
        registration_client_uri: &str,
        interceptor: RequestInterceptor,
        registration_access_token: Option<String>,
        jwks: Option<Jwks>,
        client_options: Option<ClientOptions>,
        issuer: Option<&Issuer>,
    ) -> Result<Self, OidcClientError> {
        Self::from_uri_internal(
            registration_client_uri,
            registration_access_token,
            jwks,
            client_options,
            interceptor,
            issuer,
        )
    }

    /// # Creates a client from the [Client Read Endpoint](https://openid.net/specs/openid-connect-registration-1_0.html#ReadRequest)
    /// > `This is an async method.` Checkout [`Client::from_uri()`] for the blocking version.
    ///
    /// Creates a [Client] from the Client read endpoint.
    ///
    /// The Jwks is completely ignored if the jwks_uri is present from the response.
    ///
    /// ```
    /// # use openid_client::Client;
    ///
    /// fn main() {
    ///     let client =
    ///         Client::from_uri_async("https://auth.example.com/client/id", None, None, None, None);
    /// }
    /// ```
    ///
    /// TODO: Document snippets using rest of the arguments
    pub async fn from_uri_async(
        registration_client_uri: &str,
        registration_access_token: Option<String>,
        jwks: Option<Jwks>,
        client_options: Option<ClientOptions>,
        issuer: Option<&Issuer>,
    ) -> Result<Self, OidcClientError> {
        Self::from_uri_with_interceptor_async(
            registration_client_uri,
            Box::new(default_request_interceptor),
            registration_access_token,
            jwks,
            client_options,
            issuer,
        )
        .await
    }

    /// # Creates a client with request interceptor from the [Client Read Endpoint](https://openid.net/specs/openid-connect-registration-1_0.html#ReadRequest)
    /// > `This is an async method.` Checkout [`Client::from_uri_with_interceptor()`] for the blocking version.
    ///
    /// ```
    /// # use openid_client::Client;
    ///
    /// fn main() {
    ///     let client =
    ///         Client::from_uri_with_interceptor_async("https://auth.example.com/client/id", None, None, None, None);
    /// }
    /// ```
    ///
    /// TODO: Document snippets using rest of the arguments
    pub async fn from_uri_with_interceptor_async(
        registration_client_uri: &str,
        interceptor: RequestInterceptor,
        registration_access_token: Option<String>,
        jwks: Option<Jwks>,
        client_options: Option<ClientOptions>,
        issuer: Option<&Issuer>,
    ) -> Result<Self, OidcClientError> {
        Self::from_uri_internal_async(
            registration_client_uri,
            registration_access_token,
            jwks,
            client_options,
            interceptor,
            issuer,
        )
        .await
    }

    /// Internal method that requests and process the response for all the `from_uri_methods`
    fn from_uri_internal(
        registration_client_uri: &str,
        registration_access_token: Option<String>,
        jwks: Option<Jwks>,
        client_options: Option<ClientOptions>,
        mut interceptor: RequestInterceptor,
        issuer: Option<&Issuer>,
    ) -> Result<Self, OidcClientError> {
        let req = Self::build_from_uri_request(
            registration_client_uri,
            registration_access_token.as_ref(),
        )?;

        let res = request(req, &mut interceptor)?;

        Self::process_from_uri_response(
            res,
            issuer,
            interceptor,
            registration_client_uri,
            registration_access_token,
            jwks,
            client_options,
        )
    }

    /// Internal method that requests and process the response for all the `from_uri_methods` async version.
    async fn from_uri_internal_async(
        registration_client_uri: &str,
        registration_access_token: Option<String>,
        jwks: Option<Jwks>,
        client_options: Option<ClientOptions>,
        mut interceptor: RequestInterceptor,
        issuer: Option<&Issuer>,
    ) -> Result<Self, OidcClientError> {
        let req = Self::build_from_uri_request(
            registration_client_uri,
            registration_access_token.as_ref(),
        )?;

        let res = request_async(req, &mut interceptor).await?;

        Self::process_from_uri_response(
            res,
            issuer,
            interceptor,
            registration_client_uri,
            registration_access_token,
            jwks,
            client_options,
        )
    }

    /// Request builder for the `from_uri_internal` methods
    fn build_from_uri_request(
        registration_client_uri: &str,
        registration_access_token: Option<&String>,
    ) -> Result<Request, OidcClientError> {
        let url = validate_url(registration_client_uri)?;

        let mut headers = HeaderMap::new();
        headers.insert("Accept", HeaderValue::from_static("application/json"));

        if let Some(rat) = registration_access_token {
            let header_value = match HeaderValue::from_str(&format!("Bearer {}", rat)) {
                Ok(v) => v,
                Err(_) => {
                    return Err(OidcClientError::new(
                        "TypeError",
                        "invalid access_token",
                        &format!("registration_access_token {} is invalid", rat),
                        None,
                    ))
                }
            };
            headers.insert("Authorization", header_value);
        }

        Ok(Request {
            url: url.to_string(),
            method: reqwest::Method::GET,
            expect_body: true,
            expected: StatusCode::OK,
            bearer: true,
            headers,
            ..Request::default()
        })
    }

    /// Response processor for the `from_uri_internal` methods
    fn process_from_uri_response(
        response: Response,
        issuer: Option<&Issuer>,
        interceptor: RequestInterceptor,
        registration_client_uri: &str,
        registration_access_token: Option<String>,
        jwks: Option<Jwks>,
        client_options: Option<ClientOptions>,
    ) -> Result<Self, OidcClientError> {
        let client_metadata = convert_json_to::<ClientMetadata>(response.body.as_ref().unwrap())
            .map_err(|_| {
                OidcClientError::new(
                    "OPError",
                    "invalid_client_metadata",
                    "invalid client metadata",
                    Some(response),
                )
            })?;

        Self::from_internal(
            client_metadata,
            issuer,
            interceptor,
            Some(registration_client_uri.to_string()),
            registration_access_token,
            jwks,
            client_options,
        )
    }
}

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

    /// Get id token signed response algorithm
    pub fn get_id_token_signed_response_alg(&self) -> String {
        self.id_token_signed_response_alg.clone()
    }

    /// Get response types. See [ClientMetadata].
    pub fn get_response_types(&self) -> Vec<String> {
        self.response_types.to_vec()
    }

    /// Get token endpoint authentication method. See [ClientMetadata].
    pub fn get_token_endpoint_auth_method(&self) -> String {
        self.token_endpoint_auth_method.clone()
    }

    /// Get token endpoint authentication signing alg. See [ClientMetadata].
    pub fn get_token_endpoint_auth_signing_alg(&self) -> Option<String> {
        self.token_endpoint_auth_signing_alg.clone()
    }

    /// Get introspection endpoint authentication method. See [ClientMetadata].
    pub fn get_introspection_endpoint_auth_method(&self) -> Option<String> {
        self.introspection_endpoint_auth_method.clone()
    }

    /// Get introspection endpoint authentication signing alg. See [ClientMetadata].
    pub fn get_introspection_endpoint_auth_signing_alg(&self) -> Option<String> {
        self.introspection_endpoint_auth_signing_alg.clone()
    }

    /// Get revocation endpoint authentication method. See [ClientMetadata].
    pub fn get_revocation_endpoint_auth_method(&self) -> Option<String> {
        self.revocation_endpoint_auth_method.clone()
    }

    /// Get revocation endpoint authentication signing alg. See [ClientMetadata].
    pub fn get_revocation_endpoint_auth_signing_alg(&self) -> Option<String> {
        self.revocation_endpoint_auth_signing_alg.clone()
    }

    /// Gets a field from `other_fields`
    pub fn get_field(&self, key: &str) -> Option<&serde_json::Value> {
        self.other_fields.get(key)
    }

    /// Get redirect uri. See [ClientMetadata].
    pub fn get_redirect_uri(&self) -> Option<String> {
        self.redirect_uri.clone()
    }

    /// Get redirect uris. See [ClientMetadata].
    pub fn get_redirect_uris(&self) -> Option<Vec<String>> {
        Some(self.redirect_uris.clone()?.to_vec())
    }

    /// Get response type
    pub fn get_response_type(&self) -> Option<String> {
        self.response_type.clone()
    }

    /// Gets the issuer that the client was created with.
    pub fn get_issuer(&self) -> Option<&Issuer> {
        self.issuer.as_ref()
    }

    pub(crate) fn set_request_interceptor(&mut self, interceptor: RequestInterceptor) {
        self.request_interceptor = interceptor;
    }
}

fn assert_signing_alg_values_support(
    auth_method: &Option<String>,
    supported_alg: &Option<String>,
    issuer_supported_alg_values: &Option<Vec<String>>,
    endpoint: &str,
) -> Result<(), OidcClientError> {
    if let Some(am) = auth_method {
        if am.ends_with("_jwt") && supported_alg.is_none() && issuer_supported_alg_values.is_none()
        {
            return Err(OidcClientError::new(
                "TypeError",
                "invalid configuration",
                &format!("{0}_endpoint_auth_signing_alg_values_supported must be configured on the issuer if {0}_endpoint_auth_signing_alg is not defined on a client", endpoint),
                None
            ));
        }
    }
    Ok(())
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("client_id", &self.client_id)
            .field("client_secret", &self.client_secret)
            .field("grant_types", &self.grant_types)
            .field(
                "id_token_signed_response_alg",
                &self.id_token_signed_response_alg,
            )
            .field("response_types", &self.response_types)
            .field(
                "token_endpoint_auth_method",
                &self.token_endpoint_auth_method,
            )
            .field(
                "token_endpoint_auth_signing_alg",
                &self.token_endpoint_auth_signing_alg,
            )
            .field(
                "introspection_endpoint_auth_method",
                &self.introspection_endpoint_auth_method,
            )
            .field(
                "introspection_endpoint_auth_signing_alg",
                &self.introspection_endpoint_auth_signing_alg,
            )
            .field(
                "revocation_endpoint_auth_method",
                &self.revocation_endpoint_auth_method,
            )
            .field(
                "revocation_endpoint_auth_signing_alg",
                &self.revocation_endpoint_auth_signing_alg,
            )
            .field("redirect_uri", &self.redirect_uri)
            .field("redirect_uris", &self.redirect_uris)
            .field("response_type", &self.response_type)
            .field(
                "request_interceptor",
                &"fn(&RequestOptions) -> RequestOptions",
            )
            .field("jwks", &self.jwks)
            .field("other_fields", &self.other_fields)
            .field("issuer", &self.issuer)
            .finish()
    }
}

#[cfg(test)]
#[path = "../tests/client_test.rs"]
mod client_test;
