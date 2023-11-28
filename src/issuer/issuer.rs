use core::fmt::Debug;
use std::collections::HashMap;

use crate::client::Client;
use crate::helpers::{convert_json_to, now, validate_url, webfinger_normalize};
use crate::http::request_async;
use crate::jwks::Jwks;
use crate::types::{
    ClientMetadata, ClientOptions, Fapi, IssuerMetadata, MtlsEndpoints, OidcClientError, Request,
    RequestInterceptor, Response, WebFingerResponse,
};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Method, StatusCode};
use serde_json::Value;

use super::keystore::KeyStore;

/// Holds all the discovered values from the OIDC Issuer
#[derive(Debug)]
pub struct Issuer {
    pub(crate) issuer: String,
    pub(crate) authorization_endpoint: Option<String>,
    pub(crate) device_authorization_endpoint: Option<String>,
    pub(crate) token_endpoint: Option<String>,
    pub(crate) jwks_uri: Option<String>,
    pub(crate) userinfo_endpoint: Option<String>,
    pub(crate) revocation_endpoint: Option<String>,
    pub(crate) claims_parameter_supported: Option<bool>,
    pub(crate) grant_types_supported: Option<Vec<String>>,
    pub(crate) request_parameter_supported: Option<bool>,
    pub(crate) request_uri_parameter_supported: Option<bool>,
    pub(crate) require_request_uri_registration: Option<bool>,
    pub(crate) response_modes_supported: Option<Vec<String>>,
    pub(crate) claim_types_supported: Vec<String>,
    pub(crate) token_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub(crate) token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    pub(crate) introspection_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub(crate) introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    pub(crate) revocation_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub(crate) revocation_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    pub(crate) end_session_endpoint: Option<String>,
    pub(crate) other_fields: HashMap<String, Value>,
    pub(crate) keystore: Option<KeyStore>,
    pub(crate) mtls_endpoint_aliases: Option<MtlsEndpoints>,
    pub(crate) introspection_endpoint: Option<String>,
    pub(crate) registration_endpoint: Option<String>,
    pub(crate) authorization_response_iss_parameter_supported: Option<bool>,
    pub(crate) dpop_signing_alg_values_supported: Option<Vec<String>>,
    pub(crate) pushed_authorization_request_endpoint: Option<String>,
    pub(crate) require_pushed_authorization_requests: bool,
    pub(crate) request_interceptor: Option<RequestInterceptor>,
    pub(crate) now: fn() -> i64,
}

impl Default for Issuer {
    fn default() -> Self {
        Self {
            claims_parameter_supported: Some(false),
            grant_types_supported: Some(vec![
                String::from("authorization_code"),
                String::from("implicit"),
            ]),
            request_parameter_supported: Some(false),
            request_uri_parameter_supported: Some(true),
            require_request_uri_registration: Some(false),
            response_modes_supported: Some(vec![String::from("query"), String::from("fragment")]),
            claim_types_supported: vec![String::from("normal")],
            token_endpoint_auth_methods_supported: Some(vec!["client_secret_basic".to_string()]),
            introspection_endpoint_auth_methods_supported: None,
            issuer: "".to_string(),
            authorization_endpoint: None,
            token_endpoint: None,
            jwks_uri: None,
            userinfo_endpoint: None,
            revocation_endpoint: None,
            request_interceptor: None,
            revocation_endpoint_auth_methods_supported: None,
            token_endpoint_auth_signing_alg_values_supported: None,
            introspection_endpoint_auth_signing_alg_values_supported: None,
            revocation_endpoint_auth_signing_alg_values_supported: None,
            end_session_endpoint: None,
            other_fields: Default::default(),
            keystore: None,
            mtls_endpoint_aliases: None,
            introspection_endpoint: None,
            authorization_response_iss_parameter_supported: None,
            registration_endpoint: None,
            dpop_signing_alg_values_supported: None,
            pushed_authorization_request_endpoint: None,
            require_pushed_authorization_requests: false,
            now,
            device_authorization_endpoint: None,
        }
    }
}

/// Issuer Instance Creation
impl Issuer {
    fn from(metadata: IssuerMetadata) -> Self {
        let token_endpoint_auth_methods_supported =
            match metadata.token_endpoint_auth_methods_supported {
                None => Some(vec!["client_secret_basic".to_string()]),
                Some(v) => Some(v),
            };

        let introspection_endpoint_auth_methods_supported =
            match metadata.introspection_endpoint_auth_methods_supported {
                None => token_endpoint_auth_methods_supported.clone(),
                Some(v) => Some(v),
            };

        let introspection_endpoint_auth_signing_alg_values_supported =
            match metadata.introspection_endpoint_auth_signing_alg_values_supported {
                None => metadata
                    .token_endpoint_auth_signing_alg_values_supported
                    .clone(),
                Some(v) => Some(v),
            };

        let revocation_endpoint_auth_methods_supported =
            match metadata.revocation_endpoint_auth_methods_supported {
                None => token_endpoint_auth_methods_supported.clone(),
                Some(v) => Some(v),
            };

        let revocation_endpoint_auth_signing_alg_values_supported =
            match metadata.revocation_endpoint_auth_signing_alg_values_supported {
                None => metadata
                    .token_endpoint_auth_signing_alg_values_supported
                    .clone(),
                Some(v) => Some(v),
            };

        Self {
            issuer: metadata.issuer,
            authorization_endpoint: metadata.authorization_endpoint,
            token_endpoint: metadata.token_endpoint,
            jwks_uri: metadata.jwks_uri,
            userinfo_endpoint: metadata.userinfo_endpoint,
            revocation_endpoint: metadata.revocation_endpoint,
            token_endpoint_auth_methods_supported,
            introspection_endpoint_auth_methods_supported,
            introspection_endpoint_auth_signing_alg_values_supported,
            revocation_endpoint_auth_methods_supported,
            revocation_endpoint_auth_signing_alg_values_supported,
            end_session_endpoint: metadata.end_session_endpoint,
            registration_endpoint: metadata.registration_endpoint,
            introspection_endpoint: metadata.introspection_endpoint,
            token_endpoint_auth_signing_alg_values_supported: metadata
                .token_endpoint_auth_signing_alg_values_supported,
            mtls_endpoint_aliases: metadata.mtls_endpoint_aliases,
            authorization_response_iss_parameter_supported: metadata
                .authorization_response_iss_parameter_supported,
            dpop_signing_alg_values_supported: metadata.dpop_signing_alg_values_supported,
            pushed_authorization_request_endpoint: metadata.pushed_authorization_request_endpoint,
            require_pushed_authorization_requests: metadata.require_pushed_authorization_requests,
            other_fields: metadata.other_fields,
            ..Issuer::default()
        }
    }

    /// ## Issuer
    ///
    /// Create an [Issuer] instance using [IssuerMetadata].
    ///
    /// - `metadata` - [IssuerMetadata]
    /// - `interceptor` - See [RequestInterceptor] docs for setting up an interceptor.
    ///
    /// No OIDC Discovery defaults are set if Issuer is created using this method.
    ///
    /// If no introspection/revocation endpoint auth methods or algorithms are specified,
    /// value of token endpoint auth methods and algorithms are used as the the value for the said
    /// properties.
    ///
    ///
    /// ### *Example:*
    ///
    /// ```rust
    ///     let metadata = IssuerMetadata {
    ///         issuer: "https://auth.example.com".to_string(),
    ///         authorization_endpoint: Some("https://auth.example.com/authorize".to_string()),
    ///         token_endpoint: Some("https://auth.example.com/token".to_string()),
    ///         userinfo_endpoint: Some("https://auth.example.com/userinfo".to_string()),
    ///         jwks_uri: Some("https://auth.example.com/certs".to_string()),
    ///         ..IssuerMetadata::default()
    ///     };
    ///
    ///     let issuer = Issuer::new(metadata, None);
    /// ```
    pub fn new(metadata: IssuerMetadata, interceptor: Option<RequestInterceptor>) -> Self {
        let introspection_endpoint_auth_methods_supported =
            match metadata.introspection_endpoint_auth_methods_supported {
                None => metadata.token_endpoint_auth_methods_supported.clone(),
                Some(v) => Some(v),
            };

        let introspection_endpoint_auth_signing_alg_values_supported =
            match metadata.introspection_endpoint_auth_signing_alg_values_supported {
                None => metadata
                    .token_endpoint_auth_signing_alg_values_supported
                    .clone(),
                Some(v) => Some(v),
            };

        let revocation_endpoint_auth_methods_supported =
            match metadata.revocation_endpoint_auth_methods_supported {
                None => metadata.token_endpoint_auth_methods_supported.clone(),
                Some(v) => Some(v),
            };

        let revocation_endpoint_auth_signing_alg_values_supported =
            match metadata.revocation_endpoint_auth_signing_alg_values_supported {
                None => metadata
                    .token_endpoint_auth_signing_alg_values_supported
                    .clone(),
                Some(v) => Some(v),
            };

        let jwks_uri = metadata.jwks_uri.clone();
        let cloned_interceptor = interceptor.as_ref().map(|i| i.clone_box());

        Self {
            issuer: metadata.issuer,
            authorization_endpoint: metadata.authorization_endpoint,
            token_endpoint: metadata.token_endpoint,
            jwks_uri: metadata.jwks_uri,
            userinfo_endpoint: metadata.userinfo_endpoint,
            revocation_endpoint: metadata.revocation_endpoint,
            claims_parameter_supported: None,
            grant_types_supported: None,
            request_parameter_supported: None,
            request_uri_parameter_supported: None,
            require_request_uri_registration: None,
            response_modes_supported: None,
            claim_types_supported: vec![],
            token_endpoint_auth_methods_supported: metadata.token_endpoint_auth_methods_supported,
            introspection_endpoint_auth_methods_supported,
            token_endpoint_auth_signing_alg_values_supported: metadata
                .token_endpoint_auth_signing_alg_values_supported,
            introspection_endpoint_auth_signing_alg_values_supported,
            revocation_endpoint_auth_methods_supported,
            revocation_endpoint_auth_signing_alg_values_supported,
            other_fields: metadata.other_fields,
            request_interceptor: interceptor,
            keystore: Some(KeyStore::new(jwks_uri, cloned_interceptor)),
            mtls_endpoint_aliases: metadata.mtls_endpoint_aliases,
            introspection_endpoint: metadata.introspection_endpoint,
            registration_endpoint: metadata.registration_endpoint,
            end_session_endpoint: metadata.end_session_endpoint,
            authorization_response_iss_parameter_supported: metadata
                .authorization_response_iss_parameter_supported,
            dpop_signing_alg_values_supported: metadata.dpop_signing_alg_values_supported,
            pushed_authorization_request_endpoint: metadata.pushed_authorization_request_endpoint,
            require_pushed_authorization_requests: metadata.require_pushed_authorization_requests,
            now,
            device_authorization_endpoint: metadata.device_authorization_endpoint,
        }
    }
}

/// OIDC [Issuer Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery)
impl Issuer {
    /// # Discover OIDC Issuer
    ///
    /// Discover an OIDC Issuer using the issuer url.
    ///
    /// - `issuer` - The issuer url (absolute).
    /// - `interceptor` - See [RequestInterceptor] docs for setting up an interceptor.
    ///
    /// *Only an absolute urls are accepted, passing in `auth.example.com` will result in an error.*
    ///
    ///
    /// ### *Example:*
    ///
    /// ```rust
    ///     let _ = Issuer::discover_async("https://auth.example.com", None)
    ///         .await
    ///         .unwrap();
    /// ```
    ///
    /// ### *Example: with .well-known/openid-configuration*
    ///
    /// Urls with `.well-known/openid-configuration` can also be used to discover issuer.
    ///
    /// ```rust
    ///     let _ = Issuer::discover_async(
    ///         "https://auth.example.com/.well-known/openid-configuration",
    ///         None,
    ///     )
    ///     .await
    ///     .unwrap();
    /// ```
    pub async fn discover_async(
        issuer: &str,
        mut interceptor: Option<RequestInterceptor>,
    ) -> Result<Issuer, OidcClientError> {
        let mut url = match validate_url(issuer) {
            Ok(parsed) => parsed,
            Err(err) => return Err(err),
        };

        let mut path: String = url.path().to_string();
        if path.ends_with('/') {
            path.pop();
        }

        if path.ends_with(".well-known") {
            path.push_str("/openid-configuration");
        } else if !path.contains(".well-known") {
            path.push_str("/.well-known/openid-configuration");
        }

        url.set_path(&path);

        let mut headers = HeaderMap::new();
        headers.append("accept", HeaderValue::from_static("application/json"));

        let req = Request {
            url: url.to_string(),
            headers,
            ..Request::default()
        };

        let res = request_async(&req, interceptor.as_mut()).await?;

        let issuer_metadata = match convert_json_to::<IssuerMetadata>(res.body.as_ref().unwrap()) {
            Ok(metadata) => metadata,
            Err(_) => {
                return Err(OidcClientError::new_op_error(
                    "invalid_issuer_metadata".to_string(),
                    None,
                    None,
                    None,
                    None,
                    Some(res),
                ));
            }
        };

        let mut issuer = Issuer::from(issuer_metadata);
        issuer.request_interceptor = interceptor;

        Ok(issuer)
    }
}

/// OIDC [Issuer Webfinger Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery)
impl Issuer {
    /// # Webfinger OIDC Issuer Discovery
    ///
    /// Discover an OIDC Issuer using the user email, url, url with port syntax or acct syntax.
    ///
    /// - `input` - The resource.
    /// - `interceptor` - See [RequestInterceptor] docs for setting up an interceptor.
    ///
    ///
    /// ### *Example:*
    ///
    /// ```rust
    ///     let _issuer_email = Issuer::webfinger_async("joe@auth.example.com", None)
    ///         .await
    ///         .unwrap();
    ///     let _issuer_url = Issuer::webfinger_async("https://auth.example.com/joe", None)
    ///         .await
    ///         .unwrap();
    ///     let _issuer_url_port = Issuer::webfinger_async("auth.example.com:3000/joe", None)
    ///         .await
    ///         .unwrap();
    ///     let _issuer_acct_email = Issuer::webfinger_async("acct:joe@auth.example.com", None)
    ///         .await
    ///         .unwrap();
    ///     let _issuer_acct_host = Issuer::webfinger_async("acct:auth.example.com", None)
    ///         .await
    ///         .unwrap();
    /// ```
    pub async fn webfinger_async(
        input: &str,
        mut interceptor: Option<RequestInterceptor>,
    ) -> Result<Issuer, OidcClientError> {
        let req = Self::build_webfinger_request(input)?;

        let res = request_async(&req, interceptor.as_mut()).await?;

        let expected_issuer = Self::process_webfinger_response(res)?;

        let issuer_result = Issuer::discover_async(&expected_issuer, interceptor).await;

        Self::process_webfinger_issuer_result(issuer_result, expected_issuer)
    }

    fn build_webfinger_request(input: &str) -> Result<Request, OidcClientError> {
        let resource = webfinger_normalize(input);

        let mut host: Option<String> = None;

        if resource.starts_with("acct:") {
            let split: Vec<&str> = resource.split('@').collect();
            host = Some(split[1].to_string());
        } else if resource.starts_with("https://") {
            let url = match validate_url(&resource) {
                Ok(parsed) => parsed,
                Err(err) => return Err(err),
            };

            if let Some(host_str) = url.host_str() {
                host = match url.port() {
                    Some(port) => Some(host_str.to_string() + &format!(":{}", port)),
                    None => Some(host_str.to_string()),
                }
            }
        }

        if host.is_none() {
            return Err(OidcClientError::new_type_error(
                "given input was invalid",
                None,
            ));
        }

        let web_finger_url = format!("https://{}/.well-known/webfinger", host.unwrap());

        let mut headers = HeaderMap::new();
        headers.append("accept", HeaderValue::from_static("application/json"));

        let mut search_params = HashMap::new();
        search_params.insert("resource".to_string(), vec![resource]);
        search_params.insert(
            "rel".to_string(),
            vec!["http://openid.net/specs/connect/1.0/issuer".to_string()],
        );

        Ok(Request {
            url: web_finger_url,
            method: Method::GET,
            headers,
            bearer: false,
            expected: StatusCode::OK,
            expect_body: true,
            search_params,
            ..Default::default()
        })
    }

    fn process_webfinger_response(response: Response) -> Result<String, OidcClientError> {
        let webfinger_response =
            match convert_json_to::<WebFingerResponse>(response.body.as_ref().unwrap()) {
                Ok(res) => res,
                Err(_) => {
                    return Err(OidcClientError::new_op_error(
                        "invalid  webfinger response".to_string(),
                        None,
                        None,
                        None,
                        None,
                        Some(response),
                    ));
                }
            };

        let location_link_result = webfinger_response
            .links
            .iter()
            .find(|x| x.rel == "http://openid.net/specs/connect/1.0/issuer" && x.href.is_some());

        let expected_issuer = match location_link_result {
            Some(link) => link.href.as_ref().unwrap(),
            None => {
                return Err(OidcClientError::new_rp_error(
                    "no issuer found in webfinger response",
                    Some(response),
                    None,
                ));
            }
        };

        if !expected_issuer.starts_with("https://") {
            return Err(OidcClientError::new_op_error(
                "invalid_location".to_string(),
                Some(format!("invalid issuer location {}", expected_issuer)),
                None,
                None,
                None,
                Some(response),
            ));
        }

        Ok(expected_issuer.to_string())
    }

    fn process_webfinger_issuer_result(
        issuer_result: Result<Issuer, OidcClientError>,
        expected_issuer: String,
    ) -> Result<Issuer, OidcClientError> {
        let mut response = None;

        let issuer = match issuer_result {
            Ok(i) => i,
            Err(err) => {
                response = match &err {
                    OidcClientError::Error(_, response) => response.as_ref(),
                    OidcClientError::TypeError(_, response) => response.as_ref(),
                    OidcClientError::RPError(_, response) => response.as_ref(),
                    OidcClientError::OPError(_, response) => response.as_ref(),
                };

                if let Some(error_res) = response {
                    if error_res.status == StatusCode::NOT_FOUND {
                        return Err(OidcClientError::new_op_error(
                            "no_issuer".to_string(),
                            Some(format!("invalid issuer location {}", expected_issuer)),
                            None,
                            None,
                            None,
                            Some(error_res.clone()),
                        ));
                    }
                }

                return Err(err);
            }
        };

        if issuer.issuer != expected_issuer {
            return Err(OidcClientError::new_op_error(
                "issuer_mismatch".to_string(),
                Some(format!(
                    "discovered issuer mismatch, expected {}, got: {}",
                    expected_issuer, issuer.issuer
                )),
                None,
                None,
                None,
                response.cloned(),
            ));
        }

        Ok(issuer)
    }
}

/// New [Client] implementation for Issuer
impl Issuer {
    /// # Creates a client from the issuer
    /// This method creates a new [Client] from the issuer.
    /// A client metadata with a required `client_id` field is also required
    ///
    /// - `metadata` - [ClientMetadata]
    /// - `interceptor` - See [RequestInterceptor] docs for setting up an interceptor.
    /// - `jwks` - The client jwks with private keys.
    /// - `client_options` - Client options.
    /// - `fapi` - Version of FAPI
    ///
    /// Note: If the [Issuer] already have a request interceptor and none was passed in through `interceptor`,
    ///       the interceptor from the [Issuer] is used.
    ///
    /// ### *Example:*
    ///
    /// ```rust
    ///     let issuer = Issuer::discover_async("https://auth.example.com", None)
    ///         .await
    ///         .unwrap();
    ///     
    ///     let client_metadata = ClientMetadata {
    ///         client_id: Some("client_id".to_string()),
    ///         ..ClientMetadata::default()
    ///     };
    ///     
    ///     let _client = issuer.client(client_metadata, None, None, None, None).unwrap();
    /// ```
    ///
    /// ### *Example: with jwks*
    ///
    /// ```rust
    ///     let issuer = Issuer::discover_async("https://auth.example.com", None)
    ///         .await
    ///         .unwrap();
    ///    
    ///     let client_metadata = ClientMetadata {
    ///         client_id: Some("client_id".to_string()),
    ///         token_endpoint_auth_method: Some("private_key_jwt".to_string()),
    ///         ..ClientMetadata::default()
    ///     };
    ///    
    ///     let mut jwk = Jwk::generate_rsa_key(2048).unwrap();
    ///     jwk.set_algorithm("PS256");
    ///     let jwks = Jwks::from(vec![jwk]);
    ///    
    ///     let _client = issuer
    ///         .client(client_metadata, None, Some(jwks), None, None)
    ///         .unwrap();
    /// ```
    pub fn client(
        &self,
        metadata: ClientMetadata,
        interceptor: Option<RequestInterceptor>,
        jwks: Option<Jwks>,
        client_options: Option<ClientOptions>,
        fapi: Option<Fapi>,
    ) -> Result<Client, OidcClientError> {
        let request_interceptor = match (interceptor, &self.request_interceptor) {
            (None, Some(i)) => Some(i.clone_box()),
            (Some(i), None) | (Some(i), Some(_)) => Some(i),
            _ => None,
        };

        Client::jwks_only_private_keys_validation(jwks.as_ref())?;

        Client::from_internal(
            metadata,
            Some(self),
            request_interceptor,
            jwks,
            client_options,
            fapi,
        )
    }
}

impl Clone for Issuer {
    fn clone(&self) -> Self {
        let request_interceptor = self.request_interceptor.as_ref().map(|i| i.clone_box());

        Self {
            issuer: self.issuer.clone(),
            authorization_endpoint: self.authorization_endpoint.clone(),
            token_endpoint: self.token_endpoint.clone(),
            jwks_uri: self.jwks_uri.clone(),
            userinfo_endpoint: self.userinfo_endpoint.clone(),
            revocation_endpoint: self.revocation_endpoint.clone(),
            claims_parameter_supported: self.claims_parameter_supported,
            grant_types_supported: self.grant_types_supported.clone(),
            request_parameter_supported: self.request_parameter_supported,
            request_uri_parameter_supported: self.request_uri_parameter_supported,
            require_request_uri_registration: self.require_request_uri_registration,
            response_modes_supported: self.response_modes_supported.clone(),
            claim_types_supported: self.claim_types_supported.clone(),
            token_endpoint_auth_methods_supported: self
                .token_endpoint_auth_methods_supported
                .clone(),
            token_endpoint_auth_signing_alg_values_supported: self
                .token_endpoint_auth_signing_alg_values_supported
                .clone(),
            introspection_endpoint_auth_methods_supported: self
                .introspection_endpoint_auth_methods_supported
                .clone(),
            introspection_endpoint_auth_signing_alg_values_supported: self
                .introspection_endpoint_auth_signing_alg_values_supported
                .clone(),
            revocation_endpoint_auth_methods_supported: self
                .revocation_endpoint_auth_methods_supported
                .clone(),
            revocation_endpoint_auth_signing_alg_values_supported: self
                .revocation_endpoint_auth_signing_alg_values_supported
                .clone(),
            other_fields: self.other_fields.clone(),
            keystore: self.keystore.clone(),
            mtls_endpoint_aliases: self.mtls_endpoint_aliases.clone(),
            introspection_endpoint: self.introspection_endpoint.clone(),
            request_interceptor,
            registration_endpoint: self.registration_endpoint.clone(),
            end_session_endpoint: self.end_session_endpoint.clone(),
            authorization_response_iss_parameter_supported: self
                .authorization_response_iss_parameter_supported,
            dpop_signing_alg_values_supported: self.dpop_signing_alg_values_supported.clone(),
            pushed_authorization_request_endpoint: self
                .pushed_authorization_request_endpoint
                .clone(),
            require_pushed_authorization_requests: self.require_pushed_authorization_requests,
            now,
            device_authorization_endpoint: self.device_authorization_endpoint.clone(),
        }
    }
}

impl Issuer {
    /// Gets the [IssuerMetadata] of the [Issuer]
    pub fn get_metadata(&self) -> IssuerMetadata {
        IssuerMetadata {
            issuer: self.issuer.clone(),
            authorization_endpoint: self.authorization_endpoint.clone(),
            device_authorization_endpoint: self.device_authorization_endpoint.clone(),
            token_endpoint: self.token_endpoint.clone(),
            jwks_uri: self.jwks_uri.clone(),
            userinfo_endpoint: self.userinfo_endpoint.clone(),
            revocation_endpoint: self.revocation_endpoint.clone(),
            end_session_endpoint: self.end_session_endpoint.clone(),
            registration_endpoint: self.registration_endpoint.clone(),
            introspection_endpoint: self.introspection_endpoint.clone(),
            token_endpoint_auth_methods_supported: self
                .token_endpoint_auth_methods_supported
                .clone(),
            token_endpoint_auth_signing_alg_values_supported: self
                .token_endpoint_auth_signing_alg_values_supported
                .clone(),
            introspection_endpoint_auth_methods_supported: self
                .introspection_endpoint_auth_methods_supported
                .clone(),
            introspection_endpoint_auth_signing_alg_values_supported: self
                .introspection_endpoint_auth_signing_alg_values_supported
                .clone(),
            revocation_endpoint_auth_methods_supported: self
                .revocation_endpoint_auth_methods_supported
                .clone(),
            revocation_endpoint_auth_signing_alg_values_supported: self
                .revocation_endpoint_auth_signing_alg_values_supported
                .clone(),
            mtls_endpoint_aliases: self.mtls_endpoint_aliases.clone(),
            authorization_response_iss_parameter_supported: self
                .authorization_response_iss_parameter_supported,
            dpop_signing_alg_values_supported: self.dpop_signing_alg_values_supported.clone(),
            pushed_authorization_request_endpoint: self
                .pushed_authorization_request_endpoint
                .clone(),
            require_pushed_authorization_requests: self.require_pushed_authorization_requests,
            other_fields: self.other_fields.clone(),
        }
    }

    /// Get Jwks
    pub async fn get_jwks(&mut self) -> Option<Jwks> {
        if let Some(ks) = &mut self.keystore {
            return ks.get_keystore_async(false).await.ok();
        }

        None
    }

    /// Sets an [RequestInterceptor]
    pub fn set_request_interceptor(&mut self, interceptor: RequestInterceptor) {
        self.request_interceptor = Some(interceptor);
    }
}

#[cfg(test)]
#[path = "../tests/issuer/mod.rs"]
mod issuer_tests;
