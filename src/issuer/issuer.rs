use core::fmt::Debug;
use std::collections::HashMap;
use std::fmt::Formatter;

use crate::client::Client;
use crate::helpers::{convert_json_to, validate_url, webfinger_normalize};
use crate::http::{default_request_interceptor, request, request_async};
use crate::jwks::Jwks;
use crate::types::{
    ClientMetadata, ClientOptions, IssuerMetadata, OidcClientError, Request, RequestInterceptor,
    Response, WebFingerResponse,
};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Method, StatusCode};

/// Holds all the discovered values from the OIDC Issuer
pub struct Issuer {
    /// Discovered issuer uri.
    pub(crate) issuer: String,
    /// OpenID Connect [Authorization Endpoint](https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint).
    pub(crate) authorization_endpoint: Option<String>,
    /// OpenID Connect [Token Endpoint](https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint).
    pub(crate) token_endpoint: Option<String>,
    /// URL of the authorization server's JWK Set. [See](https://www.rfc-editor.org/rfc/rfc8414.html#section-2).
    pub(crate) jwks_uri: Option<String>,
    /// OpenID Connect [Userinfo Endpoint](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo).
    pub(crate) userinfo_endpoint: Option<String>,
    /// Endpoint for revoking refresh tokes and access tokens. [Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414.html#section-2).
    pub(crate) revocation_endpoint: Option<String>,
    /// Claims supported by the Authorization Server
    pub(crate) claims_parameter_supported: Option<bool>,
    /// OAuth 2.0 Grant Types supported by the Authorization Server. [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591).
    pub(crate) grant_types_supported: Option<Vec<String>>,
    /// Indicates whether request object is supported by Authorization Server. [OIDC Request Object](https://openid.net/specs/openid-connect-core-1_0.html#RequestObject).
    pub(crate) request_parameter_supported: Option<bool>,
    /// Indicates whether request object by reference is supported by Authorization Server. [OIDC Request Object by Reference](https://openid.net/specs/openid-connect-core-1_0.html#RequestUriParameter).
    pub(crate) request_uri_parameter_supported: Option<bool>,
    /// Whether a request uri has to be pre registered with Authorization Server.
    pub(crate) require_request_uri_registration: Option<bool>,
    /// OAuth 2.0 Response Mode values that Authorization Server supports. [Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414.html#section-2).
    pub(crate) response_modes_supported: Option<Vec<String>>,
    /// Claim Types supported. [OIDC Claim types](https://openid.net/specs/openid-connect-core-1_0.html#ClaimTypes).
    pub(crate) claim_types_supported: Vec<String>,
    /// Client Authentication methods supported by Token Endpoint. [Client Authentication](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication)
    pub(crate) token_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// List of client [authentication methods](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#token-endpoint-auth-method) supported by the Authorization Server.
    pub(crate) introspection_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// List of JWS signing algorithms supported by the introspection endpoint for the signature of
    /// the JWT that the client uses to authenticate.
    pub(crate) introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    /// List of client [authentication methods](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#token-endpoint-auth-method) supported by the Authorization Server.
    pub(crate) revocation_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// List of JWS signing algorithms supported by the revocation endpoint for the signature of the
    /// JWT that the client uses to authenticate.
    pub(crate) revocation_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    /// Extra key values
    pub(crate) other_fields: HashMap<String, serde_json::Value>,
    /// Jwk Key Set,
    pub(crate) jwks: Option<Jwks>,
    /// Client registration endpoint
    pub(crate) registration_endpoint: Option<String>,
    /// Request interceptor used for every request
    pub(crate) request_interceptor: RequestInterceptor,
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
            request_interceptor: Box::new(default_request_interceptor),
            revocation_endpoint_auth_methods_supported: None,
            introspection_endpoint_auth_signing_alg_values_supported: None,
            revocation_endpoint_auth_signing_alg_values_supported: None,
            other_fields: Default::default(),
            jwks: None,
            registration_endpoint: None,
        }
    }
}

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
            other_fields: metadata.other_fields,
            ..Issuer::default()
        }
    }

    /// # Instantiate new Issuer using [IssuerMetadata]
    ///
    /// ```
    /// # use openid_client::{Issuer, IssuerMetadata};
    ///
    /// fn main() {
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
    /// }
    /// ```
    ///
    /// No OIDC Discovery defaults are set if Issuer is made through this method.
    ///
    /// If no introspection/revocation endpoint auth methods or algorithms are specified,
    /// value of token endpoint auth methods and algorithms are used as the the value for the said
    /// properties.
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

        let interceptor = match interceptor {
            Some(i) => i,
            None => Box::new(default_request_interceptor),
        };

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
            introspection_endpoint_auth_signing_alg_values_supported,
            revocation_endpoint_auth_methods_supported,
            revocation_endpoint_auth_signing_alg_values_supported,
            other_fields: metadata.other_fields,
            request_interceptor: interceptor,
            jwks: None,
            registration_endpoint: metadata.registration_endpoint,
        }
    }
}

/// OIDC [Issuer Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery)
impl Issuer {
    /// # Discover OIDC Issuer
    ///
    /// `This is a blocking method.` Checkout [`Issuer::discover_async()`] for async version.
    ///
    /// Discover an OIDC Issuer using the issuer url method.
    ///
    /// ```
    /// # use openid_client::Issuer;
    ///
    /// fn main(){
    ///     let issuer = Issuer::discover("https://auth.example.com").unwrap();
    /// }
    /// ```
    /// Only an absolute urls are accepted, passing in `auth.example.com` will result in an error.
    ///
    /// Urls with `.well-known/openid-configuration` can also be used to discover issuer.
    ///
    /// ```
    /// # use openid_client::Issuer;
    ///
    /// fn main(){
    ///     let issuer = Issuer::discover("https://auth.example.com/.well-known/openid-configurtaion").unwrap();
    /// }
    /// ```
    pub fn discover(
        issuer: &str,
        interceptor: Option<RequestInterceptor>,
    ) -> Result<Issuer, OidcClientError> {
        let mut interceptor = interceptor.unwrap_or(Box::new(default_request_interceptor));
        let req = Self::build_discover_request(issuer)?;

        let res = request(req, &mut interceptor)?;

        Self::process_discover_response(res, interceptor)
    }

    /// # Discover OIDC Issuer
    ///
    /// `This is an async method.` Checkout [`Issuer::discover()`] for blocking version.
    ///
    /// Discover an OIDC Issuer using the issuer url method.
    ///
    /// ```
    /// # use openid_client::Issuer;
    ///
    /// #[tokio::main]
    ///async fn main(){
    ///     let issuer = Issuer::discover_async("https://auth.example.com").await.unwrap();
    /// }
    /// ```
    /// Only an absolute urls are accepted, passing in `auth.example.com` will result in an error.
    ///
    /// Urls with `.well-known/openid-configuration` can also be used to discover issuer.
    ///
    /// ```
    /// # use openid_client::Issuer;
    ///
    ///#[tokio::main]
    ///async fn main(){
    ///     let issuer = Issuer::discover_async("https://auth.example.com/.well-known/openid-configurtaion").await.unwrap();
    /// }
    /// ```
    pub async fn discover_async(
        issuer: &str,
        interceptor: Option<RequestInterceptor>,
    ) -> Result<Issuer, OidcClientError> {
        let mut interceptor = interceptor.unwrap_or(Box::new(default_request_interceptor));

        let req = Self::build_discover_request(issuer)?;

        let res = request_async(req, &mut interceptor).await?;

        Self::process_discover_response(res, interceptor)
    }

    /// This is a private function that is used to build the discover request.
    fn build_discover_request(issuer: &str) -> Result<Request, OidcClientError> {
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

        Ok(Request {
            url: url.to_string(),
            headers,
            ..Request::default()
        })
    }

    /// This is a private function that is used to process the discover response.
    fn process_discover_response(
        response: Response,
        interceptor: RequestInterceptor,
    ) -> Result<Issuer, OidcClientError> {
        let issuer_metadata =
            match convert_json_to::<IssuerMetadata>(response.body.as_ref().unwrap()) {
                Ok(metadata) => metadata,
                Err(_) => {
                    return Err(OidcClientError::new(
                        "OPError",
                        "invalid_issuer_metadata",
                        "invalid issuer metadata",
                        Some(response),
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
    /// > `This is a blocking method.` Checkout [`Issuer::webfinger_async()`] for async version.
    ///
    /// Discover an OIDC Issuer using the user email, url, url with port syntax or acct syntax.
    ///
    /// ```
    /// # use openid_client::Issuer;
    ///
    /// fn main(){
    ///     let issuer_email = Issuer::webfinger("joe@auth.example.com").unwrap();
    ///     let issuer_url = Issuer::webfinger("https://auth.example.com/joe").unwrap();
    ///     let issuer_url_port = Issuer::webfinger("auth.example.com:3000/joe").unwrap();
    ///     let issuer_acct_email = Issuer::webfinger("acct:joe@auth.example.com").unwrap();
    ///     let issuer_acct_host = Issuer::webfinger("acct:auth.example.com").unwrap();
    /// }
    /// ```
    pub fn webfinger(
        input: &str,
        interceptor: Option<RequestInterceptor>,
    ) -> Result<Issuer, OidcClientError> {
        let mut interceptor = interceptor.unwrap_or(Box::new(default_request_interceptor));

        let req = Self::build_webfinger_request(input)?;

        let res = request(req, &mut interceptor)?;

        let expected_issuer = Self::process_webfinger_response(res)?;

        let issuer_result = Issuer::discover(&expected_issuer, Some(interceptor));

        Self::process_webfinger_issuer_result(issuer_result, expected_issuer)
    }

    /// # Webfinger OIDC Issuer Discovery
    ///
    /// > `This is an async method.` Checkout [`Issuer::webfinger()`] for blocking version.
    ///
    /// Discover an OIDC Issuer using the user email, url, url with port syntax or acct syntax.
    ///
    /// ```
    /// use openid_client::Issuer;
    ///#[tokio::main]
    ///async fn main(){
    ///     let issuer_email = Issuer::webfinger_async("joe@auth.example.com").await.unwrap();
    ///     let issuer_url = Issuer::webfinger_async("https://auth.example.com/joe").await.unwrap();
    ///     let issuer_url_port = Issuer::webfinger_async("auth.example.com:3000/joe").await.unwrap();
    ///     let issuer_acct_email = Issuer::webfinger_async("acct:joe@auth.example.com").await.unwrap();
    ///     let issuer_acct_host = Issuer::webfinger_async("acct:auth.example.com").await.unwrap();
    /// }
    /// ```
    pub async fn webfinger_async(
        input: &str,
        interceptor: Option<RequestInterceptor>,
    ) -> Result<Issuer, OidcClientError> {
        let mut interceptor = interceptor.unwrap_or(Box::new(default_request_interceptor));

        let req = Self::build_webfinger_request(input)?;

        let res = request_async(req, &mut interceptor).await?;

        let expected_issuer = Self::process_webfinger_response(res)?;

        let issuer_result = Issuer::discover_async(&expected_issuer, Some(interceptor)).await;

        Self::process_webfinger_issuer_result(issuer_result, expected_issuer)
    }

    /// Private function that builds the webfinger request
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
            return Err(OidcClientError::new(
                "TypeError",
                "invalid_resource",
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

    /// Private function that process the webfinger response
    fn process_webfinger_response(response: Response) -> Result<String, OidcClientError> {
        let webfinger_response =
            match convert_json_to::<WebFingerResponse>(response.body.as_ref().unwrap()) {
                Ok(res) => res,
                Err(_) => {
                    return Err(OidcClientError::new(
                        "OPError",
                        "invalid_webfinger_response",
                        "invalid  webfinger response",
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
                return Err(OidcClientError::new(
                    "OPError",
                    "empty_location_link",
                    "no issuer found in webfinger response",
                    Some(response),
                ));
            }
        };

        if !expected_issuer.starts_with("https://") {
            return Err(OidcClientError::new(
                "OPError",
                "invalid_location",
                &format!("invalid issuer location {}", expected_issuer),
                Some(response),
            ));
        }

        Ok(expected_issuer.to_string())
    }

    /// Private function that process the issuer response
    fn process_webfinger_issuer_result(
        issuer_result: Result<Issuer, OidcClientError>,
        expected_issuer: String,
    ) -> Result<Issuer, OidcClientError> {
        let issuer = match issuer_result {
            Ok(i) => i,
            Err(err) => match err.response {
                Some(err_response) if err_response.status == StatusCode::NOT_FOUND => {
                    return Err(OidcClientError::new(
                        &err.name,
                        "no_issuer",
                        &format!("invalid issuer location {}", expected_issuer),
                        Some(err_response),
                    ));
                }
                _ => return Err(err),
            },
        };

        if issuer.issuer != expected_issuer {
            return Err(OidcClientError::new(
                "OPError",
                "issuer_mismatch",
                &format!(
                    "discovered issuer mismatch, expected {}, got: {}",
                    expected_issuer, issuer.issuer
                ),
                None,
            ));
        }

        Ok(issuer)
    }
}

/// New [Client] implementation for Issuer
impl Issuer {
    /// # Get client from the issuer
    /// This method creates a new [Client] from the issuer.
    /// A client metadata with a required `client_id` field is also required
    ///
    /// - Note: The request interceptor from the issuer is not carried over to the client.
    ///         If no `interceptor` is provided with the method, a client with default request interceptor
    ///         is created. The reason for not taking the interceptor from the `issuer` is to
    ///         avoid the confusion of which request interceptor a [Client] is being created with
    ///         when you are trying to create a [Client] from the `issuer` that you get back from
    ///         the [`Client::get_issuer()`].
    ///
    /// ```
    /// # use openid_client::{Issuer, IssuerMetadata, ClientMetadata};
    ///
    /// fn main(){
    ///   let issuer_metadata = IssuerMetadata {
    ///       issuer: "https://auth.example.com".to_string(),
    ///       token_endpoint_auth_methods_supported: Some(vec![
    ///           "client_secret_post".to_string(),
    ///           "private_key_jwt".to_string(),
    ///        ]),
    ///        ..IssuerMetadata::default()
    ///    };
    ///    
    ///   let issuer = Issuer::new(issuer_metadata, None);
    ///
    ///   let client_metadata = ClientMetadata {
    ///       client_id: Some("client_id".to_string()),
    ///       ..ClientMetadata::default()
    ///   };
    ///
    ///   let client = issuer.client(client_metadata, None, None, None).unwrap();
    /// }
    /// ```
    ///
    ///  TODO: Document the client options and jwks and how it will be used by the client, and refactor the code snippet
    ///
    /// ```
    /// # use std::time::Duration;
    ///
    /// # use openid_client::{
    /// #     types::{ClientOptions, Jwks},
    /// #     ClientMetadata, Issuer, IssuerMetadata, RequestOptions, HeaderMap, HeaderValue
    /// # };
    ///
    /// fn main() {
    ///     let issuer_metadata = IssuerMetadata {
    ///         issuer: "https://auth.example.com".to_string(),
    ///         token_endpoint_auth_methods_supported: Some(vec![
    ///             "client_secret_post".to_string(),
    ///             "private_key_jwt".to_string(),
    ///         ]),
    ///         ..IssuerMetadata::default()
    ///     };
    ///
    ///     let issuer = Issuer::new(issuer_metadata, None);
    ///
    ///     let client_metadata = ClientMetadata {
    ///         client_id: Some("client_id".to_string()),
    ///         ..ClientMetadata::default()
    ///     };
    ///
    ///     let interceptor = |_request: &crate::types::Request| {
    ///         let mut headers = HeaderMap::new();
    ///         headers.append("testHeader", HeaderValue::from_static("testHeaderValue"));
    ///
    ///         RequestOptions {
    ///             headers,
    ///             timeout: Duration::from_millis(3500),
    ///         }
    ///     };
    ///
    ///     let client = issuer
    ///         .client(
    ///             client_metadata,
    ///             Some(Box::new(interceptor)),
    ///             Some(Jwks::default()),
    ///             Some(ClientOptions {
    ///                 additional_authorized_parties: Some(vec!["azp".to_string()]),
    ///             }),
    ///         )
    ///         .unwrap();
    /// }
    /// ```
    pub fn client(
        &self,
        metadata: ClientMetadata,
        interceptor: Option<RequestInterceptor>,
        jwks: Option<Jwks>,
        client_options: Option<ClientOptions>,
    ) -> Result<Client, OidcClientError> {
        let interceptor = interceptor.unwrap_or(Box::new(default_request_interceptor));

        Client::from_internal(metadata, Some(self), interceptor, jwks, client_options)
    }
}

impl Issuer {
    /// # Internal Documentation
    /// Creates a new [Issuer] with [`default_request_interceptor()`]
    pub(crate) fn clone_with_default_interceptor(&self) -> Self {
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
            jwks: self.jwks.clone(),
            request_interceptor: Box::new(default_request_interceptor),
            registration_endpoint: self.registration_endpoint.clone(),
        }
    }
}

impl Issuer {
    /// Get issuer
    pub fn get_issuer(&self) -> String {
        self.issuer.clone()
    }

    /// Get authorization endpoint
    pub fn get_authorization_endpoint(&self) -> Option<String> {
        self.authorization_endpoint.clone()
    }

    /// Get token endpoint
    pub fn get_token_endpoint(&self) -> Option<String> {
        self.token_endpoint.clone()
    }

    /// Get jwks uri
    pub fn get_jwks_uri(&self) -> Option<String> {
        self.jwks_uri.clone()
    }

    /// Get userinfo endpoint
    pub fn get_userinfo_endpoint(&self) -> Option<String> {
        self.userinfo_endpoint.clone()
    }

    /// Get revocation endpoint
    pub fn get_revocation_endpoint(&self) -> Option<String> {
        self.revocation_endpoint.clone()
    }

    /// Get claims paramter supported
    pub fn get_claims_parameter_supported(&self) -> Option<bool> {
        self.claims_parameter_supported
    }

    /// Get grant types supported
    pub fn get_grant_types_supported(&self) -> Option<Vec<String>> {
        Some(self.grant_types_supported.clone()?.to_vec())
    }

    /// Get request parameter supported
    pub fn get_request_parameter_supported(&self) -> Option<bool> {
        self.request_parameter_supported
    }

    /// Get request uri parameter supported
    pub fn get_request_uri_parameter_supported(&self) -> Option<bool> {
        self.request_uri_parameter_supported
    }

    /// Get require request uri registration
    pub fn get_require_request_uri_registration(&self) -> Option<bool> {
        self.require_request_uri_registration
    }

    /// Get response modes supported
    pub fn get_response_modes_supported(&self) -> Option<Vec<String>> {
        Some(self.response_modes_supported.clone()?.to_vec())
    }

    /// Get claim types supported
    pub fn get_claim_types_supported(&self) -> Vec<String> {
        self.claim_types_supported.clone().to_vec()
    }

    /// Get token endpoint auth methods supported
    pub fn get_token_endpoint_auth_methods_supported(&self) -> Option<Vec<String>> {
        Some(self.token_endpoint_auth_methods_supported.clone()?.to_vec())
    }

    /// Get introspection endpoint auth methods supported
    pub fn get_introspection_endpoint_auth_methods_supported(&self) -> Option<Vec<String>> {
        Some(
            self.introspection_endpoint_auth_methods_supported
                .clone()?
                .to_vec(),
        )
    }

    /// Get introspection endpoint auth signing algorithm values supported
    pub fn get_introspection_endpoint_auth_signing_alg_values_supported(
        &self,
    ) -> Option<Vec<String>> {
        Some(
            self.introspection_endpoint_auth_signing_alg_values_supported
                .clone()?
                .to_vec(),
        )
    }

    /// Get revocation endpoint auth methods supported
    pub fn get_revocation_endpoint_auth_methods_supported(&self) -> Option<Vec<String>> {
        Some(
            self.revocation_endpoint_auth_methods_supported
                .clone()?
                .to_vec(),
        )
    }

    /// Get revocation endpoint auth signing algorithm values supported
    pub fn get_revocation_endpoint_auth_signing_alg_values_supported(&self) -> Option<Vec<String>> {
        Some(
            self.revocation_endpoint_auth_signing_alg_values_supported
                .clone()?
                .to_vec(),
        )
    }

    /// Get other fields
    pub fn get_other_fields(&self) -> HashMap<String, serde_json::Value> {
        self.other_fields.clone()
    }

    /// Get Jwks
    pub fn get_jwks(&self) -> Option<Jwks> {
        self.jwks.clone()
    }

    /// Get registration endpoint
    pub fn get_registration_endpoint(&self) -> Option<String> {
        self.registration_endpoint.clone()
    }
}

impl Debug for Issuer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issuer")
            .field("issuer", &self.issuer)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("token_endpoint", &self.token_endpoint)
            .field("jwks_uri", &self.jwks_uri)
            .field("userinfo_endpoint", &self.userinfo_endpoint)
            .field("revocation_endpoint", &self.revocation_endpoint)
            .field(
                "claims_parameter_supported",
                &self.claims_parameter_supported,
            )
            .field("grant_types_supported", &self.grant_types_supported)
            .field(
                "request_parameter_supported",
                &self.request_parameter_supported,
            )
            .field(
                "request_uri_parameter_supported",
                &self.request_uri_parameter_supported,
            )
            .field(
                "require_request_uri_registration",
                &self.require_request_uri_registration,
            )
            .field("response_modes_supported", &self.response_modes_supported)
            .field("claim_types_supported", &self.claim_types_supported)
            .field(
                "token_endpoint_auth_methods_supported",
                &self.token_endpoint_auth_methods_supported,
            )
            .field(
                "introspection_endpoint_auth_methods_supported",
                &self.introspection_endpoint_auth_methods_supported,
            )
            .field(
                "introspection_endpoint_auth_signing_alg_values_supported",
                &self.introspection_endpoint_auth_signing_alg_values_supported,
            )
            .field(
                "revocation_endpoint_auth_methods_supported",
                &self.revocation_endpoint_auth_methods_supported,
            )
            .field(
                "revocation_endpoint_auth_signing_alg_values_supported",
                &self.revocation_endpoint_auth_signing_alg_values_supported,
            )
            .field("other_fields", &self.other_fields)
            .field("jwks", &self.jwks)
            .field("request_options", &"fn(&RequestOptions) -> RequestOptions")
            .finish()
    }
}

#[cfg(test)]
#[path = "../tests/issuer_test.rs"]
mod issuer_test;
