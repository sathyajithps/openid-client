//! Issuer struct contains the discovered OpenID Connect Issuer Metadata.

use core::fmt::Debug;
use std::collections::HashMap;
use std::fmt::Formatter;

use crate::helpers::{convert_json_to, validate_url, webfinger_normalize};
use crate::http::{default_request_interceptor, request, request_async};
use crate::types::{
    IssuerMetadata, OidcClientError, Request, RequestOptions, Response, WebFingerResponse,
};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Method, StatusCode};

/// Holds all the discovered values from the OIDC Issuer
pub struct Issuer {
    /// Discovered issuer uri.
    pub issuer: String,
    /// OpenID Connect [Authorization Endpoint](https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint).
    pub authorization_endpoint: Option<String>,
    /// OpenID Connect [Token Endpoint](https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint).
    pub token_endpoint: Option<String>,
    /// URL of the authorization server's JWK Set. [See](https://www.rfc-editor.org/rfc/rfc8414.html#section-2).
    pub jwks_uri: Option<String>,
    /// OpenID Connect [Userinfo Endpoint](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo).
    pub userinfo_endpoint: Option<String>,
    /// Endpoint for revoking refresh tokes and access tokens. [Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414.html#section-2).
    pub revocation_endpoint: Option<String>,
    /// Claims supported by the Authorization Server
    pub claims_parameter_supported: Option<bool>,
    /// OAuth 2.0 Grant Types supported by the Authorization Server. [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591).
    pub grant_types_supported: Option<Vec<String>>,
    /// Indicates whether request object is supported by Authorization Server. [OIDC Request Object](https://openid.net/specs/openid-connect-core-1_0.html#RequestObject).
    pub request_parameter_supported: Option<bool>,
    /// Indicates whether request object by reference is supported by Authorization Server. [OIDC Request Object by Reference](https://openid.net/specs/openid-connect-core-1_0.html#RequestUriParameter).
    pub request_uri_parameter_supported: Option<bool>,
    /// Whether a request uri has to be pre registered with Authorization Server.
    pub require_request_uri_registration: Option<bool>,
    /// OAuth 2.0 Response Mode values that Authorization Server supports. [Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414.html#section-2).
    pub response_modes_supported: Option<Vec<String>>,
    /// Claim Types supported. [OIDC Claim types](https://openid.net/specs/openid-connect-core-1_0.html#ClaimTypes).
    pub claim_types_supported: Vec<String>,
    /// Client Authentication methods supported by Token Endpoint. [Client Authentication](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication)
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
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
    /// Extra key values
    pub other_fields: HashMap<String, serde_json::Value>,
    request_interceptor: Box<dyn FnMut(&Request) -> RequestOptions>,
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
    ///     let issuer = Issuer::new(metadata);
    /// }
    /// ```
    ///
    /// No OIDC Discovery defaults are set if Issuer is made through this method.
    ///
    /// If no introspection/revocation endpoint auth methods or algorithms are specified,
    /// value of token endpoint auth methods and algorithms are used as the the value for the said
    /// properties.
    pub fn new(metadata: IssuerMetadata) -> Self {
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
            request_interceptor: Box::new(default_request_interceptor),
        }
    }
}

/// OIDC [Issuer Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery)
impl Issuer {
    /// # Discover OIDC Issuer
    ///
    /// `This is a blocking method.` Checkout [Issuer::discover_async] for async version.
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
    pub fn discover(issuer: &str) -> Result<Issuer, OidcClientError> {
        Issuer::discover_with_interceptor(issuer, Box::new(default_request_interceptor))
    }

    /// # Discover OIDC Issuer with a request interceptor
    ///
    /// > `This is a blocking method.` Checkout [Issuer::discover_with_interceptor_async] for async version.
    ///
    /// Allows you to pass in a closure that will be called for every request.
    /// First parameter is the actual request that is being processed. See [Request].
    /// The expected return type is of type [RequestOptions] with custom headers and the timeout.
    ///
    /// ```
    /// # use openid_client::{Issuer, HeaderMap, HeaderValue, RequestOptions, Request};
    /// # use std::time::Duration;
    ///
    /// fn main(){
    ///     let interceptor = |_request: &Request| {
    ///                     let mut headers = HeaderMap::new();
    ///                     headers.append("testHeader", HeaderValue::from_static("testHeaderValue"));
    ///
    ///                     RequestOptions {
    ///                         headers,
    ///                         timeout: Duration::from_millis(3500),
    ///                     }
    ///                 };
    ///
    ///     let issuer = Issuer::discover_with_interceptor("https://auth.example.com", Box::new(request_options)).unwrap();
    /// }
    /// ```
    /// Headers that are returned with request options are appended to the headers of the request.
    /// If there are duplicate headers, all values are appended to the header like so:
    ///     `header: value1, value2, value3 ....`
    pub fn discover_with_interceptor(
        issuer: &str,
        mut interceptor: Box<dyn FnMut(&Request) -> RequestOptions>,
    ) -> Result<Issuer, OidcClientError> {
        let req = Self::build_discover_request(issuer)?;

        let res = request(req, &mut interceptor)?;

        Self::process_discover_response(res, interceptor)
    }

    /// # Discover OIDC Issuer
    ///
    /// `This is an async method.` Checkout [Issuer::discover] for blocking version.
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
    pub async fn discover_async(issuer: &str) -> Result<Issuer, OidcClientError> {
        Self::discover_with_interceptor_async(issuer, Box::new(default_request_interceptor)).await
    }

    /// # Discover OIDC Issuer with a request interceptor
    ///
    /// > `This is an async method.` Checkout [Issuer::discover_with_interceptor] for blocking version.
    ///
    /// Allows you to pass in a closure that will be called for every request.
    /// First parameter is the actual request that is being processed. See [Request].
    /// The expected return type is of type [RequestOptions] with custom headers and the timeout.
    ///
    /// ```
    /// # use openid_client::{Issuer, HeaderMap, HeaderValue, RequestOptions, Request};
    /// # use std::time::Duration;
    ///
    /// #[tokio::main]
    /// fn main(){
    ///     let interceptor = |_request: &Request| {
    ///                     let mut headers = HeaderMap::new();
    ///                     headers.append("testHeader", HeaderValue::from_static("testHeaderValue"));
    ///
    ///                     RequestOptions {
    ///                         headers,
    ///                         timeout: Duration::from_millis(3500),
    ///                     }
    ///                 };
    ///
    ///     let issuer = Issuer::discover_with_interceptor_async("https://auth.example.com", Box::new(request_options)).unwrap();
    /// }
    /// ```
    /// Headers that are returned with request options are appended to the headers of the request.
    /// If there are duplicate headers, all values are appended to the header like so:
    ///     `header: value1, value2, value3 ....`
    pub async fn discover_with_interceptor_async(
        issuer: &str,
        mut request_interceptor: Box<dyn FnMut(&Request) -> RequestOptions>,
    ) -> Result<Issuer, OidcClientError> {
        let req = Self::build_discover_request(issuer)?;

        let res = request_async(req, &mut request_interceptor).await?;

        Self::process_discover_response(res, request_interceptor)
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
        request_options: Box<dyn FnMut(&Request) -> RequestOptions>,
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
        issuer.request_interceptor = request_options;
        Ok(issuer)
    }
}

/// OIDC [Issuer Webfinger Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery)
impl Issuer {
    /// # Webfinger OIDC Issuer Discovery
    ///
    /// `This is a blocking method.` Checkout [Issuer::webfinger_async] for async version.
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
    pub fn webfinger(input: &str) -> Result<Issuer, OidcClientError> {
        Issuer::webfinger_with_interceptor(input, Box::new(default_request_interceptor))
    }

    /// # Webfinger OIDC Issuer Discovery with request interceptor
    ///
    /// `This is a blocking method.` Checkout [Issuer::webfinger_with_interceptor_async] for async version.
    ///
    /// Discover an OIDC Issuer using the user email, url, url with port syntax or acct syntax.
    ///
    /// Allows you to pass in a closure as a second argument that will be called for every request.
    /// First parameter is the actual request that is being processed. See [Request].
    /// The expected return type is of type [RequestOptions] with custom headers and the timeout.
    ///
    /// ```
    /// # use openid_client::{Issuer, Request, HeaderMap, HeaderValue, RequestOptions};
    /// # use std::time::Duration;
    ///
    /// fn main(){
    ///     let interceptor = |_request: &Request| {
    ///                     let mut headers = HeaderMap::new();
    ///                     headers.append("testHeader", HeaderValue::from_static("testHeaderValue"));
    ///
    ///                     RequestOptions {
    ///                         headers,
    ///                         timeout: Duration::from_millis(3500),
    ///                     }
    ///                 };
    ///     let issuer = Issuer::webfinger_with_interceptor("joe@auth.example.com", Box::new(interceptor)).unwrap();
    /// }
    /// ```
    pub fn webfinger_with_interceptor(
        input: &str,
        mut request_options: Box<dyn FnMut(&Request) -> RequestOptions>,
    ) -> Result<Issuer, OidcClientError> {
        let req = Self::build_webfinger_request(input)?;

        let res = request(req, &mut request_options)?;

        let expected_issuer = Self::process_webfinger_response(res)?;

        let issuer_result = Issuer::discover_with_interceptor(&expected_issuer, request_options);

        Self::process_webfinger_issuer_result(issuer_result, expected_issuer)
    }

    /// # Webfinger OIDC Issuer Discovery
    ///
    /// `This is an async method.` Checkout [Issuer::webfinger] for blocking version.
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
    pub async fn webfinger_async(input: &str) -> Result<Issuer, OidcClientError> {
        Issuer::webfinger_with_interceptor_async(input, Box::new(default_request_interceptor)).await
    }

    /// # Webfinger OIDC Issuer Discovery with request interceptor
    ///
    /// `This is an async method.` Checkout [Issuer::webfinger_with_interceptor] for blocking version.
    ///
    /// Discover an OIDC Issuer using the user email, url, url with port syntax or acct syntax.
    ///
    /// Allows you to pass in a closure as a second argument that will be called for every request.
    /// First parameter is the actual request that is being processed. See [Request].
    /// The expected return type is of type [RequestOptions] with custom headers and the timeout.
    ///
    /// ```
    /// use openid_client::{Issuer, Request, HeaderMap, HeaderValue, RequestOptions};
    /// use std::time::Duration;
    ///
    ///#[tokio::main]
    ///async fn main(){
    ///     let interceptor = |_request: &Request| {
    ///                     let mut headers = HeaderMap::new();
    ///                     headers.append("testHeader", HeaderValue::from_static("testHeaderValue"));
    ///
    ///                     RequestOptions {
    ///                         headers,
    ///                         timeout: Duration::from_millis(3500),
    ///                     }
    ///                 };
    ///     let issuer = Issuer::webfinger_with_interceptor_async("joe@auth.example.com", Box::new(interceptor)).await.unwrap();
    /// }
    /// ```
    pub async fn webfinger_with_interceptor_async(
        input: &str,
        mut request_options: Box<dyn FnMut(&Request) -> RequestOptions>,
    ) -> Result<Issuer, OidcClientError> {
        let req = Self::build_webfinger_request(input)?;

        let res = request_async(req, &mut request_options).await?;

        let expected_issuer = Self::process_webfinger_response(res)?;

        let issuer_result =
            Issuer::discover_with_interceptor_async(&expected_issuer, request_options).await;

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
            expected: StatusCode::OK,
            expect_body: true,
            search_params,
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
            .field("request_options", &"fn(&String) -> RequestOptions")
            .finish()
    }
}

#[cfg(test)]
#[path = "./tests/issuer_test.rs"]
mod issuer_test;
