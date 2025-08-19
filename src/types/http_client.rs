//! # Http Client Interface for Custom Http Clients

use std::collections::HashMap;
use std::fmt::Debug;
use std::future;

use www_authenticate_parser::{parse_header, Challenge, CowStr, UniCase};

use crate::helpers::map_to_url_encoded;

/// The Http methods
#[derive(Debug, Default, Clone)]
#[cfg_attr(test, derive(PartialEq))]
#[allow(clippy::upper_case_acronyms)]
pub enum HttpMethod {
    /// Retrieve data from a server.
    #[default]
    GET,
    /// Submit data to a server.
    POST,
    /// Replace existing data on a server.
    PUT,
    /// Update a specific part of a resource.
    PATCH,
    /// Delete a resource from a server.
    DELETE,
    /// Retrieve only the headers of a resource.
    HEAD,
    /// Retrieve the capabilities of a server.
    OPTIONS,
    /// Echo the received request back to the client.
    TRACE,
    /// Establish a tunnel through a proxy server.
    CONNECT,
}

/// The expectations set by methods such as discover, token grant, callback etc...
#[derive(Debug, Clone, Copy)]
pub struct HttpResponseExpectations {
    /// Whether or not to expect body with the response.
    pub body: bool,
    /// Specifies if the response should be of type json and validates it.
    pub json: bool,
    /// Expected status code from the server.
    pub status_code: u16,
    /// Check for bearer token related errors.
    pub bearer: bool,
}

/// The client certificate
#[derive(Debug, Clone)]
pub struct ClientCertificate {
    /// Chain of PEM encoded X509 certificates, with the leaf certificate first.
    pub cert: String,
    /// PEM encoded PKCS #8 formatted private key for the leaf certificate.
    pub key: String,
}

/// The supported body types for an HTTP request.
#[derive(Debug)]
pub enum RequestBody {
    /// A map of form parameters encoded as application/x-www-form-urlencoded.
    Form(HashMap<String, String>),
    /// A JSON payload as a raw string with an application/json MIME type.
    Json(String),
    /// An arbitrary raw string payload.
    Raw(String),
}

impl RequestBody {
    /// Converts the request body to its string representation if possible.
    pub fn body_string(&self) -> Option<String> {
        match &self {
            RequestBody::Form(form) => Some(map_to_url_encoded(form)),
            RequestBody::Json(json) => Some(json.to_owned()),
            RequestBody::Raw(raw) => Some(raw.to_owned()),
        }
    }
}

/// Request is an internal struct used to create various OIDC requests.
#[derive(Debug)]
pub struct HttpRequest {
    /// Target URL of the request without query parameters.
    pub url: url::Url,
    /// The HTTP method to be used for the request.
    pub method: HttpMethod,
    /// Map of HTTP headers to be sent in the request.
    pub headers: HashMap<String, Vec<String>>,
    /// The optional payload to be included in the request.
    pub body: Option<RequestBody>,
    /// Indicates if the request requires Mutual TLS and a client certificate.
    pub mtls: bool,
    /// The certificate and key used for MTLS authentication.
    pub client_certificate: Option<ClientCertificate>,
    pub(crate) expectations: HttpResponseExpectations,
}

#[allow(unused)]
impl HttpRequest {
    /// Initializes a new request with default settings and a placeholder URL.
    pub(crate) fn new() -> Self {
        Self {
            url: url::Url::parse("about:blank").unwrap(),
            headers: HashMap::new(),
            method: HttpMethod::GET,
            body: None,
            client_certificate: None,
            mtls: false,
            expectations: HttpResponseExpectations {
                body: true,
                status_code: 200,
                json: true,
                bearer: false,
            },
        }
    }

    /// Finalizes the request by calculating and setting the content-length header.
    pub(crate) fn prepare(&mut self) {
        if let Some(body) = self.body.as_ref().and_then(|b| b.body_string()) {
            self.headers
                .insert("content-length".to_string(), vec![body.len().to_string()]);
        };
    }

    /// Sets the target URL for the request.
    pub(crate) fn url(mut self, url: url::Url) -> Self {
        self.url = url;
        self
    }

    /// Sets the HTTP method for the request.
    pub(crate) fn method(mut self, method: HttpMethod) -> Self {
        self.method = method;
        self
    }

    /// Appends a value to the specified header name.
    pub(crate) fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let name = name.into();
        let value = value.into();

        if let Some(values) = self.headers.get_mut(&name) {
            values.push(value);
        } else {
            let values = vec![value];
            self.headers.insert(name, values);
        }
        self
    }

    /// Overwrites any existing values for a specific header with a new list of values.
    pub(crate) fn header_replace(mut self, name: impl Into<String>, value: Vec<String>) -> Self {
        self.headers.insert(name.into(), value);
        self
    }

    /// Replaces the entire header map with the provided collection.
    pub(crate) fn headers(mut self, headers: HashMap<String, Vec<String>>) -> Self {
        self.headers = headers;
        self
    }

    /// Sets the request body to a JSON string and adds the appropriate content-type header.
    pub(crate) fn json(mut self, json: String) -> Self {
        self.headers.insert(
            "content-type".to_string(),
            vec!["application/json".to_string()],
        );

        self.body = Some(RequestBody::Json(json));

        self
    }

    /// Sets the request body as form-encoded data and adds the appropriate content-type header.
    pub(crate) fn form(mut self, form: HashMap<String, String>) -> Self {
        self.headers.insert(
            "content-type".to_string(),
            vec!["application/x-www-form-urlencoded".to_string()],
        );
        self.body(map_to_url_encoded(&form))
    }

    /// Sets a raw string as the request body.
    pub(crate) fn body(mut self, body: String) -> Self {
        self.body = Some(RequestBody::Raw(body));
        self
    }

    /// Configures whether the request should use Mutual TLS.
    pub(crate) fn mtls(mut self, mtls: bool) -> Self {
        self.mtls = mtls;
        self
    }

    /// Sets the expectation for whether a response body should be returned.
    pub(crate) fn expect_body(mut self, expect: bool) -> Self {
        self.expectations.body = expect;
        self
    }

    /// Sets the HTTP status code that the library expects for a successful operation.
    pub(crate) fn expect_status_code(mut self, code: u16) -> Self {
        self.expectations.status_code = code;
        self
    }

    /// Sets the expectation that the response body should be present and valid JSON.
    pub(crate) fn expect_json(mut self, expect: bool) -> Self {
        self.expectations.body = expect;
        self.expectations.json = expect;
        self
    }
}
/// Represents an HTTP response received from a server.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// The HTTP status code of the response.
    pub status_code: u16,
    /// The optional body content of the response as a string.
    pub body: Option<String>,
    /// The HTTP headers received in the response.
    pub headers: HashMap<String, Vec<String>>,
}

/// Represents the parsed components of a WWW-Authenticate header.
pub struct OpenIdWwwAuthenticateParsed(Challenge);

impl OpenIdWwwAuthenticateParsed {
    fn get_value(&self, key: &str) -> Option<&String> {
        match &self.0 {
            Challenge::Fields(challenge_fields) => challenge_fields.get(key),
            _ => None,
        }
    }

    /// Checks if the challenge follows the Token68 format.
    pub fn is_token68(&self) -> bool {
        matches!(self.0, Challenge::Token68(_))
    }
    /// Checks if the challenge contains a map of fields.
    pub fn is_challenge(&self) -> bool {
        matches!(self.0, Challenge::Fields(_))
    }

    /// Returns the raw Token68 string if present.
    pub fn token68(&self) -> Option<&String> {
        match &self.0 {
            Challenge::Token68(t68) => Some(t68),
            _ => None,
        }
    }

    /// Returns the "realm" value from the challenge fields.
    pub fn realm(&self) -> Option<&String> {
        self.get_value("realm")
    }

    /// Returns the "error" code from the challenge fields.
    pub fn error(&self) -> Option<&String> {
        self.get_value("error")
    }

    /// Returns the "error_description" text from the challenge fields.
    pub fn error_description(&self) -> Option<&String> {
        self.get_value("error_description")
    }

    /// Returns the "error_uri" value from the challenge fields.
    pub fn error_uri(&self) -> Option<&String> {
        self.get_value("error_uri")
    }

    /// Returns the "algs" parameter value from the challenge fields.
    pub fn algs(&self) -> Option<&String> {
        self.get_value("algs")
    }

    /// Returns the "scope" parameter value from the challenge fields.
    pub fn scope(&self) -> Option<&String> {
        self.get_value("scope")
    }

    /// Returns the "resource_metadata" value from the challenge fields.
    pub fn resource_metadata(&self) -> Option<&String> {
        self.get_value("resource_metadata")
    }
}

impl HttpResponse {
    /// Extracts the value of the "content-type" header from the response.
    pub fn content_type_header(&self) -> Option<&String> {
        self.headers.get("content-type").and_then(|ct| ct.first())
    }

    /// Extracts the value of the "dpop-nonce" header from the response.
    pub fn dpop_nonce_header(&self) -> Option<&String> {
        self.headers.get("dpop-nonce").and_then(|ct| ct.first())
    }

    /// Parses the "www-authenticate" headers into a map of schemes and their associated challenges.
    pub fn parsed_www_authenticate_errors(
        &self,
    ) -> Option<HashMap<UniCase<CowStr>, OpenIdWwwAuthenticateParsed>> {
        let www_headers = self.headers.get("www-authenticate");

        if let Some(www_headers) = www_headers {
            let mut map = HashMap::new();
            for header_val in www_headers {
                if let Ok((scheme, challenge)) = parse_header(header_val) {
                    map.insert(scheme, OpenIdWwwAuthenticateParsed(challenge));
                }
            }

            if !map.is_empty() {
                return Some(map);
            }
        }

        None
    }
}

/// This trait defines the interface for making HTTP requests used by the OpenID library.
pub trait OidcHttpClient {
    /// Retrieves the client certificate for Mutual TLS if required by the request.
    fn get_client_certificate(
        &self,
        _req: &HttpRequest,
    ) -> impl std::future::Future<Output = Option<ClientCertificate>> + Send {
        future::ready(None)
    }

    /// Executes the provided HTTP request and returns the response or an error string.
    fn request(
        &self,
        req: HttpRequest,
    ) -> impl std::future::Future<Output = Result<HttpResponse, String>> + Send;
}
