//! # Http Client Interface for Custom Http Clients

use std::collections::HashMap;
use std::fmt::Debug;
use std::future;

use url::Url;

use crate::helpers::string_map_to_form_url_encoded;

/// The Http methods
#[derive(Debug, Default, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub enum HttpMethod {
    /// The GET method is used to retrieve data from a server.
    #[default]
    GET,
    /// The POST method is used to submit data to a server.
    POST,
    /// The PUT method is used to replace all existing data on a server with the provided data.
    PUT,
    /// The PATCH method is used to update a specific part of a resource on a server.
    PATCH,
    /// The DELETE method is used to delete a resource from a server.
    DELETE,
    /// The HEAD method is used to retrieve only the headers of a resource, without the actual data.
    HEAD,
    /// The OPTIONS method is used to retrieve the capabilities of a server.
    OPTIONS,
    /// The TRACE method is used to echo the received request back to the client. (Rarely used)
    TRACE,
    /// The CONNECT method is used to establish a tunnel through the proxy server. (For use with secure proxies)
    CONNECT,
}

/// The expectations set by methods such as discover, token grant, callback etc...
#[derive(Debug, Clone, Copy)]
pub struct HttpResponseExpectations {
    /// Whether or not to expect body with the response
    pub body: bool,
    /// Specifies if the request is using bearer auth, and checks for bearer token related errors
    pub bearer: bool,
    /// Specifies if the response should be of type json and validates it
    pub json_body: bool,
    /// Expected status code from the server
    pub status_code: u16,
}

/// The client certificate
#[derive(Debug)]
pub struct ClientCertificate {
    /// Client public certificate in pem format.
    pub cert: String,
    /// Client private certificate in pem format.
    pub key: String,
}

/// # Request
/// Request is an internal struct used to create various OIDC requests.
#[derive(Debug)]
pub struct HttpRequest {
    /// Url of the request without query params
    pub url: Url,
    /// Http method of the request
    pub method: HttpMethod,
    /// Headers that are sent in the request
    pub headers: HashMap<String, Vec<String>>,
    /// The request body to be sent
    pub body: Option<String>,
    /// Specifies if the request is MTLS and needs client certificate
    pub mtls: bool,
    /// Client certificate to be used in the request
    pub client_certificate: Option<ClientCertificate>,
    /// Expectations to be fullfilled by the response
    pub(crate) expectations: HttpResponseExpectations,
}

impl HttpRequest {
    pub(crate) fn new() -> Self {
        Self {
            url: Url::parse("about:blank").unwrap(),

            headers: HashMap::new(),
            method: HttpMethod::GET,
            body: None,
            client_certificate: None,
            mtls: false,
            expectations: HttpResponseExpectations {
                body: true,
                bearer: false,
                status_code: 200,
                json_body: true,
            },
        }
    }

    pub(crate) fn url(mut self, url: Url) -> Self {
        self.url = url;
        self
    }

    pub(crate) fn method(mut self, method: HttpMethod) -> Self {
        self.method = method;
        self
    }

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

    pub(crate) fn header_replace(mut self, name: impl Into<String>, value: Vec<String>) -> Self {
        self.headers.insert(name.into(), value);
        self
    }

    pub(crate) fn headers(mut self, headers: HashMap<String, Vec<String>>) -> Self {
        self.headers = headers;
        self
    }

    pub(crate) fn json(mut self, json: String) -> Self {
        self.headers.insert(
            "content-type".to_string(),
            vec!["application/json".to_string()],
        );
        self.body(json)
    }

    pub(crate) fn form(mut self, form: HashMap<String, String>) -> Self {
        let form_body = string_map_to_form_url_encoded(&form).unwrap();
        self.headers.insert(
            "content-type".to_string(),
            vec!["application/x-www-form-urlencoded".to_string()],
        );
        self.body(form_body)
    }

    pub(crate) fn body(mut self, body: String) -> Self {
        self.headers.insert(
            "content-length".to_string(),
            vec![body.as_bytes().len().to_string()],
        );
        self.body = Some(body);
        self
    }

    pub(crate) fn mtls(mut self, mtls: bool) -> Self {
        self.mtls = mtls;
        self
    }

    pub(crate) fn expect_body(mut self, expect: bool) -> Self {
        self.expectations.body = expect;
        self
    }

    pub(crate) fn expect_status_code(mut self, code: u16) -> Self {
        self.expectations.status_code = code;
        self
    }

    pub(crate) fn expect_json_body(mut self, expect: bool) -> Self {
        self.expectations.json_body = expect;
        self
    }

    pub(crate) fn expect_bearer(mut self, bearer: bool) -> Self {
        self.expectations.bearer = bearer;
        self
    }
}

/// Represents an HTTP response received from a server.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// The HTTP status code of the response (e.g., 200 for success, 404 for Not Found).
    pub status_code: u16,
    /// The content type header
    pub content_type: Option<String>,
    /// The www authenticate header
    pub www_authenticate: Option<String>,
    /// The dpop nonce
    pub dpop_nonce: Option<String>,
    /// The optional body content of the response. None if there is no body content (String).
    pub body: Option<String>,
}

/// This trait defines the interface for making HTTP requests used by the OpenID library.
/// Users who need custom HTTP clients need to implement this trait.
pub trait OidcHttpClient {
    /// Gets the client certificate for the current request. Return none if the request does not need mtls
    fn get_client_certificate(
        &self,
        _req: &HttpRequest,
    ) -> impl std::future::Future<Output = Option<ClientCertificate>> + Send {
        future::ready(None)
    }

    /// Makes an HTTP request using the provided HttpRequest object.
    ///
    /// This function takes an `HttpRequest` object as input and returns a future
    /// implementing `std::future::Future<Output = Result<HttpResponse, String>>`.
    /// The future resolves to either a `Result<HttpResponse, String>`.
    ///  * On success, the result is `Ok(HttpResponse)` containing the HTTP response.
    ///  * On error, the result is `Err(String)` with an error message describing the failure.
    ///
    /// This function allows the library to be agnostic to the specific HTTP client
    /// implementation used, as long as it implements this trait.
    fn request(
        &self,
        req: HttpRequest,
    ) -> impl std::future::Future<Output = Result<HttpResponse, String>> + Send;
}
