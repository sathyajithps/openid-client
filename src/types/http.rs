use std::{collections::HashMap, fmt::Debug, time::Duration};

use reqwest::{header::HeaderMap, Method, StatusCode};
use serde_json::Value;
use url::Url;

use crate::helpers::convert_json_to;

use super::OidcClientError;

/// # Request
/// Request is an internal struct used to create various OIDC requests.
#[derive(Debug)]
pub struct Request {
    /// Url of the request without query params
    pub url: String,
    /// Expected status code from the server
    pub expected: StatusCode,
    /// Http method of the request
    pub method: Method,
    /// Whether or not to expect body with the response
    pub expect_body: bool,
    /// Specifies if the request is using bearer auth, and checks for bearer token related errors
    pub bearer: bool,
    /// Headers that are sent in the request
    pub headers: HeaderMap,
    /// Query Params that are send with the request
    pub search_params: HashMap<String, Vec<String>>,
    /// The request body to be sent
    pub json: Option<Value>,
    /// The request form body to be sent
    pub form: Option<HashMap<String, Value>>,
    /// The request body to be sent
    pub body: Option<String>,
    /// Specifies if the response should be of type json and validates it
    pub expect_body_to_be_json: bool,
    /// Specifies if the request is MTLS and needs client certificate
    pub mtls: bool,
}

impl Default for Request {
    fn default() -> Self {
        Self {
            expect_body: true,
            bearer: false,
            expected: StatusCode::OK,
            headers: HeaderMap::default(),
            method: Method::GET,
            url: "".to_string(),
            search_params: HashMap::new(),
            json: None,
            form: None,
            body: None,
            expect_body_to_be_json: true,
            mtls: false,
        }
    }
}

impl Request {
    /// Converts `search_params` to a [reqwest] compatible query params format
    pub(crate) fn get_reqwest_query(&self) -> Vec<(String, String)> {
        let mut query_list: Vec<(String, String)> = vec![];

        for (k, v) in &self.search_params {
            for val in v {
                query_list.push((k.clone(), val.to_string()))
            }
        }

        query_list
    }

    pub(crate) fn merge_form(&mut self, request: &Self) {
        match (&mut self.form, &request.form) {
            (None, Some(_)) => self.form = request.form.clone(),
            (Some(own_form), Some(other_form)) => {
                for (k, v) in other_form {
                    own_form.insert(k.to_string(), v.to_owned());
                }
            }
            (None, None) | (Some(_), None) => {}
        }
    }

    pub(crate) fn merge_headers(&mut self, request: &Self) {
        for (k, v) in &request.headers {
            self.headers.insert(k, v.clone());
        }
    }
}

/// # Response
/// Response is the abstracted version of the [reqwest] Response (async and blocking).
#[derive(Debug, Clone)]
pub struct Response {
    /// Body from the response
    pub body: Option<String>,
    /// Status code of the response
    pub status: StatusCode,
    /// Response headers from the server
    pub headers: HeaderMap,
}

impl Response {
    /// Converts to [Value]
    pub fn body_to_json_value(&self) -> Result<Value, OidcClientError> {
        if let Some(body_string) = &self.body {
            if let Ok(v) = convert_json_to::<Value>(body_string) {
                return Ok(v);
            }
        }
        Err(OidcClientError::new_error(
            "could not convert body to serde::json value",
            None,
        ))
    }

    /// Creates a new instance of Response from [reqwest::Response]
    pub(crate) async fn from_async(response: reqwest::Response) -> Self {
        let status = response.status();
        let headers = response.headers().clone();
        let body_result = response.text().await;
        let mut body: Option<String> = None;
        if let Ok(body_string) = body_result {
            if !body_string.is_empty() {
                body = Some(body_string);
            }
        }

        Self {
            body,
            status,
            headers,
        }
    }
}

/// # Request Interceptor
/// Type is a [Box]'ed [Interceptor] trait type.
pub type RequestInterceptor = Box<dyn Interceptor>;

/// # Lookup
/// Intention with this lookup is primarily for testing by
/// redirecting all requests to `localhost (127.0.0.1)` in combination with
/// the port of mock server.
///
/// *The url host, port and scheme will be swapped when building the request. No functionality is affected.*
///
/// ### *Example: *
///
/// ```
///     #[derive(Debug)]
///     struct CustomLookup;
///
///     impl Lookup for CustomLookup {
///          fn lookup(&mut self, _url: &Url) -> Url {
///              Url::parse("http://your-test-url:1234").unwrap()
///          }
///     }
///
///     RequestOptions {
///         lookup: Some(Box::new(CustomLookup{})),
///         ..Default::default()
///     }
/// ```
pub trait Lookup: Debug {
    /// The url with path (no query params) of the request url is passed as the `url`
    /// parameter in return expects a [Url] back.
    ///
    /// - The Scheme and host is required from the returned [Url]. Returns
    ///   an error otherwise. Port is optional
    ///
    /// - The entire url is just passed for reference.
    ///   Only the host:port will be replaced. Not the path.
    ///
    /// ### *Example:*
    ///
    /// ```
    ///     fn lookup(&mut self, _url: &Url) -> Url {
    ///         Url::parse("http://your-test-url:1234").unwrap()
    ///     }
    /// ```
    fn lookup(&mut self, url: &Url) -> Url;
}

/// # Interceptor
pub trait Interceptor: Debug {
    /// This method which is called before making a request
    fn intercept(&mut self, req: &Request) -> RequestOptions;

    /// Clones the [Interceptor]
    fn clone_box(&self) -> Box<dyn Interceptor>;
}

/// # RequestOptions
/// This struct is the return type of the [`Interceptor::intercept()`]
#[derive(Default, Debug)]
pub struct RequestOptions {
    /// ### Headers that are to be appended with the request that is going to be made
    pub headers: HeaderMap,
    /// ### Request timeout
    pub timeout: Duration,
    /// ### Client public certificate in pem format.
    /// The `client_crt` is ignored if `client_key` is not present
    pub client_crt: Option<String>,
    /// ### Client private certificate in pem format.
    /// The `client_key` is ignored if `client_crt` is not present
    pub client_key: Option<String>,
    /// ### Client certificate in pkcs 12 format `.p12` or `.pfx`
    /// Make sure to pass `client_pkcs_12_passphrase` if the
    /// certificate is protected.
    pub client_pkcs_12: Option<String>,
    /// Passphrase for pkcs_12 certificate
    pub client_pkcs_12_passphrase: Option<String>,
    /// ### Server certificate in pem format
    /// Useful when testing out with a self signed certificate and
    /// cannot switch on the `danger_accept_invalid_certs` property
    pub server_crt: Option<String>,
    /// ### Lookup
    /// [Lookup] trait allows you to resolve any url to a custom [Url].
    pub lookup: Option<Box<dyn Lookup>>,
    /// ### Accept invalid server certificates
    /// Accepts self signed or unverified or expired certificates.
    /// Use with caution.
    pub danger_accept_invalid_certs: bool,
}
