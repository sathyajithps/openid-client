use std::{collections::HashMap, time::Duration};

use reqwest::{header::HeaderMap, Method, StatusCode};

/// `type RequestInterceptor` is the alias for the closure that can be passed through
/// one of several methods that will be executed every time a request is being made.
pub type RequestInterceptor = Box<dyn FnMut(&Request) -> RequestOptions>;

/// # Request
/// Request is an internal struct that is used by each OIDC protocol methods.
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
    /// Creates a new instance of Response from [reqwest::blocking::Response]
    pub fn from(response: reqwest::blocking::Response) -> Self {
        let status = response.status();
        let headers = response.headers().clone();
        let body_result = response.text();
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

    /// Creates a new instance of Response from [reqwest::Response]
    pub async fn from_async(response: reqwest::Response) -> Self {
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

/// # RequestOptions
/// This struct is the return type of the request interceptor that can be passed to various methods
/// such as:
/// 1. [crate::Issuer::webfinger_with_interceptor_async]
/// 2. [crate::Issuer::webfinger_with_interceptor]
/// 3. [crate::Issuer::discover_with_interceptor_async]
/// 4. [crate::Issuer::discover_with_interceptor]
#[derive(Debug)]
pub struct RequestOptions {
    /// Headers that are tobe appended with the request that is going to be made
    pub headers: HeaderMap,
    /// Request timeout
    pub timeout: Duration,
}
