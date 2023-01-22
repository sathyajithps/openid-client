use crate::errors::OidcClientError;
use json::JsonValue;
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Method, StatusCode,
};
use std::time::Duration;

#[derive(Debug)]
pub struct Request {
    pub url: String,
    pub expected: StatusCode,
    pub method: reqwest::Method,
    pub expect_body: bool,
    pub headers: HeaderMap,
}

impl Request {
    pub fn default() -> Self {
        Self {
            expect_body: true,
            expected: StatusCode::OK,
            headers: HeaderMap::default(),
            method: Method::GET,
            url: "".to_string(),
        }
    }
}

#[derive(Debug)]
pub struct Response {
    pub body: Option<String>,
    pub status: StatusCode,
    pub headers: HeaderMap,
}

impl Response {
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

    pub fn to_json(&self) -> Option<JsonValue> {
        if let Some(body_string) = &self.body {
            if let Ok(body_json) = json::parse(body_string.as_str()) {
                return Some(body_json);
            }
        }
        None
    }
}

pub struct RequestOptions {
    pub headers: HeaderMap,
    pub timeout: Duration,
}

pub fn default_request_options(_request: &Request) -> RequestOptions {
    let mut headers = HeaderMap::new();
    headers.append(
        "User-Agent",
        HeaderValue::from_static("openid-client/0.1.0"),
    );
    RequestOptions {
        headers,
        timeout: Duration::from_millis(3500),
    }
}

pub fn request(
    request: Request,
    request_options: &mut Box<dyn FnMut(&Request) -> RequestOptions>,
) -> Result<Response, OidcClientError> {
    let options = request_options(&request);
    let client = reqwest::blocking::Client::new();

    let mut headers = HeaderMap::new();
    request
        .headers
        .iter()
        .for_each(|(header_name, header_values)| {
            headers.append(header_name, header_values.into());
            ()
        });
    options
        .headers
        .iter()
        .for_each(|(header_name, header_values)| {
            headers.append(header_name, header_values.into());
            ()
        });

    let res = client
        .request(request.method, request.url)
        .headers(headers)
        .timeout(options.timeout)
        .send();

    if res.is_err() {
        return Err(OidcClientError::new(
            "OPError",
            "unknown_error",
            "error while sending the request",
            None,
        ));
    }

    let response = Response::from(res.unwrap());

    if response.status != request.expected {
        if let Some(JsonValue::Object(obj)) = &response.to_json() {
            if obj["error"].is_string() && obj["error"].as_str().unwrap().len() > 0 {
                return Err(OidcClientError::new(
                    "OPError",
                    obj["error"].as_str().unwrap(),
                    obj["error_description"].as_str().unwrap(),
                    Some(response),
                ));
            }
        }

        return Err(OidcClientError::new(
            "OPError",
            "server_error",
            format!("expected {}, got: {}", request.expected, response.status).as_str(),
            Some(response),
        ));
    }

    if request.expect_body && response.body.is_none() {
        return Err(OidcClientError::new(
            "OPError",
            "server_error",
            format!(
                "expected {} with body but no body was returned",
                request.expected
            )
            .as_str(),
            None,
        ));
    }

    let json_body_result = response.to_json();

    if request.expect_body && json_body_result.is_none() {
        return Err(OidcClientError {
            name: "TypeError".to_string(),
            error: "parse_error".to_string(),
            error_description: "unexpected body type".to_string(),
            response: Some(response),
        });
    }

    Ok(response)
}
