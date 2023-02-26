use std::time::Duration;

use reqwest::{header::HeaderMap, Method, StatusCode};

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
}

pub struct RequestOptions {
    pub headers: HeaderMap,
    pub timeout: Duration,
}