use std::{collections::HashMap, time::Duration};

use reqwest::{header::HeaderMap, Method, StatusCode};

#[derive(Debug)]
pub struct Request {
    pub url: String,
    pub expected: StatusCode,
    pub method: reqwest::Method,
    pub expect_body: bool,
    pub headers: HeaderMap,
    pub search_params: HashMap<String, Vec<String>>,
}

impl Default for Request {
    fn default() -> Self {
        Self {
            expect_body: true,
            expected: StatusCode::OK,
            headers: HeaderMap::default(),
            method: Method::GET,
            url: "".to_string(),
            search_params: HashMap::new(),
        }
    }
}

impl Request {
    pub fn get_reqwest_query(&self) -> Vec<(String, String)> {
        let mut query_list: Vec<(String, String)> = vec![];

        for (k, v) in &self.search_params {
            for val in v {
                query_list.push((k.clone(), val.to_string()))
            }
        }

        query_list
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

#[derive(Debug)]
pub struct RequestOptions {
    pub headers: HeaderMap,
    pub timeout: Duration,
}
