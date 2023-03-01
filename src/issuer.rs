use core::fmt::Debug;
use std::collections::HashMap;
use std::fmt::Formatter;

use crate::helpers::{convert_json_to, validate_url, webfinger_normalize};
use crate::http::{default_request_options, request};
use crate::types::{IssuerMetadata, OidcClientError, Request, RequestOptions, WebFingerResponse};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Method, StatusCode};

pub struct Issuer {
    pub issuer: String,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub revocation_endpoint: Option<String>,
    pub claims_parameter_supported: bool,
    pub grant_types_supported: Vec<String>,
    pub request_parameter_supported: bool,
    pub request_uri_parameter_supported: bool,
    pub require_request_uri_registration: bool,
    pub response_modes_supported: Vec<String>,
    pub claim_types_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    request_options: Box<dyn FnMut(&Request) -> RequestOptions>,
}

impl Issuer {
    fn default() -> Self {
        Self {
            claims_parameter_supported: false,
            grant_types_supported: vec![
                String::from("authorization_code"),
                String::from("implicit"),
            ],
            request_parameter_supported: false,
            request_uri_parameter_supported: true,
            require_request_uri_registration: false,
            response_modes_supported: vec![String::from("query"), String::from("fragment")],
            claim_types_supported: vec![String::from("normal")],
            token_endpoint_auth_methods_supported: vec![String::from("client_secret_basic")],
            issuer: "".to_string(),
            authorization_endpoint: None,
            token_endpoint: None,
            jwks_uri: None,
            userinfo_endpoint: None,
            revocation_endpoint: None,
            request_options: Box::new(default_request_options),
        }
    }

    fn from(metadata: IssuerMetadata) -> Self {
        Self {
            issuer: metadata.issuer,
            authorization_endpoint: metadata.authorization_endpoint,
            token_endpoint: metadata.token_endpoint,
            jwks_uri: metadata.jwks_uri,
            userinfo_endpoint: metadata.userinfo_endpoint,
            revocation_endpoint: metadata.revocation_endpoint,
            ..Issuer::default()
        }
    }

    pub fn discover(issuer: &str) -> Result<Issuer, OidcClientError> {
        Issuer::discover_with_interceptor(issuer, Box::new(default_request_options))
    }

    pub fn discover_with_interceptor(
        issuer: &str,
        mut request_options: Box<dyn FnMut(&Request) -> RequestOptions>,
    ) -> Result<Issuer, OidcClientError> {
        let url_result = validate_url(issuer);
        if url_result.is_err() {
            return Err(url_result.unwrap_err());
        }
        let mut url = url_result.unwrap();
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

        let response = request(req, &mut request_options);
        if response.is_err() {
            return Err(response.unwrap_err());
        }

        let res = response.unwrap();

        // remove this and check on convert to json result
        if res.body.is_none() {
            return Err(OidcClientError::new(
                "OPError",
                "invalid_issuer_metadata",
                "invalid issuer metadata",
                Some(res),
            ));
        }

        let issuer_metadata: IssuerMetadata = convert_json_to(&res.body.unwrap()).unwrap();
        let mut issuer = Issuer::from(issuer_metadata);
        issuer.request_options = request_options;
        return Ok(issuer);
    }

    pub fn webfinger(input: &str) -> Result<Issuer, OidcClientError> {
        Issuer::webfinger_with_interceptor(input, Box::new(default_request_options))
    }

    pub fn webfinger_with_interceptor(
        input: &str,
        mut request_options: Box<dyn FnMut(&Request) -> RequestOptions>,
    ) -> Result<Issuer, OidcClientError> {
        let resource = webfinger_normalize(input);
        let mut host: Option<String> = None;
        if resource.starts_with("acct:") {
            let split: Vec<&str> = resource.split("@").collect();
            host = Some(split[1].to_string());
        } else if resource.starts_with("https://") {
            let url_result = validate_url(&resource);

            if url_result.is_err() {
                return Err(url_result.unwrap_err());
            }

            let url = url_result.unwrap();

            if let Some(host_str) = url.host_str() {
                if let Some(port) = url.port() {
                    host = Some(host_str.to_string() + &format!(":{}", port))
                } else {
                    host = Some(host_str.to_string());
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

        let req = Request {
            url: web_finger_url,
            method: Method::GET,
            headers,
            expected: StatusCode::OK,
            expect_body: true,
            search_params,
        };

        let response_result = request(req, &mut request_options);

        if response_result.is_err() {
            return Err(response_result.unwrap_err());
        }

        let response = response_result.unwrap();

        let webfinger_response_result: Result<WebFingerResponse, _> =
            convert_json_to(&response.body.as_ref().unwrap());

        if webfinger_response_result.is_err() {
            return Err(OidcClientError::new(
                "OPError",
                "invalid_webfinger_response",
                "invalid  webfinger response",
                Some(response),
            ));
        }

        let webfinger_response = webfinger_response_result.unwrap();

        let location_link_result = webfinger_response
            .links
            .iter()
            .find(|x| x.rel == "http://openid.net/specs/connect/1.0/issuer" && x.href.is_some());

        if location_link_result.is_none() {
            return Err(OidcClientError::new(
                "OPError",
                "empty_location_link",
                "no issuer found in webfinger response",
                Some(response),
            ));
        }

        let expected_issuer = location_link_result.unwrap().href.as_ref().unwrap();

        if !expected_issuer.starts_with("https://") {
            return Err(OidcClientError::new(
                "OPError",
                "invalid_location",
                &format!("invalid issuer location {}", expected_issuer),
                // Todo: Pass the response here
                None,
            ));
        }

        let issuer_result = Issuer::discover_with_interceptor(&expected_issuer, request_options);

        if issuer_result.is_err() {
            let issuer_error = issuer_result.unwrap_err();
            if let Some(res) = &issuer_error.response {
                if res.status == StatusCode::NOT_FOUND {
                    return Err(OidcClientError::new(
                        &issuer_error.name,
                        "no_issuer",
                        &format!("invalid issuer location {}", expected_issuer),
                        // Todo: Pass the response here
                        None,
                    ));
                }
            }
            return Err(issuer_error);
        }

        let issuer = issuer_result.unwrap();

        if &issuer.issuer != expected_issuer {
            return Err(OidcClientError::new(
                "OPError",
                "issuer_mismatch",
                &format!(
                    "discovered issuer mismatch, expected {}, got: {}",
                    expected_issuer, issuer.issuer
                ),
                Some(response),
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
