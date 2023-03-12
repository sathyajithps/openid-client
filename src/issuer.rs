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
    request_interceptor: Box<dyn FnMut(&Request) -> RequestOptions>,
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
            request_interceptor: Box::new(default_request_interceptor),
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
}

impl Issuer {
    pub fn discover(issuer: &str) -> Result<Issuer, OidcClientError> {
        Issuer::discover_with_interceptor(issuer, Box::new(default_request_interceptor))
    }

    pub fn discover_with_interceptor(
        issuer: &str,
        mut interceptor: Box<dyn FnMut(&Request) -> RequestOptions>,
    ) -> Result<Issuer, OidcClientError> {
        let req = Self::build_discover_request(issuer)?;

        let res = request(req, &mut interceptor)?;

        Self::process_discover_response(res, interceptor)
    }

    pub async fn discover_async(issuer: &str) -> Result<Issuer, OidcClientError> {
        Self::discover_with_interceptor_async(issuer, Box::new(default_request_interceptor)).await
    }

    pub async fn discover_with_interceptor_async(
        issuer: &str,
        mut request_interceptor: Box<dyn FnMut(&Request) -> RequestOptions>,
    ) -> Result<Issuer, OidcClientError> {
        let req = Self::build_discover_request(issuer)?;

        let res = request_async(req, &mut request_interceptor).await?;

        Self::process_discover_response(res, request_interceptor)
    }

    pub fn build_discover_request(issuer: &str) -> Result<Request, OidcClientError> {
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

    pub fn process_discover_response(
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
                    ))
                }
            };

        let mut issuer = Issuer::from(issuer_metadata);
        issuer.request_interceptor = request_options;
        Ok(issuer)
    }
}

impl Issuer {
    pub fn webfinger(input: &str) -> Result<Issuer, OidcClientError> {
        Issuer::webfinger_with_interceptor(input, Box::new(default_request_interceptor))
    }

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

    pub async fn webfinger_async(input: &str) -> Result<Issuer, OidcClientError> {
        Issuer::webfinger_with_interceptor_async(input, Box::new(default_request_interceptor)).await
    }

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
                    ))
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
                ))
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
                    ))
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
