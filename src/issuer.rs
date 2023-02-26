use core::fmt::Debug;
use std::fmt::Formatter;

use crate::helpers::{convert_json_to, validate_url};
use crate::http::{default_request_options, request};
use crate::types::{IssuerMetadata, OidcClientError, Request, RequestOptions};
use reqwest::header::{HeaderMap, HeaderValue};

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

        url.set_path(path.as_str());

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

        if res.body.is_none() {
            return Err(OidcClientError {
                name: "OPError".to_string(),
                error: "invalid issuer metadata".to_string(),
                error_description: "invalid issuer metadata".to_string(),
                response: Some(res),
            });
        }

        let issuer_metadata: IssuerMetadata = convert_json_to(&res.body.unwrap()).unwrap();
        let mut issuer = Issuer::from(issuer_metadata);
        issuer.request_options = request_options;
        return Ok(issuer);
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
