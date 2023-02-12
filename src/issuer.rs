use core::fmt::Debug;
use std::fmt::Formatter;

use crate::helpers::validate_url;
use crate::http::{default_request_options, request, Request, RequestOptions};
use crate::{errors::OidcClientError, issuer_metadata::IssuerMetadata};
use json::JsonValue;
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

        match &res.to_json() {
            Some(JsonValue::Object(body)) => {
                let issuer_metadata_result = IssuerMetadata::from(&body);
                if let Ok(issuer_metadata) = issuer_metadata_result {
                    let mut issuer = Issuer::from(issuer_metadata);
                    issuer.request_options = request_options;
                    return Ok(issuer);
                }
                return Err(OidcClientError {
                    name: "OPError".to_string(),
                    error: "invalid issuer metadata".to_string(),
                    error_description: "invalid issuer metadata".to_string(),
                    response: Some(res),
                });
            }
            _ => {
                return Err(OidcClientError {
                    name: "TypeError".to_string(),
                    error: "parse_error".to_string(),
                    error_description: "unexpected body type".to_string(),
                    response: Some(res),
                })
            }
        }
    }
}

#[cfg(test)]
mod issuer_discovery_tests {
    use crate::issuer::Issuer;
    pub use httpmock::Method::GET;
    pub use httpmock::MockServer;

    pub const EXPECTED: &str =  "{\"authorization_endpoint\":\"https://op.example.com/o/oauth2/v2/auth\",\"issuer\":\"https://op.example.com\",\"jwks_uri\":\"https://op.example.com/oauth2/v3/certs\",\"token_endpoint\":\"https://op.example.com/oauth2/v4/token\",\"userinfo_endpoint\":\"https://op.example.com/oauth2/v3/userinfo\"}";

    #[cfg(test)]
    mod custom_well_known {
        use super::*;

        #[test]
        fn accepts_and_assigns_the_discovered_metadata() {
            let server = MockServer::start();

            let _custom_config_server = server.mock(|when, then| {
                when.method(GET).path("/.well-known/custom-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(EXPECTED.as_bytes());
            });

            let url =
                String::from(server.base_url().as_str()) + "/.well-known/custom-configuration";

            let issuer_result = Issuer::discover(url.as_str());

            assert_eq!(true, issuer_result.is_ok());
            let issuer = issuer_result.unwrap();
            assert_eq!(issuer.issuer, "https://op.example.com".to_string());
            assert_eq!(
                issuer.jwks_uri,
                Some("https://op.example.com/oauth2/v3/certs".to_string())
            );
            assert_eq!(
                issuer.token_endpoint,
                Some("https://op.example.com/oauth2/v4/token".to_string())
            );
            assert_eq!(
                issuer.userinfo_endpoint,
                Some("https://op.example.com/oauth2/v3/userinfo".to_string())
            );
            assert_eq!(
                issuer.authorization_endpoint,
                Some("https://op.example.com/o/oauth2/v2/auth".to_string())
            );
        }
    }

    #[cfg(test)]
    mod well_known {
        use super::*;

        #[test]
        fn accepts_and_assigns_the_discovered_metadata() {
            let server = MockServer::start();

            let _custom_config_server = server.mock(|when, then| {
                when.method(GET).path("/.well-known/openid-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(EXPECTED.as_bytes());
            });

            let url =
                String::from(server.base_url().as_str()) + "/.well-known/openid-configuration";

            let issuer_result = Issuer::discover(url.as_str());

            assert_eq!(true, issuer_result.is_ok());
            let issuer = issuer_result.unwrap();
            assert_eq!(issuer.issuer, "https://op.example.com".to_string());
            assert_eq!(
                issuer.jwks_uri,
                Some("https://op.example.com/oauth2/v3/certs".to_string())
            );
            assert_eq!(
                issuer.token_endpoint,
                Some("https://op.example.com/oauth2/v4/token".to_string())
            );
            assert_eq!(
                issuer.userinfo_endpoint,
                Some("https://op.example.com/oauth2/v3/userinfo".to_string())
            );
            assert_eq!(
                issuer.authorization_endpoint,
                Some("https://op.example.com/o/oauth2/v2/auth".to_string())
            );
        }

        #[test]
        fn can_be_discovered_by_omitting_well_known() {
            let server = MockServer::start();
            let expected = "{\"issuer\":\"https://op.example.com\"}";

            let _custom_config_server = server.mock(|when, then| {
                when.method(GET).path("/.well-known/openid-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(expected.as_bytes());
            });

            let issuer_result = Issuer::discover(server.base_url().as_str());

            assert_eq!(true, issuer_result.is_ok());
            assert_eq!(
                issuer_result.unwrap().issuer,
                "https://op.example.com".to_string()
            );
        }

        #[test]
        fn discovers_issuers_with_path_components_with_trailing_slash() {
            let server = MockServer::start();
            let expected = "{\"issuer\":\"https://op.example.com/oidc\"}";

            let _custom_config_server = server.mock(|when, then| {
                when.method(GET)
                    .path("/oidc/.well-known/openid-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(expected.as_bytes());
            });

            let url = String::from(server.base_url().as_str()) + "/oidc/";

            let issuer_result = Issuer::discover(url.as_str());

            assert_eq!(true, issuer_result.is_ok());
            assert_eq!(
                issuer_result.unwrap().issuer,
                "https://op.example.com/oidc".to_string()
            );
        }

        #[test]
        fn discovers_issuers_with_path_components_without_trailing_slash() {
            let server = MockServer::start();
            let expected = "{\"issuer\":\"https://op.example.com/oidc\"}";

            let _custom_config_server = server.mock(|when, then| {
                when.method(GET)
                    .path("/oidc/.well-known/openid-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(expected.as_bytes());
            });

            let url = String::from(server.base_url().as_str()) + "/oidc";

            let issuer_result = Issuer::discover(url.as_str());

            assert_eq!(true, issuer_result.is_ok());
            assert_eq!(
                issuer_result.unwrap().issuer,
                "https://op.example.com/oidc".to_string()
            );
        }

        #[test]
        fn discovering_issuers_with_well_known_uri_including_path_and_query() {
            let server = MockServer::start();
            let expected = "{\"issuer\":\"https://op.example.com/oidc\"}";

            let _custom_config_server = server.mock(|when, then| {
                when.method(GET)
                    .path("/oidc/.well-known/openid-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(expected.as_bytes());
            });

            let url = String::from(server.base_url().as_str())
                + "/oidc/.well-known/openid-configuration?foo=bar";

            let issuer_result = Issuer::discover(url.as_str());

            assert_eq!(true, issuer_result.is_ok());
            assert_eq!(
                issuer_result.unwrap().issuer,
                "https://op.example.com/oidc".to_string()
            );
        }
    }

    mod well_known_oauth_authorization_server {
        use super::*;

        #[test]
        fn accepts_and_assigns_the_discovered_metadata() {
            let server = MockServer::start();

            let _custom_config_server = server.mock(|when, then| {
                when.method(GET)
                    .path("/.well-known/oauth-authorization-server");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(EXPECTED.as_bytes());
            });

            let url = String::from(server.base_url().as_str())
                + "/.well-known/oauth-authorization-server";

            let issuer_result = Issuer::discover(url.as_str());

            assert_eq!(true, issuer_result.is_ok());
            let issuer = issuer_result.unwrap();
            assert_eq!(issuer.issuer, "https://op.example.com".to_string());
            assert_eq!(
                issuer.jwks_uri,
                Some("https://op.example.com/oauth2/v3/certs".to_string())
            );
            assert_eq!(
                issuer.token_endpoint,
                Some("https://op.example.com/oauth2/v4/token".to_string())
            );
            assert_eq!(
                issuer.userinfo_endpoint,
                Some("https://op.example.com/oauth2/v3/userinfo".to_string())
            );
            assert_eq!(
                issuer.authorization_endpoint,
                Some("https://op.example.com/o/oauth2/v2/auth".to_string())
            );
        }

        #[test]
        fn discovering_issuers_with_well_known_uri_including_path_and_query() {
            let server = MockServer::start();
            let expected = "{\"issuer\":\"https://op.example.com/oauth2\"}";

            let _custom_config_server = server.mock(|when, then| {
                when.method(GET)
                    .path("/.well-known/oauth-authorization-server/oauth2");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(expected.as_bytes());
            });

            let url = String::from(server.base_url().as_str())
                + "/.well-known/oauth-authorization-server/oauth2?foo=bar";

            let issuer_result = Issuer::discover(url.as_str());

            assert_eq!(true, issuer_result.is_ok());
            assert_eq!(
                issuer_result.unwrap().issuer,
                "https://op.example.com/oauth2".to_string()
            );
        }
    }

    #[test]
    fn assigns_discovery_1_0_defaults_1_of_2() {
        let server = MockServer::start();
        let _custom_config_server = server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200)
                .header("content-type", "application/json")
                .body(EXPECTED.as_bytes());
        });

        let url = String::from(server.base_url().as_str()) + "/.well-known/openid-configuration";

        let issuer_result = Issuer::discover(url.as_str());

        assert_eq!(true, issuer_result.is_ok());
        let issuer = issuer_result.unwrap();
        assert_eq!(issuer.claims_parameter_supported, false);
        assert_eq!(
            issuer.grant_types_supported,
            vec!["authorization_code", "implicit"]
        );
        assert_eq!(issuer.request_parameter_supported, false);
        assert_eq!(issuer.request_uri_parameter_supported, true);
        assert_eq!(issuer.require_request_uri_registration, false);
        assert_eq!(issuer.response_modes_supported, vec!["query", "fragment"]);
        assert_eq!(issuer.claim_types_supported, vec!["normal"]);
        assert_eq!(
            issuer.token_endpoint_auth_methods_supported,
            vec!["client_secret_basic"]
        );
    }

    #[test]
    fn assigns_discovery_1_0_defaults_2_of_2() {
        let server = MockServer::start();

        let _custom_config_server = server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200)
                .header("content-type", "application/json")
                .body(EXPECTED.as_bytes());
        });

        let issuer_result = Issuer::discover(server.base_url().as_str());

        assert_eq!(true, issuer_result.is_ok());
        let issuer = issuer_result.unwrap();
        assert_eq!(issuer.claims_parameter_supported, false);
        assert_eq!(
            issuer.grant_types_supported,
            vec!["authorization_code", "implicit"]
        );
        assert_eq!(issuer.request_parameter_supported, false);
        assert_eq!(issuer.request_uri_parameter_supported, true);
        assert_eq!(issuer.require_request_uri_registration, false);
        assert_eq!(issuer.response_modes_supported, vec!["query", "fragment"]);
        assert_eq!(issuer.claim_types_supported, vec!["normal"]);
        assert_eq!(
            issuer.token_endpoint_auth_methods_supported,
            vec!["client_secret_basic"]
        );
    }

    #[test]
    fn is_rejected_with_op_error_upon_oidc_error() {
        let server = MockServer::start();

        let _custom_config_server = server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(500).body(
                "{\"error\":\"server_error\",\"error_description\":\"bad things are happening\"}"
                    .as_bytes(),
            );
        });

        let issuer_result = Issuer::discover(server.base_url().as_str());

        assert_eq!(true, issuer_result.is_err());
        let error = issuer_result.unwrap_err();
        assert_eq!(error.name, "OPError");
        assert_eq!(error.error, "server_error");
        assert_eq!(error.error_description, "bad things are happening");
    }

    #[test]
    fn is_rejected_with_error_when_no_absolute_url_is_provided() {
        let issuer_result = Issuer::discover("op.example.com/.well-known/foobar");

        assert_eq!(true, issuer_result.is_err());
        let error = issuer_result.unwrap_err();
        assert_eq!(error.name, "TypeError");
        assert_eq!(error.error, "invalid_url");
        assert_eq!(
            error.error_description,
            "only valid absolute URLs can be requested"
        );
    }

    #[test]
    fn is_rejected_with_rp_error_when_error_is_not_a_string() {
        let server = MockServer::start();

        let _custom_config_server = server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(400).body(
                "{\"error\": {},\"error_description\":\"bad things are happening\"}".as_bytes(),
            );
        });

        let issuer_result = Issuer::discover(server.base_url().as_str());

        assert_eq!(true, issuer_result.is_err());
        let error = issuer_result.unwrap_err();
        assert_eq!(error.name, "OPError");
        assert_eq!(error.error, "server_error");
        assert_eq!(
            error.error_description,
            "expected 200 OK, got: 400 Bad Request"
        );
    }

    #[test]
    fn is_rejected_with_when_non_200_is_returned() {
        let server = MockServer::start();

        let _custom_config_server = server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(500);
        });

        let issuer_result = Issuer::discover(server.base_url().as_str());

        assert_eq!(true, issuer_result.is_err());
        let error = issuer_result.unwrap_err();
        assert_eq!(error.name, "OPError");
        assert_eq!(error.error, "server_error");
        assert_eq!(
            error.error_description,
            "expected 200 OK, got: 500 Internal Server Error"
        );
        assert!(error.response.is_some());
    }

    #[test]
    fn is_rejected_with_json_parse_error_upon_invalid_response() {
        let server = MockServer::start();

        let _custom_config_server = server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).body("{\"notavalid\"}".as_bytes());
        });

        let issuer_result = Issuer::discover(server.base_url().as_str());

        assert_eq!(true, issuer_result.is_err());
        let error = issuer_result.unwrap_err();
        assert_eq!(error.name, "TypeError");
        assert_eq!(error.error, "parse_error");
        assert_eq!(error.error_description, "unexpected body type");
        assert!(error.response.is_some());
    }

    #[test]
    fn is_rejected_when_no_body_is_returned() {
        let server = MockServer::start();

        let _custom_config_server = server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200);
        });

        let issuer_result = Issuer::discover(server.base_url().as_str());

        assert_eq!(true, issuer_result.is_err());
        let error = issuer_result.unwrap_err();
        assert_eq!(error.name, "OPError");
        assert_eq!(error.error, "server_error");
        assert_eq!(
            error.error_description,
            "expected 200 OK with body but no body was returned"
        );
    }

    #[test]
    fn is_rejected_when_unepexted_status_code_is_returned() {
        let server = MockServer::start();

        let _custom_config_server = server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(301);
        });

        let issuer_result = Issuer::discover(server.base_url().as_str());

        assert_eq!(true, issuer_result.is_err());
        let error = issuer_result.unwrap_err();
        assert_eq!(error.name, "OPError");
        assert_eq!(error.error, "server_error");
        assert_eq!(
            error.error_description,
            "expected 200 OK, got: 301 Moved Permanently"
        );
    }

    #[cfg(test)]
    mod http_options {
        use std::time::Duration;

        use reqwest::header::{HeaderMap, HeaderValue};

        use crate::http::RequestOptions;

        use super::*;

        #[test]
        fn allows_for_http_options_to_be_defined_for_issuer_discover_calls() {
            let server = MockServer::start();

            let mock_server = server.mock(|when, then| {
                when.method(GET)
                    .header_exists("testHeader")
                    .path("/.well-known/custom-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(EXPECTED.as_bytes());
            });

            let request_options = |_request: &crate::http::Request| {
                let mut headers = HeaderMap::new();
                headers.append("testHeader", HeaderValue::from_static("testHeaderValue"));

                RequestOptions {
                    headers,
                    timeout: Duration::from_millis(3500),
                }
            };

            let url =
                String::from(server.base_url().as_str()) + "/.well-known/custom-configuration";

            let _ = Issuer::discover_with_interceptor(url.as_str(), Box::new(request_options));
            mock_server.assert_hits(1);
        }
    }
}
