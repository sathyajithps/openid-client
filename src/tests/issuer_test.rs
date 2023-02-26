#[cfg(test)]
mod issuer_discovery_tests {
    use crate::issuer::Issuer;
    use crate::tests::{get_url_with_count, set_mock_domain};
    pub use httpmock::Method::GET;
    pub use httpmock::MockServer;

    pub const EXPECTED: &str =  "{\"authorization_endpoint\":\"https://op.example.com/o/oauth2/v2/auth\",\"issuer\":\"https://op.example.com\",\"jwks_uri\":\"https://op.example.com/oauth2/v3/certs\",\"token_endpoint\":\"https://op.example.com/oauth2/v4/token\",\"userinfo_endpoint\":\"https://op.example.com/oauth2/v3/userinfo\"}";

    #[cfg(test)]
    mod custom_well_known {
        use crate::tests::{get_url_with_count, set_mock_domain};

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

            let real_domain = get_url_with_count("op.example<>.com");

            set_mock_domain(&real_domain.to_string(), server.port());

            let issuer_result = Issuer::discover(
                format!("https://{}/.well-known/custom-configuration", real_domain).as_str(),
            );

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
        use crate::tests::{get_url_with_count, set_mock_domain};

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

            let real_domain = get_url_with_count("op.example<>.com");

            set_mock_domain(&real_domain.to_string(), server.port());

            let issuer_result = Issuer::discover(
                format!("https://{}/.well-known/openid-configuration", real_domain).as_str(),
            );

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

            let real_domain = get_url_with_count("op.example<>.com");

            set_mock_domain(&real_domain.to_string(), server.port());

            let issuer_result = Issuer::discover(format!("https://{}", real_domain).as_str());

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

            let real_domain = get_url_with_count("op.example<>.com");

            set_mock_domain(&real_domain.to_string(), server.port());

            let issuer_result = Issuer::discover(format!("https://{}/oidc/", real_domain).as_str());

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

            let real_domain = get_url_with_count("op.example<>.com");

            set_mock_domain(&real_domain.to_string(), server.port());

            let issuer_result = Issuer::discover(format!("https://{}/oidc", real_domain).as_str());

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

            let real_domain = get_url_with_count("op.example<>.com");

            set_mock_domain(&real_domain.to_string(), server.port());

            let issuer_result = Issuer::discover(
                format!(
                    "https://{}/oidc/.well-known/openid-configuration?foo=bar",
                    real_domain
                )
                .as_str(),
            );

            assert_eq!(true, issuer_result.is_ok());
            assert_eq!(
                issuer_result.unwrap().issuer,
                "https://op.example.com/oidc".to_string()
            );
        }
    }

    mod well_known_oauth_authorization_server {
        use crate::tests::set_mock_domain;

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

            let real_domain = get_url_with_count("op.example<>.com");

            set_mock_domain(&real_domain.to_string(), server.port());

            let issuer_result = Issuer::discover(
                format!(
                    "https://{}/.well-known/oauth-authorization-server",
                    real_domain
                )
                .as_str(),
            );

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

            let real_domain = get_url_with_count("op.example<>.com");

            set_mock_domain(&real_domain.to_string(), server.port());

            let issuer_result = Issuer::discover(
                format!(
                    "https://{}/.well-known/oauth-authorization-server/oauth2?foo=bar",
                    real_domain
                )
                .as_str(),
            );

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

        let real_domain = get_url_with_count("op.example<>.com");

        set_mock_domain(&real_domain.to_string(), server.port());

        let issuer_result = Issuer::discover(
            format!("https://{}/.well-known/openid-configuration", real_domain).as_str(),
        );

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

        let real_domain = get_url_with_count("op.example<>.com");

        set_mock_domain(&real_domain.to_string(), server.port());

        let issuer_result = Issuer::discover(format!("https://{}", real_domain).as_str());

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

        let real_domain = get_url_with_count("op.example<>.com");

        set_mock_domain(&real_domain.to_string(), server.port());

        let issuer_result = Issuer::discover(format!("https://{}", real_domain).as_str());

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

        let real_domain = get_url_with_count("op.example<>.com");

        set_mock_domain(&real_domain.to_string(), server.port());

        let issuer_result = Issuer::discover(format!("https://{}", real_domain).as_str());

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

        let real_domain = get_url_with_count("op.example<>.com");

        set_mock_domain(&real_domain.to_string(), server.port());

        let issuer_result = Issuer::discover(format!("https://{}", real_domain).as_str());

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

        let real_domain = get_url_with_count("op.example<>.com");

        set_mock_domain(&real_domain.to_string(), server.port());

        let issuer_result = Issuer::discover(format!("https://{}", real_domain).as_str());

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

        let real_domain = get_url_with_count("op.example<>.com");

        set_mock_domain(&real_domain.to_string(), server.port());

        let issuer_result = Issuer::discover(format!("https://{}", real_domain).as_str());

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

        let real_domain = get_url_with_count("op.example<>.com");

        set_mock_domain(&real_domain.to_string(), server.port());

        let issuer_result = Issuer::discover(format!("https://{}", real_domain).as_str());

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

        use crate::{tests::get_url_with_count, types::RequestOptions};

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

            let request_options = |_request: &crate::types::Request| {
                let mut headers = HeaderMap::new();
                headers.append("testHeader", HeaderValue::from_static("testHeaderValue"));

                RequestOptions {
                    headers,
                    timeout: Duration::from_millis(3500),
                }
            };

            let real_domain = get_url_with_count("op.example<>.com");

            set_mock_domain(&real_domain.to_string(), server.port());

            let _ = Issuer::discover_with_interceptor(
                format!("https://{}/.well-known/custom-configuration", real_domain).as_str(),
                Box::new(request_options),
            );
            mock_server.assert_hits(1);
        }
    }
}
