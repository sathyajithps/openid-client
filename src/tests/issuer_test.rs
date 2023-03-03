#[cfg(test)]
mod issuer_discovery_tests {
    use crate::issuer::Issuer;
    use crate::tests::{get_url_with_count, set_mock_domain};
    pub use httpmock::Method::GET;
    pub use httpmock::MockServer;

    pub fn get_expected(domain: &str) -> String {
        format!("{{\"authorization_endpoint\":\"https://{0}/o/oauth2/v2/auth\",\"issuer\":\"https://{0}\",\"jwks_uri\":\"https://{0}/oauth2/v3/certs\",\"token_endpoint\":\"https://{0}/oauth2/v4/token\",\"userinfo_endpoint\":\"https://{0}/oauth2/v3/userinfo\"}}", domain)
    }

    #[cfg(test)]
    mod custom_well_known {
        use crate::tests::{get_url_with_count, set_mock_domain};

        use super::*;

        #[test]
        fn accepts_and_assigns_the_discovered_metadata() {
            let server = MockServer::start();

            let real_domain = get_url_with_count("op.example<>.com");

            let _custom_config_server = server.mock(|when, then| {
                when.method(GET).path("/.well-known/custom-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(get_expected(&real_domain));
            });

            set_mock_domain(&real_domain.to_string(), server.port());

            let issuer_result = Issuer::discover(&format!(
                "https://{}/.well-known/custom-configuration",
                real_domain
            ));

            assert_eq!(true, issuer_result.is_ok());
            let issuer = issuer_result.unwrap();
            assert_eq!(issuer.issuer, format!("https://{0}", &real_domain));
            assert_eq!(
                issuer.jwks_uri,
                Some(format!("https://{0}/oauth2/v3/certs", &real_domain))
            );
            assert_eq!(
                issuer.token_endpoint,
                Some(format!("https://{0}/oauth2/v4/token", &real_domain))
            );
            assert_eq!(
                issuer.userinfo_endpoint,
                Some(format!("https://{0}/oauth2/v3/userinfo", &real_domain))
            );
            assert_eq!(
                issuer.authorization_endpoint,
                Some(format!("https://{0}/o/oauth2/v2/auth", &real_domain))
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

            let real_domain = get_url_with_count("op.example<>.com");

            let _custom_config_server = server.mock(|when, then| {
                when.method(GET).path("/.well-known/openid-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(get_expected(&real_domain));
            });

            set_mock_domain(&real_domain.to_string(), server.port());

            let issuer_result = Issuer::discover(&format!(
                "https://{}/.well-known/openid-configuration",
                real_domain
            ));

            assert_eq!(true, issuer_result.is_ok());
            let issuer = issuer_result.unwrap();

            assert_eq!(issuer.issuer, format!("https://{0}", &real_domain));
            assert_eq!(
                issuer.jwks_uri,
                Some(format!("https://{0}/oauth2/v3/certs", &real_domain))
            );
            assert_eq!(
                issuer.token_endpoint,
                Some(format!("https://{0}/oauth2/v4/token", &real_domain))
            );
            assert_eq!(
                issuer.userinfo_endpoint,
                Some(format!("https://{0}/oauth2/v3/userinfo", &real_domain))
            );
            assert_eq!(
                issuer.authorization_endpoint,
                Some(format!("https://{0}/o/oauth2/v2/auth", &real_domain))
            );
        }

        #[test]
        fn can_be_discovered_by_omitting_well_known() {
            let server = MockServer::start();

            let real_domain = get_url_with_count("op.example<>.com");

            let expected = format!("{{\"issuer\":\"https://{}\"}}", &real_domain);

            let _custom_config_server = server.mock(|when, then| {
                when.method(GET).path("/.well-known/openid-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(&expected);
            });

            set_mock_domain(&real_domain.to_string(), server.port());

            let issuer_result = Issuer::discover(&format!("https://{}", real_domain));

            assert_eq!(true, issuer_result.is_ok());
            assert_eq!(
                issuer_result.unwrap().issuer,
                format!("https://{}", &real_domain)
            );
        }

        #[test]
        fn discovers_issuers_with_path_components_with_trailing_slash() {
            let server = MockServer::start();

            let real_domain = get_url_with_count("op.example<>.com");
            let expected = format!("{{\"issuer\":\"https://{}/oidc\"}}", &real_domain);

            let _custom_config_server = server.mock(|when, then| {
                when.method(GET)
                    .path("/oidc/.well-known/openid-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(&expected);
            });

            set_mock_domain(&real_domain.to_string(), server.port());

            let issuer_result = Issuer::discover(&format!("https://{}/oidc/", real_domain));

            assert_eq!(true, issuer_result.is_ok());
            assert_eq!(
                issuer_result.unwrap().issuer,
                format!("https://{}/oidc", real_domain)
            );
        }

        #[test]
        fn discovers_issuers_with_path_components_without_trailing_slash() {
            let server = MockServer::start();

            let real_domain = get_url_with_count("op.example<>.com");
            let expected = format!("{{\"issuer\":\"https://{}/oidc\"}}", &real_domain);

            let _custom_config_server = server.mock(|when, then| {
                when.method(GET)
                    .path("/oidc/.well-known/openid-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(&expected);
            });

            set_mock_domain(&real_domain.to_string(), server.port());

            let issuer_result = Issuer::discover(&format!("https://{}/oidc", real_domain));

            assert_eq!(true, issuer_result.is_ok());
            assert_eq!(
                issuer_result.unwrap().issuer,
                format!("https://{}/oidc", real_domain)
            );
        }

        #[test]
        fn discovering_issuers_with_well_known_uri_including_path_and_query() {
            let server = MockServer::start();

            let real_domain = get_url_with_count("op.example<>.com");
            let expected = format!("{{\"issuer\":\"https://{}/oidc\"}}", &real_domain);

            let _custom_config_server = server.mock(|when, then| {
                when.method(GET)
                    .path("/oidc/.well-known/openid-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(&expected);
            });

            set_mock_domain(&real_domain.to_string(), server.port());

            let issuer_result = Issuer::discover(&format!(
                "https://{}/oidc/.well-known/openid-configuration?foo=bar",
                real_domain
            ));

            assert_eq!(true, issuer_result.is_ok());
            assert_eq!(
                issuer_result.unwrap().issuer,
                format!("https://{}/oidc", real_domain)
            );
        }
    }

    mod well_known_oauth_authorization_server {
        use crate::tests::set_mock_domain;

        use super::*;

        #[test]
        fn accepts_and_assigns_the_discovered_metadata() {
            let server = MockServer::start();

            let real_domain = get_url_with_count("op.example<>.com");

            let _custom_config_server = server.mock(|when, then| {
                when.method(GET)
                    .path("/.well-known/oauth-authorization-server");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(get_expected(&real_domain));
            });

            set_mock_domain(&real_domain.to_string(), server.port());

            let issuer_result = Issuer::discover(&format!(
                "https://{}/.well-known/oauth-authorization-server",
                real_domain
            ));

            assert_eq!(true, issuer_result.is_ok());
            let issuer = issuer_result.unwrap();
            assert_eq!(issuer.issuer, format!("https://{}", &real_domain));
            assert_eq!(
                issuer.jwks_uri,
                Some(format!("https://{}/oauth2/v3/certs", &real_domain))
            );
            assert_eq!(
                issuer.token_endpoint,
                Some(format!("https://{}/oauth2/v4/token", &real_domain))
            );
            assert_eq!(
                issuer.userinfo_endpoint,
                Some(format!("https://{}/oauth2/v3/userinfo", &real_domain))
            );
            assert_eq!(
                issuer.authorization_endpoint,
                Some(format!("https://{}/o/oauth2/v2/auth", &real_domain))
            );
        }

        #[test]
        fn discovering_issuers_with_well_known_uri_including_path_and_query() {
            let server = MockServer::start();

            let real_domain = get_url_with_count("op.example<>.com");
            let expected = format!("{{\"issuer\":\"https://{}/oauth2\"}}", &real_domain);

            let _custom_config_server = server.mock(|when, then| {
                when.method(GET)
                    .path("/.well-known/oauth-authorization-server/oauth2");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(&expected);
            });

            set_mock_domain(&real_domain.to_string(), server.port());

            let issuer_result = Issuer::discover(&format!(
                "https://{}/.well-known/oauth-authorization-server/oauth2?foo=bar",
                real_domain
            ));

            assert_eq!(true, issuer_result.is_ok());
            assert_eq!(
                issuer_result.unwrap().issuer,
                format!("https://{}/oauth2", &real_domain)
            );
        }
    }

    #[test]
    fn assigns_discovery_1_0_defaults_1_of_2() {
        let server = MockServer::start();

        let real_domain = get_url_with_count("op.example<>.com");

        let _custom_config_server = server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200)
                .header("content-type", "application/json")
                .body(get_expected(&real_domain));
        });

        set_mock_domain(&real_domain.to_string(), server.port());

        let issuer_result = Issuer::discover(&format!(
            "https://{}/.well-known/openid-configuration",
            real_domain
        ));

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

        let real_domain = get_url_with_count("op.example<>.com");

        let _custom_config_server = server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200)
                .header("content-type", "application/json")
                .body(get_expected(&real_domain));
        });

        set_mock_domain(&real_domain.to_string(), server.port());

        let issuer_result = Issuer::discover(&format!("https://{}", real_domain));

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

        let issuer_result = Issuer::discover(&format!("https://{}", real_domain));

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

        let issuer_result = Issuer::discover(&format!("https://{}", real_domain));

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

        let issuer_result = Issuer::discover(&format!("https://{}", real_domain));

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

        let issuer_result = Issuer::discover(&format!("https://{}", real_domain));

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

        let issuer_result = Issuer::discover(&format!("https://{}", real_domain));

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

        let issuer_result = Issuer::discover(&format!("https://{}", real_domain));

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

            let real_domain = get_url_with_count("op.example<>.com");

            let mock_server = server.mock(|when, then| {
                when.method(GET)
                    .header_exists("testHeader")
                    .path("/.well-known/custom-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(get_expected(&real_domain));
            });

            let request_options = |_request: &crate::types::Request| {
                let mut headers = HeaderMap::new();
                headers.append("testHeader", HeaderValue::from_static("testHeaderValue"));

                RequestOptions {
                    headers,
                    timeout: Duration::from_millis(3500),
                }
            };

            set_mock_domain(&real_domain.to_string(), server.port());

            let _ = Issuer::discover_with_interceptor(
                &format!("https://{}/.well-known/custom-configuration", real_domain),
                Box::new(request_options),
            );
            mock_server.assert_hits(1);
        }
    }
}

#[cfg(test)]
mod issuer_webfinger_tests {

    use httpmock::Method::GET;
    use httpmock::MockServer;

    use crate::issuer::Issuer;
    use crate::tests::{get_url_with_count, set_mock_domain};

    #[test]
    fn can_discover_using_the_email_syntax() {
        let server = MockServer::start();

        let real_domain = get_url_with_count("opemail.example<>.com");

        let body_wf = format!("{{\"subject\":\"https://{0}/joe\",\"links\":[{{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://{0}\"}}]}}", real_domain);
        let body_oidc = format!("{{\"authorization_endpoint\":\"https://{0}/o/oauth2/v2/auth\",\"issuer\":\"https://{0}\",\"jwks_uri\":\"https://{0}/oauth2/v3/certs\",\"token_endpoint\":\"https://{0}/oauth2/v4/token\",\"userinfo_endpoint\":\"https://{0}/oauth2/v3/userinfo\"}}", real_domain);

        let resource = format!("joe@{}", real_domain);

        set_mock_domain(&real_domain.to_string(), server.port());

        let webfinger = server.mock(|when, then| {
            when.method(GET)
                .path("/.well-known/webfinger")
                .query_param("resource", format!("acct:{}", &resource));
            then.status(200).body(body_wf);
        });

        let discovery = server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).body(body_oidc);
        });

        let _ = Issuer::webfinger(&resource);

        webfinger.assert();
        discovery.assert();
    }

    #[test]
    fn verifies_the_webfinger_responds_with_an_issuer() {
        let server = MockServer::start();

        let real_domain = get_url_with_count("opemail.example<>.com");

        let body_wf = format!(
            "{{\"subject\":\"https://{0}/joe\",\"links\":[]}}",
            real_domain
        );

        let resource = format!("joe@{}", real_domain);

        set_mock_domain(&real_domain.to_string(), server.port());

        let _webfinger = server.mock(|when, then| {
            when.method(GET)
                .path("/.well-known/webfinger")
                .header("Accept", "application/json");
            then.status(200).body(body_wf);
        });

        let issuer_result = Issuer::webfinger(&resource);

        assert!(issuer_result.is_err());

        let error = issuer_result.unwrap_err();

        assert_eq!(
            error.error_description,
            "no issuer found in webfinger response"
        );
    }

    #[test]
    fn verifies_the_webfinger_responds_with_an_issuer_which_is_a_valid_issuer_value_1_of_2() {
        let server = MockServer::start();

        let real_domain = get_url_with_count("opemail.example<>.com");

        let body_wf = format!("{{\"subject\":\"https://{0}/joe\",\"links\":[{{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://{0}\"}}]}}", real_domain);

        let resource = format!("joe@{}", real_domain);

        set_mock_domain(&real_domain.to_string(), server.port());

        let _webfinger = server.mock(|when, then| {
            when.method(GET).path("/.well-known/webfinger");
            then.status(200).body(body_wf);
        });

        let issuer_result = Issuer::webfinger(&resource);

        assert!(issuer_result.is_err());

        let error = issuer_result.unwrap_err();

        assert_eq!(
            error.error_description,
            format!("invalid issuer location https://{}", real_domain)
        );
    }

    #[test]
    fn verifies_the_webfinger_responds_with_an_issuer_which_is_a_valid_issuer_value_2_of_2() {
        let server = MockServer::start();

        let real_domain = get_url_with_count("opemail.example<>.com");

        let body_wf = format!("{{\"subject\":\"https://{}/joe\",\"links\":[{{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"1\"}}]}}", real_domain);

        let resource = format!("joe@{}", real_domain);

        set_mock_domain(&real_domain.to_string(), server.port());

        let _webfinger = server.mock(|when, then| {
            when.method(GET).path("/.well-known/webfinger");
            then.status(200).body(body_wf);
        });

        let issuer_result = Issuer::webfinger(&resource);

        assert!(issuer_result.is_err());

        let error = issuer_result.unwrap_err();

        assert_eq!(error.error_description, "invalid issuer location 1");
    }

    // Todo: not implementing cache right now
    // #[test]
    // fn uses_cached_issuer_if_it_has_one() {
    //     let server = MockServer::start();

    //     let real_domain = get_url_with_count("opemail.example<>.com");

    //     let body_wf = format!("{{\"subject\":\"https://{0}/joe\",\"links\":[{{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://{0}\"}}]}}", real_domain);
    //     let body_oidc = format!("{{\"authorization_endpoint\":\"https://{0}/o/oauth2/v2/auth\",\"issuer\":\"https://{0}\",\"jwks_uri\":\"https://{0}/oauth2/v3/certs\",\"token_endpoint\":\"https://{0}/oauth2/v4/token\",\"userinfo_endpoint\":\"https://{0}/oauth2/v3/userinfo\"}}", real_domain);

    //     let resource = format!("joe@{}", real_domain);

    //     set_mock_domain(&real_domain.to_string(), server.port());

    //     let webfinger = server.mock(|when, then| {
    //         when.method(GET).path("/.well-known/webfinger");
    //         then.status(200).body(body_wf);
    //     });

    //     let discovery = server.mock(|when, then| {
    //         when.method(GET).path("/.well-known/openid-configuration");
    //         then.status(200).body(body_oidc);
    //     });

    //     let _ = Issuer::webfinger(&resource);
    //     let __ = Issuer::webfinger(&resource);

    //     webfinger.assert_hits(2);
    //     discovery.assert_hits(1);
    // }

    #[test]
    fn validates_the_discovered_issuer_is_the_same_as_from_webfinger() {
        let server = MockServer::start();

        let real_domain = get_url_with_count("opemail.example<>.com");

        let body_wf = format!("{{\"subject\":\"https://{0}/joe\",\"links\":[{{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://{0}\"}}]}}", real_domain);
        let body_oidc = format!("{{\"authorization_endpoint\":\"https://{0}/o/oauth2/v2/auth\",\"issuer\":\"https://another.issuer.com\",\"jwks_uri\":\"https://{0}/oauth2/v3/certs\",\"token_endpoint\":\"https://{0}/oauth2/v4/token\",\"userinfo_endpoint\":\"https://{0}/oauth2/v3/userinfo\"}}", real_domain);

        let resource = format!("joe@{}", real_domain);

        set_mock_domain(&real_domain.to_string(), server.port());

        let webfinger = server.mock(|when, then| {
            when.method(GET).path("/.well-known/webfinger");
            then.status(200).body(body_wf);
        });

        let discovery = server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).body(body_oidc);
        });

        let issuer_result = Issuer::webfinger(&resource);
        assert!(issuer_result.is_err());

        let error = issuer_result.unwrap_err();

        assert_eq!(
            format!(
                "discovered issuer mismatch, expected https://{}, got: https://another.issuer.com",
                real_domain
            ),
            error.error_description
        );

        webfinger.assert();
        discovery.assert();
    }

    #[test]
    fn can_discover_using_the_url_syntax() {
        let server = MockServer::start();

        let real_domain = get_url_with_count("opurl.example<>.com");

        let body_wf = format!("{{\"subject\":\"https://{0}/joe\",\"links\":[{{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://{0}\"}}]}}", real_domain);
        let body_oidc = format!("{{\"authorization_endpoint\":\"https://{0}/o/oauth2/v2/auth\",\"issuer\":\"https://{0}\",\"jwks_uri\":\"https://{0}/oauth2/v3/certs\",\"token_endpoint\":\"https://{0}/oauth2/v4/token\",\"userinfo_endpoint\":\"https://{0}/oauth2/v3/userinfo\"}}", real_domain);

        let url = format!("https://{}/joe", real_domain);

        set_mock_domain(&real_domain.to_string(), server.port());

        let webfinger = server.mock(|when, then| {
            when.method(GET)
                .path("/.well-known/webfinger")
                .query_param("resource", &url);
            then.status(200).body(body_wf);
        });

        let discovery = server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).body(body_oidc);
        });

        let issuer_result = Issuer::webfinger(&url);
        assert!(issuer_result.is_ok());

        webfinger.assert();
        discovery.assert();
    }

    #[test]
    fn can_discover_using_the_hostname_and_port_syntax() {
        let server = MockServer::start();

        let real_domain = get_url_with_count("ophp.example<>.com");

        let real_domain_with_port = format!("{}:8080", real_domain);

        let body_wf = format!("{{\"subject\":\"https://{0}:8080\",\"links\":[{{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://{0}\"}}]}}", real_domain);
        let body_oidc = format!("{{\"authorization_endpoint\":\"https://{0}/o/oauth2/v2/auth\",\"issuer\":\"https://{0}\",\"jwks_uri\":\"https://{0}/oauth2/v3/certs\",\"token_endpoint\":\"https://{0}/oauth2/v4/token\",\"userinfo_endpoint\":\"https://{0}/oauth2/v3/userinfo\"}}", real_domain);

        // for webfinger
        set_mock_domain(&real_domain_with_port, server.port());
        // for oidc discovery
        set_mock_domain(&real_domain, server.port());

        let webfinger = server.mock(|when, then| {
            when.method(GET)
                .path("/.well-known/webfinger")
                .query_param("resource", format!("https://{}", real_domain_with_port));
            then.status(200).body(body_wf);
        });

        let discovery = server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).body(body_oidc);
        });

        let issuer_result = Issuer::webfinger(&real_domain_with_port);
        assert!(issuer_result.is_ok());

        webfinger.assert();
        discovery.assert();
    }

    #[test]
    fn can_discover_using_the_acct_syntax() {
        let server = MockServer::start();

        let real_domain = get_url_with_count("opacct.example<>.com");
        let resource = format!("acct:juliet%40capulet.example@{}", real_domain);

        let body_wf = format!("{{\"subject\":\"{0}\",\"links\":[{{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://{1}\"}}]}}",resource, real_domain);
        let body_oidc = format!("{{\"authorization_endpoint\":\"https://{0}/o/oauth2/v2/auth\",\"issuer\":\"https://{0}\",\"jwks_uri\":\"https://{0}/oauth2/v3/certs\",\"token_endpoint\":\"https://{0}/oauth2/v4/token\",\"userinfo_endpoint\":\"https://{0}/oauth2/v3/userinfo\"}}", real_domain);

        set_mock_domain(&real_domain.to_string(), server.port());

        let webfinger = server.mock(|when, then| {
            when.method(GET)
                .path("/.well-known/webfinger")
                .query_param("resource", &resource);
            then.status(200).body(body_wf);
        });

        let discovery = server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).body(body_oidc);
        });

        let issuer_result = Issuer::webfinger(&resource);
        assert!(issuer_result.is_ok());

        webfinger.assert();
        discovery.assert();
    }

    #[cfg(test)]
    mod http_options {
        use std::time::Duration;

        use httpmock::{Method::GET, MockServer};
        use reqwest::header::{HeaderMap, HeaderValue};

        use crate::{
            issuer::Issuer,
            tests::{get_url_with_count, set_mock_domain},
            types::RequestOptions,
        };

        #[test]
        fn allows_for_http_options_to_be_defined_for_issuer_webfinger_calls() {
            let server = MockServer::start();

            let real_domain = get_url_with_count("op.example<>.com");
            let resource = format!("acct:juliet@{}", real_domain);

            let body_wf = format!("{{\"subject\":\"{0}\",\"links\":[{{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://{1}\"}}]}}",resource, real_domain);
            let body_oidc = format!("{{\"authorization_endpoint\":\"https://{0}/o/oauth2/v2/auth\",\"issuer\":\"https://{0}\",\"jwks_uri\":\"https://{0}/oauth2/v3/certs\",\"token_endpoint\":\"https://{0}/oauth2/v4/token\",\"userinfo_endpoint\":\"https://{0}/oauth2/v3/userinfo\"}}", real_domain);

            set_mock_domain(&real_domain.to_string(), server.port());

            let webfinger = server.mock(|when, then| {
                when.method(GET)
                    .path("/.well-known/webfinger")
                    .header("custom", "foo")
                    .query_param("resource", &resource);
                then.status(200).body(body_wf);
            });

            let discovery = server.mock(|when, then| {
                when.method(GET)
                    .path("/.well-known/openid-configuration")
                    .header("custom", "foo");
                then.status(200).body(body_oidc);
            });

            let request_options = |_request: &crate::types::Request| {
                let mut headers = HeaderMap::new();
                headers.append("custom", HeaderValue::from_static("foo"));
                RequestOptions {
                    headers,
                    timeout: Duration::from_millis(3500),
                }
            };

            let issuer_result =
                Issuer::webfinger_with_interceptor(&resource, Box::new(request_options));

            webfinger.assert();
            discovery.assert();
            assert!(issuer_result.is_ok());
        }
    }
}
