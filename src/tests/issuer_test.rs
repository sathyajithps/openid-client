#[cfg(test)]
mod issuer_discovery_tests {
    use crate::issuer::Issuer;
    use crate::tests::{get_url_with_count, set_mock_domain};
    pub use httpmock::Method::GET;
    pub use httpmock::MockServer;

    pub fn get_async_issuer_discovery(issuer: &str) -> Result<Issuer, crate::OidcClientError> {
        let async_runtime = tokio::runtime::Runtime::new().unwrap();

        let result: Result<Issuer, crate::OidcClientError> = async_runtime.block_on(async {
            let iss = Issuer::discover_async(issuer).await;
            return iss;
        });
        result
    }

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

            let issuer = format!("https://{}/.well-known/custom-configuration", real_domain);
            let issuer_result = Issuer::discover(&issuer);
            let async_issuer_result = get_async_issuer_discovery(&issuer);

            assert_eq!(true, issuer_result.is_ok());
            assert_eq!(true, async_issuer_result.is_ok());

            let issuer = issuer_result.unwrap();
            let async_issuer = async_issuer_result.unwrap();

            assert_eq!(issuer.issuer, format!("https://{0}", &real_domain));
            assert_eq!(async_issuer.issuer, format!("https://{0}", &real_domain));

            assert_eq!(
                issuer.jwks_uri,
                Some(format!("https://{0}/oauth2/v3/certs", &real_domain))
            );
            assert_eq!(
                async_issuer.jwks_uri,
                Some(format!("https://{0}/oauth2/v3/certs", &real_domain))
            );

            assert_eq!(
                issuer.token_endpoint,
                Some(format!("https://{0}/oauth2/v4/token", &real_domain))
            );
            assert_eq!(
                async_issuer.token_endpoint,
                Some(format!("https://{0}/oauth2/v4/token", &real_domain))
            );

            assert_eq!(
                issuer.userinfo_endpoint,
                Some(format!("https://{0}/oauth2/v3/userinfo", &real_domain))
            );
            assert_eq!(
                async_issuer.userinfo_endpoint,
                Some(format!("https://{0}/oauth2/v3/userinfo", &real_domain))
            );

            assert_eq!(
                issuer.authorization_endpoint,
                Some(format!("https://{0}/o/oauth2/v2/auth", &real_domain))
            );
            assert_eq!(
                async_issuer.authorization_endpoint,
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

            let issuer = format!("https://{}/.well-known/openid-configuration", real_domain);
            let issuer_result = Issuer::discover(&issuer);
            let async_issuer_result = get_async_issuer_discovery(&issuer);

            assert_eq!(true, issuer_result.is_ok());
            assert_eq!(true, async_issuer_result.is_ok());

            let issuer = issuer_result.unwrap();
            let async_issuer = async_issuer_result.unwrap();

            assert_eq!(issuer.issuer, format!("https://{0}", &real_domain));
            assert_eq!(async_issuer.issuer, format!("https://{0}", &real_domain));

            assert_eq!(
                issuer.jwks_uri,
                Some(format!("https://{0}/oauth2/v3/certs", &real_domain))
            );
            assert_eq!(
                async_issuer.jwks_uri,
                Some(format!("https://{0}/oauth2/v3/certs", &real_domain))
            );

            assert_eq!(
                issuer.token_endpoint,
                Some(format!("https://{0}/oauth2/v4/token", &real_domain))
            );
            assert_eq!(
                async_issuer.token_endpoint,
                Some(format!("https://{0}/oauth2/v4/token", &real_domain))
            );

            assert_eq!(
                issuer.userinfo_endpoint,
                Some(format!("https://{0}/oauth2/v3/userinfo", &real_domain))
            );
            assert_eq!(
                async_issuer.userinfo_endpoint,
                Some(format!("https://{0}/oauth2/v3/userinfo", &real_domain))
            );

            assert_eq!(
                issuer.authorization_endpoint,
                Some(format!("https://{0}/o/oauth2/v2/auth", &real_domain))
            );
            assert_eq!(
                async_issuer.authorization_endpoint,
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

            let issuer = format!("https://{}", real_domain);
            let issuer_result = Issuer::discover(&issuer);
            let async_issuer_result = get_async_issuer_discovery(&issuer);

            assert_eq!(true, issuer_result.is_ok());
            assert_eq!(true, async_issuer_result.is_ok());

            assert_eq!(issuer_result.unwrap().issuer, issuer);
            assert_eq!(async_issuer_result.unwrap().issuer, issuer);
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

            let issuer = format!("https://{}/oidc/", real_domain);
            let issuer_result = Issuer::discover(&issuer);
            let async_issuer_result = get_async_issuer_discovery(&issuer);

            assert_eq!(true, issuer_result.is_ok());
            assert_eq!(true, async_issuer_result.is_ok());

            assert_eq!(
                issuer_result.unwrap().issuer,
                format!("https://{}/oidc", real_domain)
            );
            assert_eq!(
                async_issuer_result.unwrap().issuer,
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

            let issuer = format!("https://{}/oidc", real_domain);
            let issuer_result = Issuer::discover(&issuer);
            let async_issuer_result = get_async_issuer_discovery(&issuer);

            assert_eq!(true, issuer_result.is_ok());
            assert_eq!(true, async_issuer_result.is_ok());

            assert_eq!(
                issuer_result.unwrap().issuer,
                format!("https://{}/oidc", real_domain)
            );
            assert_eq!(
                async_issuer_result.unwrap().issuer,
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

            let issuer = format!(
                "https://{}/oidc/.well-known/openid-configuration?foo=bar",
                real_domain
            );
            let issuer_result = Issuer::discover(&issuer);
            let async_issuer_result = get_async_issuer_discovery(&issuer);

            assert_eq!(true, issuer_result.is_ok());
            assert_eq!(true, async_issuer_result.is_ok());

            assert_eq!(
                issuer_result.unwrap().issuer,
                format!("https://{}/oidc", real_domain)
            );
            assert_eq!(
                async_issuer_result.unwrap().issuer,
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

            let issuer = format!(
                "https://{}/.well-known/oauth-authorization-server",
                real_domain
            );
            let issuer_result = Issuer::discover(&issuer);
            let async_issuer_result = get_async_issuer_discovery(&issuer);

            assert_eq!(true, issuer_result.is_ok());
            assert_eq!(true, async_issuer_result.is_ok());

            let issuer = issuer_result.unwrap();
            let async_issuer = async_issuer_result.unwrap();

            assert_eq!(issuer.issuer, format!("https://{}", &real_domain));
            assert_eq!(async_issuer.issuer, format!("https://{}", &real_domain));

            assert_eq!(
                issuer.jwks_uri,
                Some(format!("https://{}/oauth2/v3/certs", &real_domain))
            );
            assert_eq!(
                async_issuer.jwks_uri,
                Some(format!("https://{}/oauth2/v3/certs", &real_domain))
            );

            assert_eq!(
                issuer.token_endpoint,
                Some(format!("https://{}/oauth2/v4/token", &real_domain))
            );
            assert_eq!(
                async_issuer.token_endpoint,
                Some(format!("https://{}/oauth2/v4/token", &real_domain))
            );

            assert_eq!(
                issuer.userinfo_endpoint,
                Some(format!("https://{}/oauth2/v3/userinfo", &real_domain))
            );
            assert_eq!(
                async_issuer.userinfo_endpoint,
                Some(format!("https://{}/oauth2/v3/userinfo", &real_domain))
            );

            assert_eq!(
                issuer.authorization_endpoint,
                Some(format!("https://{}/o/oauth2/v2/auth", &real_domain))
            );
            assert_eq!(
                async_issuer.authorization_endpoint,
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

            let issuer = format!(
                "https://{}/.well-known/oauth-authorization-server/oauth2?foo=bar",
                real_domain
            );
            let issuer_result = Issuer::discover(&issuer);
            let async_issuer_result = get_async_issuer_discovery(&issuer);

            assert_eq!(true, issuer_result.is_ok());
            assert_eq!(true, async_issuer_result.is_ok());

            assert_eq!(
                issuer_result.unwrap().issuer,
                format!("https://{}/oauth2", &real_domain)
            );
            assert_eq!(
                async_issuer_result.unwrap().issuer,
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

        let issuer = format!("https://{}/.well-known/openid-configuration", real_domain);
        let issuer_result = Issuer::discover(&issuer);
        let async_issuer_result = get_async_issuer_discovery(&issuer);

        assert_eq!(true, issuer_result.is_ok());
        assert_eq!(true, async_issuer_result.is_ok());

        let issuer = issuer_result.unwrap();
        let async_issuer = async_issuer_result.unwrap();

        assert_eq!(issuer.claims_parameter_supported, Some(false));
        assert_eq!(async_issuer.claims_parameter_supported, Some(false));

        assert_eq!(
            issuer.grant_types_supported,
            Some(vec![
                "authorization_code".to_string(),
                "implicit".to_string(),
            ])
        );
        assert_eq!(
            async_issuer.grant_types_supported,
            Some(vec![
                "authorization_code".to_string(),
                "implicit".to_string(),
            ])
        );

        assert_eq!(issuer.request_parameter_supported, Some(false));
        assert_eq!(async_issuer.request_parameter_supported, Some(false));

        assert_eq!(issuer.request_uri_parameter_supported, Some(true));
        assert_eq!(async_issuer.request_uri_parameter_supported, Some(true));

        assert_eq!(issuer.require_request_uri_registration, Some(false));
        assert_eq!(async_issuer.require_request_uri_registration, Some(false));

        assert_eq!(
            issuer.response_modes_supported,
            Some(vec!["query".to_string(), "fragment".to_string()])
        );
        assert_eq!(
            async_issuer.response_modes_supported,
            Some(vec!["query".to_string(), "fragment".to_string()])
        );

        assert_eq!(issuer.claim_types_supported, vec!["normal".to_string()]);
        assert_eq!(
            async_issuer.claim_types_supported,
            vec!["normal".to_string()]
        );

        assert_eq!(
            issuer.token_endpoint_auth_methods_supported,
            Some(vec!["client_secret_basic".to_string()])
        );
        assert_eq!(
            async_issuer.token_endpoint_auth_methods_supported,
            Some(vec!["client_secret_basic".to_string()])
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

        let issuer = format!("https://{}", real_domain);
        let issuer_result = Issuer::discover(&issuer);
        let async_issuer_result = get_async_issuer_discovery(&issuer);

        assert_eq!(true, issuer_result.is_ok());
        assert_eq!(true, async_issuer_result.is_ok());

        let issuer = issuer_result.unwrap();
        let async_issuer = async_issuer_result.unwrap();

        assert_eq!(issuer.claims_parameter_supported, Some(false));
        assert_eq!(async_issuer.claims_parameter_supported, Some(false));

        assert_eq!(
            issuer.grant_types_supported,
            Some(vec![
                "authorization_code".to_string(),
                "implicit".to_string(),
            ])
        );
        assert_eq!(
            async_issuer.grant_types_supported,
            Some(vec![
                "authorization_code".to_string(),
                "implicit".to_string(),
            ])
        );

        assert_eq!(issuer.request_parameter_supported, Some(false));
        assert_eq!(async_issuer.request_parameter_supported, Some(false));

        assert_eq!(issuer.request_uri_parameter_supported, Some(true));
        assert_eq!(async_issuer.request_uri_parameter_supported, Some(true));

        assert_eq!(issuer.require_request_uri_registration, Some(false));
        assert_eq!(async_issuer.require_request_uri_registration, Some(false));

        assert_eq!(
            issuer.response_modes_supported,
            Some(vec!["query".to_string(), "fragment".to_string()])
        );
        assert_eq!(
            async_issuer.response_modes_supported,
            Some(vec!["query".to_string(), "fragment".to_string()])
        );

        assert_eq!(issuer.claim_types_supported, vec!["normal".to_string()]);
        assert_eq!(
            async_issuer.claim_types_supported,
            vec!["normal".to_string()]
        );

        assert_eq!(
            issuer.token_endpoint_auth_methods_supported,
            Some(vec!["client_secret_basic".to_string()])
        );
        assert_eq!(
            async_issuer.token_endpoint_auth_methods_supported,
            Some(vec!["client_secret_basic".to_string()])
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

        let issuer = format!("https://{}", real_domain);
        let issuer_result = Issuer::discover(&issuer);
        let async_issuer_result = get_async_issuer_discovery(&issuer);

        assert_eq!(true, issuer_result.is_err());
        assert_eq!(true, async_issuer_result.is_err());

        let error = issuer_result.unwrap_err();
        let async_error = async_issuer_result.unwrap_err();

        assert_eq!(error.name, "OPError");
        assert_eq!(async_error.name, "OPError");

        assert_eq!(error.error, "server_error");
        assert_eq!(async_error.error, "server_error");

        assert_eq!(error.error_description, "bad things are happening");
        assert_eq!(async_error.error_description, "bad things are happening");
    }

    #[test]
    fn is_rejected_with_error_when_no_absolute_url_is_provided() {
        let issuer_result = Issuer::discover("op.example.com/.well-known/foobar");
        let async_issuer_result = get_async_issuer_discovery("op.example.com/.well-known/foobar");

        assert_eq!(true, issuer_result.is_err());
        assert_eq!(true, async_issuer_result.is_err());

        let error = issuer_result.unwrap_err();
        let async_error = async_issuer_result.unwrap_err();

        assert_eq!(error.name, "TypeError");
        assert_eq!(async_error.name, "TypeError");

        assert_eq!(error.error, "invalid_url");
        assert_eq!(async_error.error, "invalid_url");

        assert_eq!(
            error.error_description,
            "only valid absolute URLs can be requested"
        );
        assert_eq!(
            async_error.error_description,
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

        let issuer = format!("https://{}", real_domain);
        let issuer_result = Issuer::discover(&issuer);
        let async_issuer_result = get_async_issuer_discovery(&issuer);

        assert_eq!(true, issuer_result.is_err());
        assert_eq!(true, async_issuer_result.is_err());

        let error = issuer_result.unwrap_err();
        let async_error = async_issuer_result.unwrap_err();

        assert_eq!(error.name, "OPError");
        assert_eq!(async_error.name, "OPError");

        assert_eq!(error.error, "server_error");
        assert_eq!(async_error.error, "server_error");

        assert_eq!(
            error.error_description,
            "expected 200 OK, got: 400 Bad Request"
        );
        assert_eq!(
            async_error.error_description,
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

        let issuer = format!("https://{}", real_domain);
        let issuer_result = Issuer::discover(&issuer);
        let async_issuer_result = get_async_issuer_discovery(&issuer);

        assert_eq!(true, issuer_result.is_err());
        assert_eq!(true, async_issuer_result.is_err());

        let error = issuer_result.unwrap_err();
        let async_error = async_issuer_result.unwrap_err();

        assert_eq!(error.name, "OPError");
        assert_eq!(async_error.name, "OPError");

        assert_eq!(error.error, "server_error");
        assert_eq!(async_error.error, "server_error");

        assert_eq!(
            error.error_description,
            "expected 200 OK, got: 500 Internal Server Error"
        );
        assert_eq!(
            async_error.error_description,
            "expected 200 OK, got: 500 Internal Server Error"
        );

        assert!(error.response.is_some());
        assert!(async_error.response.is_some());
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

        let issuer = format!("https://{}", real_domain);
        let issuer_result = Issuer::discover(&issuer);
        let async_issuer_result = get_async_issuer_discovery(&issuer);

        assert_eq!(true, issuer_result.is_err());
        assert_eq!(true, async_issuer_result.is_err());

        let error = issuer_result.unwrap_err();
        let async_error = async_issuer_result.unwrap_err();

        assert_eq!(error.name, "TypeError");
        assert_eq!(async_error.name, "TypeError");

        assert_eq!(error.error, "parse_error");
        assert_eq!(async_error.error, "parse_error");

        assert_eq!(error.error_description, "unexpected body type");
        assert_eq!(async_error.error_description, "unexpected body type");

        assert!(error.response.is_some());
        assert!(async_error.response.is_some());
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

        let issuer = format!("https://{}", real_domain);
        let issuer_result = Issuer::discover(&issuer);
        let async_issuer_result = get_async_issuer_discovery(&issuer);

        assert_eq!(true, issuer_result.is_err());
        assert_eq!(true, async_issuer_result.is_err());

        let error = issuer_result.unwrap_err();
        let async_error = async_issuer_result.unwrap_err();

        assert_eq!(error.name, "OPError");
        assert_eq!(async_error.name, "OPError");

        assert_eq!(error.error, "server_error");
        assert_eq!(async_error.error, "server_error");

        assert_eq!(
            error.error_description,
            "expected 200 OK with body but no body was returned"
        );
        assert_eq!(
            async_error.error_description,
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

        let issuer = format!("https://{}", real_domain);
        let issuer_result = Issuer::discover(&issuer);
        let async_issuer_result = get_async_issuer_discovery(&issuer);

        assert_eq!(true, issuer_result.is_err());
        assert_eq!(true, async_issuer_result.is_err());

        let error = issuer_result.unwrap_err();
        let async_error = async_issuer_result.unwrap_err();

        assert_eq!(error.name, "OPError");
        assert_eq!(async_error.name, "OPError");

        assert_eq!(error.error, "server_error");
        assert_eq!(async_error.error, "server_error");

        assert_eq!(
            error.error_description,
            "expected 200 OK, got: 301 Moved Permanently"
        );
        assert_eq!(
            async_error.error_description,
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

            let interceptor = |_request: &crate::types::Request| {
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
                Box::new(interceptor),
            );
            mock_server.assert_hits(1);
        }

        #[test]
        fn allows_for_http_options_to_be_defined_for_issuer_discover_calls_async() {
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

            let interceptor = |_request: &crate::types::Request| {
                let mut headers = HeaderMap::new();
                headers.append("testHeader", HeaderValue::from_static("testHeaderValue"));

                RequestOptions {
                    headers,
                    timeout: Duration::from_millis(3500),
                }
            };

            set_mock_domain(&real_domain.to_string(), server.port());

            let async_runtime = tokio::runtime::Runtime::new().unwrap();

            let _ = async_runtime.block_on(async {
                Issuer::discover_with_interceptor_async(
                    &format!("https://{}/.well-known/custom-configuration", real_domain),
                    Box::new(interceptor),
                )
                .await
            });

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

    pub fn get_async_webfinger_discovery(input: &str) -> Result<Issuer, crate::OidcClientError> {
        let async_runtime = tokio::runtime::Runtime::new().unwrap();

        let result: Result<Issuer, crate::OidcClientError> = async_runtime.block_on(async {
            let iss = Issuer::webfinger_async(input).await;
            return iss;
        });
        result
    }

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

        let _ = get_async_webfinger_discovery(&resource);

        webfinger.assert_hits(2);
        discovery.assert_hits(2);
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
        let async_issuer_result = get_async_webfinger_discovery(&resource);

        assert!(issuer_result.is_err());
        assert!(async_issuer_result.is_err());

        let error = issuer_result.unwrap_err();
        let async_error = async_issuer_result.unwrap_err();

        assert_eq!(
            error.error_description,
            "no issuer found in webfinger response"
        );
        assert_eq!(
            async_error.error_description,
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
        let async_issuer_result = get_async_webfinger_discovery(&resource);

        assert!(issuer_result.is_err());
        assert!(async_issuer_result.is_err());

        let error = issuer_result.unwrap_err();
        let async_error = async_issuer_result.unwrap_err();

        assert_eq!(
            error.error_description,
            format!("invalid issuer location https://{}", real_domain)
        );
        assert_eq!(
            async_error.error_description,
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
        let async_issuer_result = get_async_webfinger_discovery(&resource);

        assert!(issuer_result.is_err());
        assert!(async_issuer_result.is_err());

        let error = issuer_result.unwrap_err();
        let async_error = async_issuer_result.unwrap_err();

        assert_eq!(error.error_description, "invalid issuer location 1");
        assert_eq!(async_error.error_description, "invalid issuer location 1");
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
        let async_issuer_result = get_async_webfinger_discovery(&resource);

        assert!(issuer_result.is_err());
        assert!(async_issuer_result.is_err());

        let error = issuer_result.unwrap_err();
        let async_error = async_issuer_result.unwrap_err();

        assert_eq!(
            format!(
                "discovered issuer mismatch, expected https://{}, got: https://another.issuer.com",
                real_domain
            ),
            error.error_description
        );
        assert_eq!(
            format!(
                "discovered issuer mismatch, expected https://{}, got: https://another.issuer.com",
                real_domain
            ),
            async_error.error_description
        );

        webfinger.assert_hits(2);
        discovery.assert_hits(2);
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
        let async_issuer_result = get_async_webfinger_discovery(&url);

        assert!(issuer_result.is_ok());
        assert!(async_issuer_result.is_ok());

        webfinger.assert_hits(2);
        discovery.assert_hits(2);
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
        let async_issuer_result = get_async_webfinger_discovery(&real_domain_with_port);

        assert!(issuer_result.is_ok());
        assert!(async_issuer_result.is_ok());

        webfinger.assert_hits(2);
        discovery.assert_hits(2);
    }

    #[test]
    fn can_discover_using_the_acct_syntax() {
        let server = MockServer::start();

        let real_domain = get_url_with_count("opacct.example<>.com");
        let resource = format!("acct:juliet%40capulet.example@{}", real_domain);

        let body_wf = format!("{{\"subject\":\"{0}\",\"links\":[{{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://{1}\"}}]}}", resource, real_domain);
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
        let async_issuer_result = get_async_webfinger_discovery(&resource);

        assert!(issuer_result.is_ok());
        assert!(async_issuer_result.is_ok());

        webfinger.assert_hits(2);
        discovery.assert_hits(2);
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

            let body_wf = format!("{{\"subject\":\"{0}\",\"links\":[{{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://{1}\"}}]}}", resource, real_domain);
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

            let interceptor = |_request: &crate::types::Request| {
                let mut headers = HeaderMap::new();
                headers.append("custom", HeaderValue::from_static("foo"));
                RequestOptions {
                    headers,
                    timeout: Duration::from_millis(3500),
                }
            };

            let issuer_result =
                Issuer::webfinger_with_interceptor(&resource, Box::new(interceptor));

            webfinger.assert();
            discovery.assert();
            assert!(issuer_result.is_ok());
        }

        #[test]
        fn allows_for_http_options_to_be_defined_for_issuer_webfinger_calls_async() {
            let server = MockServer::start();

            let real_domain = get_url_with_count("op.example<>.com");
            let resource = format!("acct:juliet@{}", real_domain);

            let body_wf = format!("{{\"subject\":\"{0}\",\"links\":[{{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://{1}\"}}]}}", resource, real_domain);
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

            let interceptor = |_request: &crate::types::Request| {
                let mut headers = HeaderMap::new();
                headers.append("custom", HeaderValue::from_static("foo"));
                RequestOptions {
                    headers,
                    timeout: Duration::from_millis(3500),
                }
            };

            let async_runtime = tokio::runtime::Runtime::new().unwrap();

            let issuer_result: Result<Issuer, crate::OidcClientError> =
                async_runtime.block_on(async {
                    Issuer::webfinger_with_interceptor_async(&resource, Box::new(interceptor)).await
                });

            webfinger.assert();
            discovery.assert();
            assert!(issuer_result.is_ok());
        }
    }
}

#[cfg(test)]
mod issuer_new {
    use crate::issuer::Issuer;
    use crate::IssuerMetadata;
    use std::collections::HashMap;

    #[test]
    fn accepts_the_recognized_metadata() {
        let metadata = IssuerMetadata {
            issuer: "https://accounts.google.com".to_string(),
            authorization_endpoint: Some(
                "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            ),
            token_endpoint: Some("https://www.googleapis.com/oauth2/v4/token".to_string()),
            userinfo_endpoint: Some("https://www.googleapis.com/oauth2/v3/userinfo".to_string()),
            jwks_uri: Some("https://www.googleapis.com/oauth2/v3/certs".to_string()),
            ..IssuerMetadata::default()
        };

        let issuer = Issuer::new(metadata, None);

        assert_eq!(
            Some("https://accounts.google.com/o/oauth2/v2/auth".to_string()),
            issuer.authorization_endpoint
        );
        assert_eq!(
            Some("https://www.googleapis.com/oauth2/v4/token".to_string()),
            issuer.token_endpoint
        );
        assert_eq!(
            Some("https://www.googleapis.com/oauth2/v3/userinfo".to_string()),
            issuer.userinfo_endpoint
        );
        assert_eq!(
            Some("https://www.googleapis.com/oauth2/v3/certs".to_string()),
            issuer.jwks_uri
        );
    }

    #[test]
    fn does_not_assign_discovery_1_0_defaults_when_instantiating_manually() {
        let issuer = Issuer::new(IssuerMetadata::default(), None);

        assert!(issuer.claims_parameter_supported.is_none());
        assert!(issuer.grant_types_supported.is_none());
        assert!(issuer.request_parameter_supported.is_none());
        assert!(issuer.request_uri_parameter_supported.is_none());
        assert!(issuer.require_request_uri_registration.is_none());
        assert!(issuer.response_modes_supported.is_none());
        assert!(issuer.token_endpoint_auth_methods_supported.is_none());
    }

    #[test]
    fn assigns_introspection_and_revocation_auth_method_meta_from_token_if_both_are_not_defined() {
        let metadata = IssuerMetadata {
            token_endpoint: Some("https://op.example.com/token".to_string()),
            token_endpoint_auth_methods_supported: Some(vec![
                "client_secret_basic".to_string(),
                "client_secret_post".to_string(),
                "client_secret_jwt".to_string(),
            ]),
            token_endpoint_auth_signing_alg_values_supported: Some(vec![
                "RS256".to_string(),
                "HS256".to_string(),
            ]),
            ..IssuerMetadata::default()
        };

        let issuer = Issuer::new(metadata, None);

        assert_eq!(
            issuer.introspection_endpoint_auth_methods_supported,
            Some(vec![
                "client_secret_basic".to_string(),
                "client_secret_post".to_string(),
                "client_secret_jwt".to_string(),
            ])
        );
        assert_eq!(
            issuer.revocation_endpoint_auth_methods_supported,
            Some(vec![
                "client_secret_basic".to_string(),
                "client_secret_post".to_string(),
                "client_secret_jwt".to_string(),
            ])
        );

        assert_eq!(
            issuer.revocation_endpoint_auth_signing_alg_values_supported,
            Some(vec!["RS256".to_string(), "HS256".to_string()])
        );
        assert_eq!(
            issuer.introspection_endpoint_auth_signing_alg_values_supported,
            Some(vec!["RS256".to_string(), "HS256".to_string()])
        );
    }

    #[test]
    fn is_able_to_discover_custom_or_non_recognized_properties() {
        let mut other_fields: HashMap<String, serde_json::Value> = HashMap::new();
        other_fields.insert(
            "foo".to_string(),
            serde_json::Value::String("bar".to_string()),
        );

        let metadata = IssuerMetadata {
            issuer: "https://op.example.com".to_string(),
            other_fields,
            ..IssuerMetadata::default()
        };

        let issuer = Issuer::new(metadata, None);

        assert_eq!(issuer.issuer, "https://op.example.com".to_string());
        assert!(issuer.other_fields.contains_key("foo"));
        assert_eq!(
            issuer.other_fields.get("foo"),
            Some(&serde_json::Value::String("bar".to_string()))
        );
    }
}

#[cfg(test)]
mod issuer_instance {
    use crate::tests::{get_url_with_count, set_mock_domain};
    use crate::types::Jwks;
    use crate::{Issuer, IssuerMetadata};
    use httpmock::Method::GET;
    use httpmock::MockServer;

    fn get_default_jwks() -> String {
        let mut jwks = Jwks::default();
        jwks.generate("RSA", None, None);
        serde_json::to_string(&jwks).unwrap()
    }

    #[test]
    fn requires_jwks_uri_to_be_configured() {
        let mut issuer = Issuer::new(IssuerMetadata::default(), None);

        assert!(issuer.get_keystore(false).is_err());
        assert_eq!(
            issuer.get_keystore(false).unwrap_err().error_description,
            "jwks_uri must be configured on the issuer".to_string()
        );

        let async_runtime = tokio::runtime::Runtime::new().unwrap();
        async_runtime.block_on(async {
            assert!(issuer.get_keystore_async(false).await.is_err());
            assert_eq!(
                issuer
                    .get_keystore_async(false)
                    .await
                    .unwrap_err()
                    .error_description,
                "jwks_uri must be configured on the issuer".to_string()
            );
        });
    }

    #[test]
    fn does_not_refetch_immediately() {
        let real_domain = get_url_with_count("op.example<>.com");

        let server = MockServer::start();

        let mock_server = server.mock(|when, then| {
            when.method(GET)
                // TODO: should validate headers
                .path("/jwks");
            then.status(200)
                .header("content-type", "application/jwk-set+json")
                .body(get_default_jwks());
        });

        set_mock_domain(&real_domain.to_string(), server.port());

        let issuer = format!("https://{}", real_domain);
        let jwks_uri = format!("https://{}/jwks", real_domain);

        let metadata = IssuerMetadata {
            issuer,
            jwks_uri: Some(jwks_uri),
            ..IssuerMetadata::default()
        };

        let mut issuer = Issuer::new(metadata, None);

        assert!(issuer.get_keystore(true).is_ok());

        let _ = issuer.get_keystore(false).unwrap();

        mock_server.assert_hits(1);
    }

    #[test]
    fn does_not_refetch_immediately_async() {
        let real_domain = get_url_with_count("op.example<>.com");

        let server = MockServer::start();

        let mock_server = server.mock(|when, then| {
            when.method(GET)
                // TODO: should validate headers
                .path("/jwks");
            then.status(200)
                .header("content-type", "application/jwk-set+json")
                .body(get_default_jwks());
        });

        set_mock_domain(&real_domain.to_string(), server.port());

        let issuer = format!("https://{}", real_domain);
        let jwks_uri = format!("https://{}/jwks", real_domain);

        let metadata = IssuerMetadata {
            issuer,
            jwks_uri: Some(jwks_uri),
            ..IssuerMetadata::default()
        };

        let mut issuer = Issuer::new(metadata, None);

        let async_runtime = tokio::runtime::Runtime::new().unwrap();
        async_runtime.block_on(async {
            assert!(issuer.get_keystore_async(true).await.is_ok());

            let _ = issuer.get_keystore_async(false).await.unwrap();
        });

        mock_server.assert_hits(1);
    }

    #[test]
    fn refetches_if_asked_to() {
        let real_domain = get_url_with_count("op.example<>.com");

        let server = MockServer::start();

        let mock_server = server.mock(|when, then| {
            when.method(GET)
                // TODO: should validate headers
                .path("/jwks");
            then.status(200)
                .header("content-type", "application/jwk-set+json")
                .body(get_default_jwks());
        });

        set_mock_domain(&real_domain.to_string(), server.port());

        let issuer = format!("https://{}", real_domain);
        let jwks_uri = format!("https://{}/jwks", real_domain);

        let metadata = IssuerMetadata {
            issuer,
            jwks_uri: Some(jwks_uri),
            ..IssuerMetadata::default()
        };

        let mut issuer = Issuer::new(metadata, None);

        assert!(issuer.get_keystore(true).is_ok());
        assert!(issuer.get_keystore(true).is_ok());

        mock_server.assert_hits(2);
    }

    #[test]
    fn refetches_if_asked_to_async() {
        let real_domain = get_url_with_count("op.example<>.com");

        let server = MockServer::start();

        let mock_server = server.mock(|when, then| {
            when.method(GET)
                // TODO: should validate headers
                .path("/jwks");
            then.status(200)
                .header("content-type", "application/jwk-set+json")
                .body(get_default_jwks());
        });

        set_mock_domain(&real_domain.to_string(), server.port());

        let issuer = format!("https://{}", real_domain);
        let jwks_uri = format!("https://{}/jwks", real_domain);

        let metadata = IssuerMetadata {
            issuer,
            jwks_uri: Some(jwks_uri),
            ..IssuerMetadata::default()
        };

        let mut issuer = Issuer::new(metadata, None);

        let async_runtime = tokio::runtime::Runtime::new().unwrap();
        async_runtime.block_on(async {
            assert!(issuer.get_keystore_async(true).await.is_ok());
            assert!(issuer.get_keystore_async(true).await.is_ok());
        });

        mock_server.assert_hits(2);
    }

    #[test]
    fn rejects_when_no_matching_key_is_found() {
        let real_domain = get_url_with_count("op.example<>.com");

        let server = MockServer::start();

        let _mock_server = server.mock(|when, then| {
            when.method(GET)
                // TODO: should validate headers
                .path("/jwks");
            then.status(200)
                .header("content-type", "application/jwk-set+json")
                .body(get_default_jwks());
        });

        set_mock_domain(&real_domain.to_string(), server.port());

        let issuer = format!("https://{}", real_domain);
        let jwks_uri = format!("https://{}/jwks", real_domain);

        let metadata = IssuerMetadata {
            issuer,
            jwks_uri: Some(jwks_uri),
            ..IssuerMetadata::default()
        };

        let mut issuer = Issuer::new(metadata, None);

        let jwk_result = issuer.get_jwk(
            Some("RS256".to_string()),
            Some("sig".to_string()),
            Some("noway".to_string()),
        );

        let expected_error = "no valid key found in issuer\'s jwks_uri for key parameters kid: noway, alg: RS256, key_use: sig";

        assert!(jwk_result.is_err());

        let error = jwk_result.unwrap_err();

        assert_eq!(expected_error, error.error_description);

        let async_runtime = tokio::runtime::Runtime::new().unwrap();
        async_runtime.block_on(async {
            let jwk_result_async = issuer
                .get_jwk_async(
                    Some("RS256".to_string()),
                    Some("sig".to_string()),
                    Some("noway".to_string()),
                )
                .await;

            assert!(jwk_result_async.is_err());

            let error_async = jwk_result_async.unwrap_err();

            assert_eq!(expected_error, error_async.error_description);
        });
    }

    #[test]
    fn requires_a_kid_when_multiple_matches_are_found() {
        let real_domain = get_url_with_count("op.example<>.com");

        let server = MockServer::start();

        let mut jwks = Jwks::default();
        jwks.generate("RSA", None, None);
        jwks.generate("RSA", None, None);
        let jwks = serde_json::to_string(&jwks).unwrap();

        let _mock_server = server.mock(|when, then| {
            when.method(GET)
                // TODO: should validate headers
                .path("/jwks");

            then.status(200)
                .header("content-type", "application/jwk-set+json")
                .body(jwks);
        });

        set_mock_domain(&real_domain.to_string(), server.port());

        let issuer = format!("https://{}", real_domain);
        let jwks_uri = format!("https://{}/jwks", real_domain);

        let metadata = IssuerMetadata {
            issuer,
            jwks_uri: Some(jwks_uri),
            ..IssuerMetadata::default()
        };

        let mut issuer = Issuer::new(metadata, None);

        let jwk_result = issuer.get_jwk(Some("RS256".to_string()), Some("sig".to_string()), None);

        let expected_error = "multiple matching keys found in issuer\'s jwks_uri for key parameters kid: , key_use: sig, alg: RS256, kid must be provided in this case";

        assert!(jwk_result.is_err());

        let error = jwk_result.unwrap_err();

        assert_eq!(expected_error, error.error_description);

        let async_runtime = tokio::runtime::Runtime::new().unwrap();
        async_runtime.block_on(async {
            let jwk_result_async = issuer
                .get_jwk_async(Some("RS256".to_string()), Some("sig".to_string()), None)
                .await;

            assert!(jwk_result_async.is_err());

            let error_async = jwk_result_async.unwrap_err();

            assert_eq!(expected_error, error_async.error_description);
        });
    }

    #[test]
    fn multiple_keys_can_match_jwt_header() {
        let real_domain = get_url_with_count("op.example<>.com");

        let server = MockServer::start();

        let mut jwks = Jwks::default();

        let kid = uuid::Uuid::new_v4().to_string();

        jwks.generate("RSA", None, Some(kid.clone()));
        jwks.generate("RSA", None, Some(kid.clone()));

        let jwks = serde_json::to_string(&jwks).unwrap();

        let _mock_server = server.mock(|when, then| {
            when.method(GET)
                // TODO: should validate headers
                .path("/jwks");

            then.status(200)
                .header("content-type", "application/jwk-set+json")
                .body(jwks);
        });

        set_mock_domain(&real_domain.to_string(), server.port());

        let issuer = format!("https://{}", real_domain);
        let jwks_uri = format!("https://{}/jwks", real_domain);

        let metadata = IssuerMetadata {
            issuer,
            jwks_uri: Some(jwks_uri),
            ..IssuerMetadata::default()
        };

        let mut issuer = Issuer::new(metadata, None);

        let jwk_result = issuer.get_jwk(
            Some("RS256".to_string()),
            Some("sig".to_string()),
            Some(kid.clone()),
        );

        assert!(jwk_result.is_ok());

        let matched_jwks = jwk_result.unwrap();

        assert!(matched_jwks.len() > 1);

        let async_runtime = tokio::runtime::Runtime::new().unwrap();
        async_runtime.block_on(async {
            let jwk_result_async = issuer
                .get_jwk_async(
                    Some("RS256".to_string()),
                    Some("sig".to_string()),
                    Some(kid),
                )
                .await;

            assert!(jwk_result_async.is_ok());

            let matched_jwks_async = jwk_result_async.unwrap();

            assert!(matched_jwks_async.len() > 1);
        });
    }

    #[cfg(test)]
    mod http_options {
        use std::time::Duration;

        use reqwest::header::{HeaderMap, HeaderValue};

        use crate::{tests::get_url_with_count, types::RequestOptions};

        use super::*;

        #[test]
        fn allows_for_http_options_to_be_defined_for_issuer_keystore_calls() {
            let server = MockServer::start();

            let real_domain = get_url_with_count("op.example<>.com");
            let issuer = format!("https://{}", real_domain);
            let jwks_uri = format!("https://{}/jwks", real_domain);

            let mock_server = server.mock(|when, then| {
                when.method(GET).header_exists("testHeader").path("/jwks");

                then.status(200)
                    .header("content-type", "application/jwk-set+json")
                    .body(get_default_jwks());
            });

            let interceptor = |_request: &crate::types::Request| {
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
                Box::new(interceptor),
            );

            let metadata = IssuerMetadata {
                issuer,
                jwks_uri: Some(jwks_uri),
                ..IssuerMetadata::default()
            };

            let mut issuer = Issuer::new(metadata, Some(Box::new(interceptor)));

            let _ = issuer.get_keystore(false);

            mock_server.assert_hits(1);
        }

        #[test]
        fn allows_for_http_options_to_be_defined_for_issuer_keystore_calls_async() {
            let server = MockServer::start();

            let real_domain = get_url_with_count("op.example<>.com");
            let issuer = format!("https://{}", real_domain);
            let jwks_uri = format!("https://{}/jwks", real_domain);

            let mock_server = server.mock(|when, then| {
                when.method(GET).header_exists("testHeader").path("/jwks");

                then.status(200)
                    .header("content-type", "application/jwk-set+json")
                    .body(get_default_jwks());
            });

            let interceptor = |_request: &crate::types::Request| {
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
                Box::new(interceptor),
            );

            let metadata = IssuerMetadata {
                issuer,
                jwks_uri: Some(jwks_uri),
                ..IssuerMetadata::default()
            };

            let mut issuer = Issuer::new(metadata, Some(Box::new(interceptor)));

            let async_runtime = tokio::runtime::Runtime::new().unwrap();

            async_runtime.block_on(async {
                let _ = issuer.get_keystore_async(false).await;
                mock_server.assert_hits(1);
            });
        }
    }
}
