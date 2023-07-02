#[cfg(test)]
mod issuer_discovery_tests {
    use crate::issuer::Issuer;
    use crate::tests::test_interceptors::get_default_test_interceptor;
    use crate::types::OidcClientError;
    pub use httpmock::Method::GET;
    pub use httpmock::MockServer;

    pub fn get_async_issuer_discovery(issuer: &str, port: u16) -> Result<Issuer, OidcClientError> {
        let async_runtime = tokio::runtime::Runtime::new().unwrap();

        let result: Result<Issuer, OidcClientError> = async_runtime.block_on(async {
            let iss = Issuer::discover_async(issuer, get_default_test_interceptor(port)).await;
            return iss;
        });
        result
    }

    pub fn get_default_expected_discovery_document() -> String {
        "{\"authorization_endpoint\":\"https://op.example.com/o/oauth2/v2/auth\",\"issuer\":\"https://op.example.com\",\"jwks_uri\":\"https://op.example.com/oauth2/v3/certs\",\"token_endpoint\":\"https://op.example.com/oauth2/v4/token\",\"userinfo_endpoint\":\"https://op.example.com/oauth2/v3/userinfo\"}".to_string()
    }

    #[cfg(test)]
    mod custom_well_known {

        use super::*;

        #[test]
        fn accepts_and_assigns_the_discovered_metadata() {
            let mock_http_server = MockServer::start();

            let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET).path("/.well-known/custom-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(get_default_expected_discovery_document());
            });

            let issuer_discovery_url = "https://op.example.com/.well-known/custom-configuration";

            let issuer = Issuer::discover(
                &issuer_discovery_url,
                get_default_test_interceptor(mock_http_server.port()),
            )
            .unwrap();
            let async_issuer =
                get_async_issuer_discovery(&issuer_discovery_url, mock_http_server.port()).unwrap();

            assert_eq!("https://op.example.com", issuer.issuer);
            assert_eq!("https://op.example.com", async_issuer.issuer,);

            assert_eq!(
                "https://op.example.com/oauth2/v3/certs",
                issuer.jwks_uri.unwrap(),
            );
            assert_eq!(
                "https://op.example.com/oauth2/v3/certs",
                async_issuer.jwks_uri.unwrap(),
            );

            assert_eq!(
                "https://op.example.com/oauth2/v4/token",
                issuer.token_endpoint.unwrap(),
            );
            assert_eq!(
                "https://op.example.com/oauth2/v4/token",
                async_issuer.token_endpoint.unwrap(),
            );

            assert_eq!(
                "https://op.example.com/oauth2/v3/userinfo",
                issuer.userinfo_endpoint.unwrap(),
            );
            assert_eq!(
                "https://op.example.com/oauth2/v3/userinfo",
                async_issuer.userinfo_endpoint.unwrap(),
            );

            assert_eq!(
                "https://op.example.com/o/oauth2/v2/auth",
                issuer.authorization_endpoint.unwrap(),
            );
            assert_eq!(
                "https://op.example.com/o/oauth2/v2/auth",
                async_issuer.authorization_endpoint.unwrap(),
            );
        }
    }

    #[cfg(test)]
    mod well_known {

        use super::*;

        #[test]
        fn accepts_and_assigns_the_discovered_metadata() {
            let mock_http_server = MockServer::start();

            let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET).path("/.well-known/openid-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(get_default_expected_discovery_document());
            });

            let issuer_discovery_url = "https://op.example.com/.well-known/openid-configuration";

            let issuer = Issuer::discover(
                &issuer_discovery_url,
                get_default_test_interceptor(mock_http_server.port()),
            )
            .unwrap();
            let async_issuer =
                get_async_issuer_discovery(&issuer_discovery_url, mock_http_server.port()).unwrap();

            assert_eq!("https://op.example.com", issuer.issuer);
            assert_eq!("https://op.example.com", async_issuer.issuer,);

            assert_eq!(
                "https://op.example.com/oauth2/v3/certs",
                issuer.jwks_uri.unwrap(),
            );
            assert_eq!(
                "https://op.example.com/oauth2/v3/certs",
                async_issuer.jwks_uri.unwrap(),
            );

            assert_eq!(
                "https://op.example.com/oauth2/v4/token",
                issuer.token_endpoint.unwrap(),
            );
            assert_eq!(
                "https://op.example.com/oauth2/v4/token",
                async_issuer.token_endpoint.unwrap(),
            );

            assert_eq!(
                "https://op.example.com/oauth2/v3/userinfo",
                issuer.userinfo_endpoint.unwrap(),
            );
            assert_eq!(
                "https://op.example.com/oauth2/v3/userinfo",
                async_issuer.userinfo_endpoint.unwrap(),
            );

            assert_eq!(
                "https://op.example.com/o/oauth2/v2/auth",
                issuer.authorization_endpoint.unwrap(),
            );
            assert_eq!(
                "https://op.example.com/o/oauth2/v2/auth",
                async_issuer.authorization_endpoint.unwrap(),
            );
        }

        #[test]
        fn can_be_discovered_by_omitting_well_known() {
            let mock_http_server = MockServer::start();

            let expected_discovery_document = "{\"issuer\":\"https://op.example.com\"}";

            let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET).path("/.well-known/openid-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(expected_discovery_document);
            });

            let issuer_discovery_url = "https://op.example.com";

            let issuer = Issuer::discover(
                &issuer_discovery_url,
                get_default_test_interceptor(mock_http_server.port()),
            )
            .unwrap();
            let async_issuer =
                get_async_issuer_discovery(&issuer_discovery_url, mock_http_server.port()).unwrap();

            assert_eq!(issuer_discovery_url, issuer.issuer);
            assert_eq!(issuer_discovery_url, async_issuer.issuer);
        }

        #[test]
        fn discovers_issuers_with_path_components_with_trailing_slash() {
            let mock_http_server = MockServer::start();

            let expected_discovery_document = "{\"issuer\":\"https://op.example.com/oidc\"}";

            let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET)
                    .path("/oidc/.well-known/openid-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(expected_discovery_document);
            });

            let issuer_discovery_url = "https://op.example.com/oidc/";

            let issuer = Issuer::discover(
                &issuer_discovery_url,
                get_default_test_interceptor(mock_http_server.port()),
            )
            .unwrap();
            let async_issuer =
                get_async_issuer_discovery(&issuer_discovery_url, mock_http_server.port()).unwrap();

            assert_eq!("https://op.example.com/oidc", issuer.issuer,);
            assert_eq!("https://op.example.com/oidc", async_issuer.issuer,);
        }

        #[test]
        fn discovers_issuers_with_path_components_without_trailing_slash() {
            let mock_http_server = MockServer::start();

            let expected_discovery_document = "{\"issuer\":\"https://op.example.com/oidc\"}";

            let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET)
                    .path("/oidc/.well-known/openid-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(&expected_discovery_document);
            });

            let issuer_discovery_url = "https://op.example.com/oidc";

            let issuer = Issuer::discover(
                &issuer_discovery_url,
                get_default_test_interceptor(mock_http_server.port()),
            )
            .unwrap();
            let async_issuer =
                get_async_issuer_discovery(&issuer_discovery_url, mock_http_server.port()).unwrap();

            assert_eq!("https://op.example.com/oidc", issuer.issuer,);
            assert_eq!("https://op.example.com/oidc", async_issuer.issuer,);
        }

        #[test]
        fn discovering_issuers_with_well_known_uri_including_path_and_query() {
            let mock_http_server = MockServer::start();

            let expected_discovery_document = "{\"issuer\":\"https://op.example.com/oidc\"}";

            let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET)
                    .path("/oidc/.well-known/openid-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(&expected_discovery_document);
            });

            let issuer_discovery_url =
                "https://op.example.com/oidc/.well-known/openid-configuration?foo=bar";

            let issuer = Issuer::discover(
                &issuer_discovery_url,
                get_default_test_interceptor(mock_http_server.port()),
            )
            .unwrap();
            let async_issuer =
                get_async_issuer_discovery(&issuer_discovery_url, mock_http_server.port()).unwrap();

            assert_eq!("https://op.example.com/oidc", issuer.issuer,);
            assert_eq!("https://op.example.com/oidc", async_issuer.issuer,);
        }
    }

    mod well_known_oauth_authorization_server {

        use super::*;

        #[test]
        fn accepts_and_assigns_the_discovered_metadata() {
            let mock_http_server = MockServer::start();

            let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET)
                    .path("/.well-known/oauth-authorization-server");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(get_default_expected_discovery_document());
            });

            let issuer_discovery_url =
                "https://op.example.com/.well-known/oauth-authorization-server";

            let issuer = Issuer::discover(
                &issuer_discovery_url,
                get_default_test_interceptor(mock_http_server.port()),
            )
            .unwrap();
            let async_issuer =
                get_async_issuer_discovery(&issuer_discovery_url, mock_http_server.port()).unwrap();

            assert_eq!("https://op.example.com", issuer.issuer);
            assert_eq!("https://op.example.com", async_issuer.issuer,);

            assert_eq!(
                "https://op.example.com/oauth2/v3/certs",
                issuer.jwks_uri.unwrap(),
            );
            assert_eq!(
                "https://op.example.com/oauth2/v3/certs",
                async_issuer.jwks_uri.unwrap(),
            );

            assert_eq!(
                "https://op.example.com/oauth2/v4/token",
                issuer.token_endpoint.unwrap(),
            );
            assert_eq!(
                "https://op.example.com/oauth2/v4/token",
                async_issuer.token_endpoint.unwrap(),
            );

            assert_eq!(
                "https://op.example.com/oauth2/v3/userinfo",
                issuer.userinfo_endpoint.unwrap(),
            );
            assert_eq!(
                "https://op.example.com/oauth2/v3/userinfo",
                async_issuer.userinfo_endpoint.unwrap(),
            );

            assert_eq!(
                "https://op.example.com/o/oauth2/v2/auth",
                issuer.authorization_endpoint.unwrap(),
            );
            assert_eq!(
                "https://op.example.com/o/oauth2/v2/auth",
                async_issuer.authorization_endpoint.unwrap(),
            );
        }

        #[test]
        fn discovering_issuers_with_well_known_uri_including_path_and_query() {
            let mock_http_server = MockServer::start();

            let expected_discovery_document = "{\"issuer\":\"https://op.example.com/oauth2\"}";

            let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET)
                    .path("/.well-known/oauth-authorization-server/oauth2");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(&expected_discovery_document);
            });

            let issuer_discovery_url =
                "https://op.example.com/.well-known/oauth-authorization-server/oauth2?foo=bar";

            let issuer = Issuer::discover(
                &issuer_discovery_url,
                get_default_test_interceptor(mock_http_server.port()),
            )
            .unwrap();
            let async_issuer =
                get_async_issuer_discovery(&issuer_discovery_url, mock_http_server.port()).unwrap();

            assert_eq!("https://op.example.com/oauth2", issuer.issuer,);
            assert_eq!("https://op.example.com/oauth2", async_issuer.issuer,);
        }
    }

    #[test]
    fn assigns_discovery_1_0_defaults_1_of_2() {
        let mock_http_server = MockServer::start();

        let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200)
                .header("content-type", "application/json")
                .body(get_default_expected_discovery_document());
        });

        let issuer_discovery_url = "https://op.example.com/.well-known/openid-configuration";

        let issuer = Issuer::discover(
            &issuer_discovery_url,
            get_default_test_interceptor(mock_http_server.port()),
        )
        .unwrap();
        let async_issuer =
            get_async_issuer_discovery(&issuer_discovery_url, mock_http_server.port()).unwrap();

        assert_eq!(false, issuer.claims_parameter_supported.unwrap());
        assert_eq!(false, async_issuer.claims_parameter_supported.unwrap());

        assert_eq!(
            vec!["authorization_code".to_string(), "implicit".to_string(),],
            issuer.grant_types_supported.unwrap(),
        );
        assert_eq!(
            vec!["authorization_code".to_string(), "implicit".to_string(),],
            async_issuer.grant_types_supported.unwrap(),
        );

        assert_eq!(false, issuer.request_parameter_supported.unwrap());
        assert_eq!(false, async_issuer.request_parameter_supported.unwrap());

        assert_eq!(true, issuer.request_uri_parameter_supported.unwrap());
        assert_eq!(true, async_issuer.request_uri_parameter_supported.unwrap());

        assert_eq!(false, issuer.require_request_uri_registration.unwrap());
        assert_eq!(
            false,
            async_issuer.require_request_uri_registration.unwrap(),
        );

        assert_eq!(
            vec!["query".to_string(), "fragment".to_string()],
            issuer.response_modes_supported.unwrap(),
        );
        assert_eq!(
            vec!["query".to_string(), "fragment".to_string()],
            async_issuer.response_modes_supported.unwrap(),
        );

        assert_eq!(vec!["normal".to_string()], issuer.claim_types_supported);
        assert_eq!(
            vec!["normal".to_string()],
            async_issuer.claim_types_supported,
        );

        assert_eq!(
            vec!["client_secret_basic".to_string()],
            issuer.token_endpoint_auth_methods_supported.unwrap(),
        );
        assert_eq!(
            vec!["client_secret_basic".to_string()],
            async_issuer.token_endpoint_auth_methods_supported.unwrap(),
        );
    }

    #[test]
    fn assigns_discovery_1_0_defaults_2_of_2() {
        let mock_http_server = MockServer::start();

        let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200)
                .header("content-type", "application/json")
                .body(get_default_expected_discovery_document());
        });

        let issuer_discovery_url = "https://op.example.com";

        let issuer = Issuer::discover(
            &issuer_discovery_url,
            get_default_test_interceptor(mock_http_server.port()),
        )
        .unwrap();
        let async_issuer =
            get_async_issuer_discovery(&issuer_discovery_url, mock_http_server.port()).unwrap();

        assert_eq!(false, issuer.claims_parameter_supported.unwrap());
        assert_eq!(false, async_issuer.claims_parameter_supported.unwrap());

        assert_eq!(
            vec!["authorization_code".to_string(), "implicit".to_string(),],
            issuer.grant_types_supported.unwrap(),
        );
        assert_eq!(
            vec!["authorization_code".to_string(), "implicit".to_string(),],
            async_issuer.grant_types_supported.unwrap(),
        );

        assert_eq!(false, issuer.request_parameter_supported.unwrap());
        assert_eq!(false, async_issuer.request_parameter_supported.unwrap());

        assert_eq!(true, issuer.request_uri_parameter_supported.unwrap());
        assert_eq!(true, async_issuer.request_uri_parameter_supported.unwrap());

        assert_eq!(false, issuer.require_request_uri_registration.unwrap());
        assert_eq!(
            false,
            async_issuer.require_request_uri_registration.unwrap(),
        );

        assert_eq!(
            vec!["query".to_string(), "fragment".to_string()],
            issuer.response_modes_supported.unwrap(),
        );
        assert_eq!(
            vec!["query".to_string(), "fragment".to_string()],
            async_issuer.response_modes_supported.unwrap(),
        );

        assert_eq!(vec!["normal".to_string()], issuer.claim_types_supported);
        assert_eq!(
            vec!["normal".to_string()],
            async_issuer.claim_types_supported,
        );

        assert_eq!(
            vec!["client_secret_basic".to_string()],
            issuer.token_endpoint_auth_methods_supported.unwrap(),
        );
        assert_eq!(
            vec!["client_secret_basic".to_string()],
            async_issuer.token_endpoint_auth_methods_supported.unwrap(),
        );
    }

    #[test]
    fn is_rejected_with_op_error_upon_oidc_error() {
        let mock_http_server = MockServer::start();

        let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(500).body(
                "{\"error\":\"server_error\",\"error_description\":\"bad things are happening\"}",
            );
        });

        let issuer_discovery_url = "https://op.example.com";

        let error = Issuer::discover(
            &issuer_discovery_url,
            get_default_test_interceptor(mock_http_server.port()),
        )
        .unwrap_err();
        let error_async =
            get_async_issuer_discovery(&issuer_discovery_url, mock_http_server.port()).unwrap_err();

        assert!(error.is_op_error());
        assert!(error_async.is_op_error());

        let err = error.op_error().error;
        let err_async = error_async.op_error().error;

        assert_eq!(err.error, "server_error");
        assert_eq!(err_async.error, "server_error");

        assert_eq!(
            Some("bad things are happening".to_string()),
            err.error_description
        );
        assert_eq!(
            Some("bad things are happening".to_string()),
            err_async.error_description
        );
    }

    #[test]
    fn is_rejected_with_error_when_no_absolute_url_is_provided() {
        let error = Issuer::discover("op.example.com/.well-known/foobar", None).unwrap_err();
        let error_async =
            get_async_issuer_discovery("op.example.com/.well-known/foobar", 0).unwrap_err();

        assert!(error.is_type_error());
        assert!(error_async.is_type_error());

        let err = error.type_error().error;
        let err_async = error_async.type_error().error;

        assert_eq!("only valid absolute URLs can be requested", err.message,);
        assert_eq!(
            "only valid absolute URLs can be requested",
            err_async.message,
        );
    }

    #[test]
    fn is_rejected_with_rp_error_when_error_is_not_a_string() {
        let mock_http_server = MockServer::start();

        let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(400)
                .body("{\"error\": {},\"error_description\":\"bad things are happening\"}");
        });

        let issuer_discovery_url = "https://op.example.com";

        let error = Issuer::discover(
            &issuer_discovery_url,
            get_default_test_interceptor(mock_http_server.port()),
        )
        .unwrap_err();
        let error_async =
            get_async_issuer_discovery(&issuer_discovery_url, mock_http_server.port()).unwrap_err();

        assert!(error.is_op_error());
        assert!(error_async.is_op_error());

        let err = error.op_error().error;
        let err_async = error_async.op_error().error;

        assert_eq!("server_error", err.error);
        assert_eq!("server_error", err_async.error);

        assert_eq!(
            Some("expected 200 OK, got: 400 Bad Request".to_string()),
            err.error_description,
        );
        assert_eq!(
            Some("expected 200 OK, got: 400 Bad Request".to_string()),
            err_async.error_description,
        );
    }

    #[test]
    fn is_rejected_with_when_non_200_is_returned() {
        let mock_http_server = MockServer::start();

        let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(500);
        });

        let issuer_discovery_url = "https://op.example.com";

        let error = Issuer::discover(
            &issuer_discovery_url,
            get_default_test_interceptor(mock_http_server.port()),
        )
        .unwrap_err();
        let error_async =
            get_async_issuer_discovery(&issuer_discovery_url, mock_http_server.port()).unwrap_err();

        assert!(error.is_op_error());
        assert!(error_async.is_op_error());

        let err = error.op_error();
        let err_async = error_async.op_error();

        assert_eq!("server_error", err.error.error);
        assert_eq!("server_error", err_async.error.error);

        assert_eq!(
            Some("expected 200 OK, got: 500 Internal Server Error".to_string()),
            err.error.error_description,
        );
        assert_eq!(
            Some("expected 200 OK, got: 500 Internal Server Error".to_string()),
            err_async.error.error_description,
        );

        assert!(err.response.is_some());
        assert!(err_async.response.is_some());
    }

    #[test]
    fn is_rejected_with_json_parse_error_upon_invalid_response() {
        let mock_http_server = MockServer::start();

        let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).body("{\"notavalid\"}");
        });

        let issuer_discovery_url = "https://op.example.com";

        let error = Issuer::discover(
            &issuer_discovery_url,
            get_default_test_interceptor(mock_http_server.port()),
        )
        .unwrap_err();
        let error_async =
            get_async_issuer_discovery(&issuer_discovery_url, mock_http_server.port()).unwrap_err();

        assert!(error.is_type_error());
        assert!(error_async.is_type_error());

        let err = error.type_error();
        let err_async = error_async.type_error();

        assert_eq!("unexpected body type", err.error.message);
        assert_eq!("unexpected body type", err_async.error.message);

        assert!(err.response.is_some());
        assert!(err_async.response.is_some());
    }

    #[test]
    fn is_rejected_when_no_body_is_returned() {
        let mock_http_server = MockServer::start();

        let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200);
        });

        let issuer_discovery_url = "https://op.example.com";

        let error = Issuer::discover(
            &issuer_discovery_url,
            get_default_test_interceptor(mock_http_server.port()),
        )
        .unwrap_err();
        let error_async =
            get_async_issuer_discovery(&issuer_discovery_url, mock_http_server.port()).unwrap_err();

        assert!(error.is_op_error());
        assert!(error_async.is_op_error());

        let err = error.op_error().error;
        let err_async = error_async.op_error().error;

        assert_eq!("server_error", err.error);
        assert_eq!("server_error", err_async.error);

        assert_eq!(
            Some("expected 200 OK with body but no body was returned".to_string()),
            err.error_description,
        );
        assert_eq!(
            Some("expected 200 OK with body but no body was returned".to_string()),
            err_async.error_description,
        );
    }

    #[test]
    fn is_rejected_when_unepexted_status_code_is_returned() {
        let mock_http_server = MockServer::start();

        let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(301);
        });

        let issuer_discovery_url = "https://op.example.com";

        let error = Issuer::discover(
            &issuer_discovery_url,
            get_default_test_interceptor(mock_http_server.port()),
        )
        .unwrap_err();
        let error_async =
            get_async_issuer_discovery(&issuer_discovery_url, mock_http_server.port()).unwrap_err();

        assert!(error.is_op_error());
        assert!(error_async.is_op_error());

        let err = error.op_error().error;
        let err_async = error_async.op_error().error;

        assert_eq!("server_error", err.error);
        assert_eq!("server_error", err_async.error);

        assert_eq!(
            Some("expected 200 OK, got: 301 Moved Permanently".to_string()),
            err.error_description,
        );
        assert_eq!(
            Some("expected 200 OK, got: 301 Moved Permanently".to_string()),
            err_async.error_description,
        );
    }

    #[cfg(test)]
    mod http_options {

        use crate::tests::test_interceptors::TestInterceptor;

        use super::*;

        #[test]
        fn allows_for_http_options_to_be_defined_for_issuer_discover_calls() {
            let mock_http_server = MockServer::start();

            let auth_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET)
                    .header("testHeader", "testHeaderValue")
                    .path("/.well-known/custom-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(get_default_expected_discovery_document());
            });

            let _ = Issuer::discover(
                "https://op.example.com/.well-known/custom-configuration",
                Some(Box::new(TestInterceptor {
                    test_header: Some("testHeader".to_string()),
                    test_header_value: Some("testHeaderValue".to_string()),
                    test_server_port: Some(mock_http_server.port()),
                })),
            );

            auth_mock_server.assert_hits(1);
        }

        #[test]
        fn allows_for_http_options_to_be_defined_for_issuer_discover_calls_async() {
            let mock_http_server = MockServer::start();

            let auth_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET)
                    .header("testHeader", "testHeaderValue")
                    .path("/.well-known/custom-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(get_default_expected_discovery_document());
            });

            let async_runtime = tokio::runtime::Runtime::new().unwrap();

            let _ = async_runtime.block_on(async {
                Issuer::discover_async(
                    "https://op.example.com/.well-known/custom-configuration",
                    Some(Box::new(TestInterceptor {
                        test_header: Some("testHeader".to_string()),
                        test_header_value: Some("testHeaderValue".to_string()),
                        test_server_port: Some(mock_http_server.port()),
                    })),
                )
                .await
            });

            auth_mock_server.assert_hits(1);
        }
    }
}

#[cfg(test)]
mod issuer_webfinger_tests {

    use httpmock::Method::GET;
    use httpmock::MockServer;

    use crate::issuer::Issuer;
    use crate::tests::test_interceptors::get_default_test_interceptor;
    use crate::types::OidcClientError;

    pub fn get_async_webfinger_discovery(
        input: &str,
        port: u16,
    ) -> Result<Issuer, OidcClientError> {
        let async_runtime = tokio::runtime::Runtime::new().unwrap();

        let result: Result<Issuer, OidcClientError> = async_runtime.block_on(async {
            let iss = Issuer::webfinger_async(input, get_default_test_interceptor(port)).await;
            return iss;
        });
        result
    }

    #[test]
    fn can_discover_using_the_email_syntax() {
        let mock_http_server = MockServer::start();

        let webfinger_response_body = "{\"subject\":\"https://opemail.example.com/joe\",\"links\":[{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://opemail.example.com\"}]}";
        let discovery_document_response_body = "{\"authorization_endpoint\":\"https://opemail.example.com/o/oauth2/v2/auth\",\"issuer\":\"https://opemail.example.com\",\"jwks_uri\":\"https://opemail.example.com/oauth2/v3/certs\",\"token_endpoint\":\"https://opemail.example.com/oauth2/v4/token\",\"userinfo_endpoint\":\"https://opemail.example.com/oauth2/v3/userinfo\"}";

        let resource = "joe@opemail.example.com";

        let webfinger_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .path("/.well-known/webfinger")
                .query_param("resource", format!("acct:{}", &resource));
            then.status(200).body(webfinger_response_body);
        });

        let issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).body(discovery_document_response_body);
        });

        let _ = Issuer::webfinger(
            &resource,
            get_default_test_interceptor(mock_http_server.port()),
        );

        let _ = get_async_webfinger_discovery(&resource, mock_http_server.port());

        webfinger_mock_server.assert_hits(2);
        issuer_discovery_mock_server.assert_hits(2);
    }

    #[test]
    fn verifies_the_webfinger_responds_with_an_issuer() {
        let mock_http_server = MockServer::start();
        let webfinger_response_body =
            "{\"subject\":\"https://opemail.example.com/joe\",\"links\":[]}";

        let _webfinger_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .path("/.well-known/webfinger")
                .header("Accept", "application/json");
            then.status(200).body(webfinger_response_body);
        });

        let resource = "joe@opemail.example.com";

        let error = Issuer::webfinger(
            &resource,
            get_default_test_interceptor(mock_http_server.port()),
        )
        .unwrap_err();
        let error_async =
            get_async_webfinger_discovery(&resource, mock_http_server.port()).unwrap_err();

        assert_eq!(
            "no issuer found in webfinger response",
            error.rp_error().error.message,
        );
        assert_eq!(
            "no issuer found in webfinger response",
            error_async.rp_error().error.message,
        );
    }

    #[test]
    fn verifies_the_webfinger_responds_with_an_issuer_which_is_a_valid_issuer_value_1_of_2() {
        let mock_http_server = MockServer::start();

        let webfinger_response_body = "{\"subject\":\"https://opemail.example.com/joe\",\"links\":[{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://opemail.example.com\"}]}";

        let _webfinger_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/webfinger");
            then.status(200).body(webfinger_response_body);
        });

        let resource = "joe@opemail.example.com";

        let error = Issuer::webfinger(
            &resource,
            get_default_test_interceptor(mock_http_server.port()),
        )
        .unwrap_err();
        let error_async =
            get_async_webfinger_discovery(&resource, mock_http_server.port()).unwrap_err();

        assert_eq!(
            Some("invalid issuer location https://opemail.example.com".to_string()),
            error.op_error().error.error_description,
        );

        assert_eq!(
            Some("invalid issuer location https://opemail.example.com".to_string()),
            error_async.op_error().error.error_description,
        );
    }

    #[test]
    fn verifies_the_webfinger_responds_with_an_issuer_which_is_a_valid_issuer_value_2_of_2() {
        let mock_http_server = MockServer::start();

        let webfinger_response_body = "{\"subject\":\"https://opemail.example.com/joe\",\"links\":[{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"1\"}]}";

        let _webfinger = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/webfinger");
            then.status(200).body(webfinger_response_body);
        });

        let resource = "joe@opemail.example.com";

        let error = Issuer::webfinger(
            &resource,
            get_default_test_interceptor(mock_http_server.port()),
        )
        .unwrap_err();
        let error_async =
            get_async_webfinger_discovery(&resource, mock_http_server.port()).unwrap_err();

        assert_eq!(
            Some("invalid issuer location 1".to_string()),
            error.op_error().error.error_description
        );

        assert_eq!(
            Some("invalid issuer location 1".to_string()),
            error_async.op_error().error.error_description,
        );
    }

    // Todo: not implementing cache right now
    // #[test]
    // fn uses_cached_issuer_if_it_has_one() {
    //  mock_http_server server = MockServer::start();

    //     let auth_server_domain = get_url_with_count("opemail.example<>.com");

    //     let webfinger_response_body = format!("{{\"subject\":\"https://{0}/joe\",\"links\":[{{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://{0}\"}}]}}", auth_server_domain);
    //     let discovery_document_response_body = format!("{{\"authorization_endpoint\":\"https://{0}/o/oauth2/v2/auth\",\"issuer\":\"https://{0}\",\"jwks_uri\":\"https://{0}/oauth2/v3/certs\",\"token_endpoint\":\"https://{0}/oauth2/v4/token\",\"userinfo_endpoint\":\"https://{0}/oauth2/v3/userinfo\"}}", auth_server_domain);

    //     let resource = format!("joe@{}", auth_server_domain);

    //

    //     let webfinger_mock_server = mock_http_server.mock(|when, then| {
    //         when.method(GET).path("/.well-known/webfinger");
    //         then.status(200).body(webfinger_response_body);
    //     });

    //     let issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
    //         when.method(GET).path("/.well-known/openid-configuration");
    //         then.status(200).body(discovery_document_response_body);
    //     });

    //     let _ = Issuer::webfinger(&resource, None);
    //     let __ = Issuer::webfinger(&resource, None);

    //     webfinger_mock_server.assert_hits(2);
    //     issuer_discovery_mock_server.assert_hits(1);
    // }

    #[test]
    fn validates_the_discovered_issuer_is_the_same_as_from_webfinger() {
        let mock_http_server = MockServer::start();

        let webfinger_response_body ="{\"subject\":\"https://opemail.example.com/joe\",\"links\":[{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://opemail.example.com\"}]}";
        let discovery_document_response_body = "{\"authorization_endpoint\":\"https://opemail.example.com/o/oauth2/v2/auth\",\"issuer\":\"https://another.issuer.com\",\"jwks_uri\":\"https://opemail.example.com/oauth2/v3/certs\",\"token_endpoint\":\"https://opemail.example.com/oauth2/v4/token\",\"userinfo_endpoint\":\"https://opemail.example.com/oauth2/v3/userinfo\"}";

        let webfinger_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/webfinger");
            then.status(200).body(webfinger_response_body);
        });

        let issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).body(discovery_document_response_body);
        });

        let resource = "joe@opemail.example.com";

        let error = Issuer::webfinger(
            &resource,
            get_default_test_interceptor(mock_http_server.port()),
        )
        .unwrap_err();
        let error_async =
            get_async_webfinger_discovery(&resource, mock_http_server.port()).unwrap_err();

        assert_eq!(
            Some(
                "discovered issuer mismatch, expected https://opemail.example.com, got: https://another.issuer.com".to_string(),
            ),
            error.op_error().error.error_description,
        );
        assert_eq!(
            Some(
                "discovered issuer mismatch, expected https://opemail.example.com, got: https://another.issuer.com".to_string(),
            ),
            error_async.op_error().error.error_description,
        );

        webfinger_mock_server.assert_hits(2);
        issuer_discovery_mock_server.assert_hits(2);
    }

    #[test]
    fn can_discover_using_the_url_syntax() {
        let mock_http_server = MockServer::start();

        let webfinger_response_body = "{\"subject\":\"https://opurl.example.com/joe\",\"links\":[{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://opurl.example.com\"}]}";
        let discovery_document_response_body = "{\"authorization_endpoint\":\"https://opurl.example.com/o/oauth2/v2/auth\",\"issuer\":\"https://opurl.example.com\",\"jwks_uri\":\"https://opurl.example.com/oauth2/v3/certs\",\"token_endpoint\":\"https://opurl.example.com/oauth2/v4/token\",\"userinfo_endpoint\":\"https://opurl.example.com/oauth2/v3/userinfo\"}";

        let webfinger_url = "https://opurl.example.com/joe";

        let webfinger_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .path("/.well-known/webfinger")
                .query_param("resource", webfinger_url);
            then.status(200).body(webfinger_response_body);
        });

        let issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).body(discovery_document_response_body);
        });

        let issuer_result = Issuer::webfinger(
            &webfinger_url,
            get_default_test_interceptor(mock_http_server.port()),
        );
        let async_issuer_result =
            get_async_webfinger_discovery(&webfinger_url, mock_http_server.port());

        assert!(issuer_result.is_ok());
        assert!(async_issuer_result.is_ok());

        webfinger_mock_server.assert_hits(2);
        issuer_discovery_mock_server.assert_hits(2);
    }

    #[test]
    fn can_discover_using_the_hostname_and_port_syntax() {
        let mock_http_server = MockServer::start();

        let auth_server_domain_with_port = "ophp.example.com:8080";

        let webfinger_response_body = "{\"subject\":\"https://ophp.example.com:8080\",\"links\":[{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://ophp.example.com\"}]}";
        let discovery_document_response_body = "{\"authorization_endpoint\":\"https://ophp.example.com/o/oauth2/v2/auth\",\"issuer\":\"https://ophp.example.com\",\"jwks_uri\":\"https://ophp.example.com/oauth2/v3/certs\",\"token_endpoint\":\"https://ophp.example.com/oauth2/v4/token\",\"userinfo_endpoint\":\"https://ophp.example.com/oauth2/v3/userinfo\"}";

        let webfinger_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/webfinger").query_param(
                "resource",
                format!("https://{}", auth_server_domain_with_port),
            );
            then.status(200).body(webfinger_response_body);
        });

        let issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).body(discovery_document_response_body);
        });

        let issuer_result = Issuer::webfinger(
            &auth_server_domain_with_port,
            get_default_test_interceptor(mock_http_server.port()),
        );
        let async_issuer_result =
            get_async_webfinger_discovery(&auth_server_domain_with_port, mock_http_server.port());

        assert!(issuer_result.is_ok());
        assert!(async_issuer_result.is_ok());

        webfinger_mock_server.assert_hits(2);
        issuer_discovery_mock_server.assert_hits(2);
    }

    #[test]
    fn can_discover_using_the_acct_syntax() {
        let mock_http_server = MockServer::start();

        let resource = "acct:juliet%40capulet.example@opacct.example.com";

        let webfinger_response_body = "{\"subject\":\"acct:juliet%40capulet.example@opacct.example.com\",\"links\":[{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://opacct.example.com\"}]}";
        let discovery_document_response_body = "{\"authorization_endpoint\":\"https://opacct.example.com/o/oauth2/v2/auth\",\"issuer\":\"https://opacct.example.com\",\"jwks_uri\":\"https://opacct.example.com/oauth2/v3/certs\",\"token_endpoint\":\"https://opacct.example.com/oauth2/v4/token\",\"userinfo_endpoint\":\"https://opacct.example.com/oauth2/v3/userinfo\"}";

        let webfinger_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .path("/.well-known/webfinger")
                .query_param("resource", resource);
            then.status(200).body(webfinger_response_body);
        });

        let issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).body(discovery_document_response_body);
        });

        let issuer_result = Issuer::webfinger(
            &resource,
            get_default_test_interceptor(mock_http_server.port()),
        );
        let async_issuer_result = get_async_webfinger_discovery(&resource, mock_http_server.port());

        assert!(issuer_result.is_ok());
        assert!(async_issuer_result.is_ok());

        webfinger_mock_server.assert_hits(2);
        issuer_discovery_mock_server.assert_hits(2);
    }

    #[cfg(test)]
    mod http_options {

        use httpmock::{Method::GET, MockServer};

        use crate::{
            issuer::Issuer, tests::test_interceptors::TestInterceptor, types::OidcClientError,
        };

        #[test]
        fn allows_for_http_options_to_be_defined_for_issuer_webfinger_calls() {
            let mock_http_server = MockServer::start();

            let resource = "acct:juliet@op.example.com";

            let webfinger_response_body = "{\"subject\":\"acct:juliet@op.example.com\",\"links\":[{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://op.example.com\"}]}";
            let discovery_document_response_body = "{\"authorization_endpoint\":\"https://op.example.com/o/oauth2/v2/auth\",\"issuer\":\"https://op.example.com\",\"jwks_uri\":\"https://op.example.com/oauth2/v3/certs\",\"token_endpoint\":\"https://op.example.com/oauth2/v4/token\",\"userinfo_endpoint\":\"https://op.example.com/oauth2/v3/userinfo\"}";

            let webfinger_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET)
                    .path("/.well-known/webfinger")
                    .header("custom", "foo")
                    .query_param("resource", resource);
                then.status(200).body(webfinger_response_body);
            });

            let issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET)
                    .path("/.well-known/openid-configuration")
                    .header("custom", "foo");
                then.status(200).body(discovery_document_response_body);
            });

            let issuer_result = Issuer::webfinger(
                &resource,
                Some(Box::new(TestInterceptor {
                    test_header: Some("custom".to_string()),
                    test_header_value: Some("foo".to_string()),
                    test_server_port: Some(mock_http_server.port()),
                })),
            );

            webfinger_mock_server.assert();
            issuer_discovery_mock_server.assert();
            assert!(issuer_result.is_ok());
        }

        #[test]
        fn allows_for_http_options_to_be_defined_for_issuer_webfinger_calls_async() {
            let mock_http_server = MockServer::start();

            let resource = "acct:juliet@op.example.com";

            let webfinger_response_body = "{\"subject\":\"acct:juliet@op.example.com\",\"links\":[{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://op.example.com\"}]}";
            let discovery_document_response_body = "{\"authorization_endpoint\":\"https://op.example.com/o/oauth2/v2/auth\",\"issuer\":\"https://op.example.com\",\"jwks_uri\":\"https://op.example.com/oauth2/v3/certs\",\"token_endpoint\":\"https://op.example.com/oauth2/v4/token\",\"userinfo_endpoint\":\"https://op.example.com/oauth2/v3/userinfo\"}";

            let webfinger_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET)
                    .path("/.well-known/webfinger")
                    .header("custom", "foo")
                    .query_param("resource", resource);
                then.status(200).body(webfinger_response_body);
            });

            let issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET)
                    .path("/.well-known/openid-configuration")
                    .header("custom", "foo");
                then.status(200).body(discovery_document_response_body);
            });

            let async_runtime = tokio::runtime::Runtime::new().unwrap();

            let issuer_result: Result<Issuer, OidcClientError> = async_runtime.block_on(async {
                Issuer::webfinger_async(
                    &resource,
                    Some(Box::new(TestInterceptor {
                        test_header: Some("custom".to_string()),
                        test_header_value: Some("foo".to_string()),
                        test_server_port: Some(mock_http_server.port()),
                    })),
                )
                .await
            });

            webfinger_mock_server.assert();
            issuer_discovery_mock_server.assert();
            assert!(issuer_result.is_ok());
        }
    }
}

#[cfg(test)]
mod issuer_new {
    use crate::issuer::Issuer;
    use crate::types::IssuerMetadata;
    use std::collections::HashMap;

    #[test]
    fn accepts_the_recognized_metadata() {
        let authorization_endpoint = || "https://accounts.google.com/o/oauth2/v2/auth".to_string();
        let token_endpoint = || "https://www.googleapis.com/oauth2/v4/token".to_string();
        let userinfo_endpoint = || "https://www.googleapis.com/oauth2/v3/userinfo".to_string();
        let jwks_uri = || "https://www.googleapis.com/oauth2/v3/certs".to_string();

        let metadata = IssuerMetadata {
            issuer: "https://accounts.google.com".to_string(),
            authorization_endpoint: Some(authorization_endpoint()),
            token_endpoint: Some(token_endpoint()),
            userinfo_endpoint: Some(userinfo_endpoint()),
            jwks_uri: Some(jwks_uri()),
            ..IssuerMetadata::default()
        };

        let issuer = Issuer::new(metadata, None);

        assert_eq!(
            authorization_endpoint(),
            issuer.authorization_endpoint.unwrap()
        );
        assert_eq!(token_endpoint(), issuer.token_endpoint.unwrap());
        assert_eq!(userinfo_endpoint(), issuer.userinfo_endpoint.unwrap());
        assert_eq!(jwks_uri(), issuer.jwks_uri.unwrap());
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
        let token_endpoint = || "https://op.example.com/token".to_string();
        let token_endpoint_auth_methods_supported = || {
            vec![
                "client_secret_basic".to_string(),
                "client_secret_post".to_string(),
                "client_secret_jwt".to_string(),
            ]
        };

        let token_endpoint_auth_signing_alg_values_supported =
            || vec!["RS256".to_string(), "HS256".to_string()];

        let metadata = IssuerMetadata {
            token_endpoint: Some(token_endpoint()),
            token_endpoint_auth_methods_supported: Some(token_endpoint_auth_methods_supported()),
            token_endpoint_auth_signing_alg_values_supported: Some(
                token_endpoint_auth_signing_alg_values_supported(),
            ),
            ..IssuerMetadata::default()
        };

        let issuer = Issuer::new(metadata, None);

        assert_eq!(
            token_endpoint_auth_methods_supported(),
            issuer
                .introspection_endpoint_auth_methods_supported
                .unwrap(),
        );
        assert_eq!(
            token_endpoint_auth_methods_supported(),
            issuer.revocation_endpoint_auth_methods_supported.unwrap(),
        );

        assert_eq!(
            token_endpoint_auth_signing_alg_values_supported(),
            issuer
                .revocation_endpoint_auth_signing_alg_values_supported
                .unwrap(),
        );
        assert_eq!(
            token_endpoint_auth_signing_alg_values_supported(),
            issuer
                .introspection_endpoint_auth_signing_alg_values_supported
                .unwrap(),
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

        assert_eq!("https://op.example.com".to_string(), issuer.issuer);
        assert!(issuer.other_fields.contains_key("foo"));
        assert_eq!(
            Some(&serde_json::Value::String("bar".to_string())),
            issuer.other_fields.get("foo"),
        );
    }
}

#[cfg(test)]
mod issuer_instance {
    use crate::tests::test_interceptors::get_default_test_interceptor;
    use crate::{issuer::Issuer, types::IssuerMetadata};
    use httpmock::Method::GET;
    use httpmock::MockServer;

    fn get_default_jwks() -> String {
        "{\"keys\":[{\"e\":\"AQAB\",\"n\":\"zwGRh6jBiyfwbSz_gs71ehiLLuVNd5Cyb67wKVPaS6GFyHtPjD5r-Yta5aZ7OaZV1AB7ieuhvvKsjvx4pzBAnQzwyYcaFDdb91jVHad019LMkjO_UTwSHegV_Bcwrhi0g64tfW3bTNUMEEKLZEusJZElpLi9HLZsGRJUlRCYRTqMeq1SYjQunVF9GmTTJlgK7IIdMYJ6ktQNRkQFz9ACpTZCS6SCUCjA4psFz-vtW-pBOvwO1gu4hWFQx9IFmPIojyZhF5kgfVlOnAc0YTRgj03uEMYXwLpBlbC-SPM9YXmFq1iflRbxEZqEP170J_27HjYpvo8eK2YwL9jXxNLC4Q\",\"kty\":\"RSA\",\"kid\":\"RraeLjB4KnAKQaihCOLHPByOJaSjXc0iWkhq2b3I7-o\"}]}".to_string()
    }

    #[test]
    fn requires_jwks_uri_to_be_configured() {
        let mut issuer = Issuer::new(IssuerMetadata::default(), None);

        assert!(issuer.get_keystore(false).is_err());
        assert_eq!(
            "jwks_uri must be configured on the issuer".to_string(),
            issuer
                .get_keystore(false)
                .unwrap_err()
                .type_error()
                .error
                .message,
        );

        let async_runtime = tokio::runtime::Runtime::new().unwrap();
        async_runtime.block_on(async {
            assert!(issuer.get_keystore_async(false).await.is_err());
            assert_eq!(
                "jwks_uri must be configured on the issuer".to_string(),
                issuer
                    .get_keystore_async(false)
                    .await
                    .unwrap_err()
                    .type_error()
                    .error
                    .message,
            );
        });
    }

    #[test]
    fn does_not_refetch_immediately() {
        let mock_http_server = MockServer::start();

        let jwks_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .header("Accept", "application/json,application/jwk-set+json")
                .path("/jwks");
            then.status(200)
                .header("content-type", "application/jwk-set+json")
                .body(get_default_jwks());
        });

        let issuer = "https://op.example.com".to_string();
        let jwks_uri = "https://op.example.com/jwks".to_string();

        let metadata = IssuerMetadata {
            issuer,
            jwks_uri: Some(jwks_uri),
            ..IssuerMetadata::default()
        };

        let mut issuer = Issuer::new(
            metadata,
            get_default_test_interceptor(mock_http_server.port()),
        );

        assert!(issuer.get_keystore(true).is_ok());

        let _ = issuer.get_keystore(false).unwrap();

        jwks_mock_server.assert_hits(1);
    }

    #[test]
    fn does_not_refetch_immediately_async() {
        let mock_http_server = MockServer::start();

        let jwks_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .header("Accept", "application/json,application/jwk-set+json")
                .path("/jwks");
            then.status(200)
                .header("content-type", "application/jwk-set+json")
                .body(get_default_jwks());
        });

        let issuer = "https://op.example.com".to_string();
        let jwks_uri = "https://op.example.com/jwks".to_string();

        let metadata = IssuerMetadata {
            issuer,
            jwks_uri: Some(jwks_uri),
            ..IssuerMetadata::default()
        };

        let mut issuer = Issuer::new(
            metadata,
            get_default_test_interceptor(mock_http_server.port()),
        );

        let async_runtime = tokio::runtime::Runtime::new().unwrap();
        async_runtime.block_on(async {
            assert!(issuer.get_keystore_async(true).await.is_ok());

            let _ = issuer.get_keystore_async(false).await.unwrap();
        });

        jwks_mock_server.assert_hits(1);
    }

    #[test]
    fn refetches_if_asked_to() {
        let mock_http_server = MockServer::start();

        let jwks_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .header("Accept", "application/json,application/jwk-set+json")
                .path("/jwks");
            then.status(200)
                .header("content-type", "application/jwk-set+json")
                .body(get_default_jwks());
        });

        let issuer = "https://op.example.com".to_string();
        let jwks_uri = "https://op.example.com/jwks".to_string();

        let metadata = IssuerMetadata {
            issuer,
            jwks_uri: Some(jwks_uri),
            ..IssuerMetadata::default()
        };

        let mut issuer = Issuer::new(
            metadata,
            get_default_test_interceptor(mock_http_server.port()),
        );

        assert!(issuer.get_keystore(true).is_ok());
        assert!(issuer.get_keystore(true).is_ok());

        jwks_mock_server.assert_hits(2);
    }

    #[test]
    fn refetches_if_asked_to_async() {
        let mock_http_server = MockServer::start();

        let jwks_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .header("Accept", "application/json,application/jwk-set+json")
                .path("/jwks");
            then.status(200)
                .header("content-type", "application/jwk-set+json")
                .body(get_default_jwks());
        });

        let issuer = "https://op.example.com".to_string();
        let jwks_uri = "https://op.example.com/jwks".to_string();

        let metadata = IssuerMetadata {
            issuer,
            jwks_uri: Some(jwks_uri),
            ..IssuerMetadata::default()
        };

        let mut issuer = Issuer::new(
            metadata,
            get_default_test_interceptor(mock_http_server.port()),
        );

        let async_runtime = tokio::runtime::Runtime::new().unwrap();
        async_runtime.block_on(async {
            assert!(issuer.get_keystore_async(true).await.is_ok());
            assert!(issuer.get_keystore_async(true).await.is_ok());
        });

        jwks_mock_server.assert_hits(2);
    }

    #[test]
    fn rejects_when_no_matching_key_is_found() {
        let mock_http_server = MockServer::start();

        let _jwks_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .header("Accept", "application/json,application/jwk-set+json")
                .path("/jwks");
            then.status(200)
                .header("content-type", "application/jwk-set+json")
                .body(get_default_jwks());
        });

        let issuer = "https://op.example.com".to_string();
        let jwks_uri = "https://op.example.com/jwks".to_string();

        let metadata = IssuerMetadata {
            issuer,
            jwks_uri: Some(jwks_uri),
            ..IssuerMetadata::default()
        };

        let mut issuer = Issuer::new(
            metadata,
            get_default_test_interceptor(mock_http_server.port()),
        );

        let jwk_result = issuer.get_jwk(
            Some("RS256".to_string()),
            Some("sig".to_string()),
            Some("noway".to_string()),
        );

        let expected_error = "no valid key found in issuer\'s jwks_uri for key parameters kid: noway, alg: RS256, key_use: sig";

        assert!(jwk_result.is_err());

        let error = jwk_result.unwrap_err();

        assert_eq!(expected_error, error.error().error.message);

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

            assert_eq!(expected_error, error_async.error().error.message);
        });
    }

    #[test]
    fn requires_a_kid_when_multiple_matches_are_found() {
        let mock_http_server = MockServer::start();

        let _jwks_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .header("Accept", "application/json,application/jwk-set+json")
                .path("/jwks");

            then.status(200)
                .header("content-type", "application/jwk-set+json")
                .body("{\"keys\":[{\"e\":\"AQAB\",\"n\":\"5RnVQ2VT79TaW_Louj5ib7_dVJ1vX5ebaVeifBjNDlUp3KsrHm5sq1KWzPVz-XE6m4GBGXnVxMc5pmN7pQcqGe2rzw_jTAOIQzjYZ2UPTvl8HSjPCf9VwJleHiy4195YgnOcAF-PVASLKNKnoHjgn4b2gXpikMnztvdTFZrQAAlEVwslbW0Z17imHQsYzDXDYVzwpxjiRl4tWretNXhJS2Bk1NZoctW5kY6otkeMZ8VLpCUfbBzrhhLh5b_7Q0JKQjGX94f8j5tpVz_CXkpwQUXyymfBH9B-FY5s7LDZRKCEneSnCwSFce_nVzPqcO5J4SwsVF6FhwVQMvCC0QmNGw\",\"kty\":\"RSA\"},{\"e\":\"AQAB\",\"n\":\"3ANc8Uhup5_tnZfJuR4jQIwzobzEegcPGySt_EVzdF8ft2L4RoOE8wWq2fff9tRtrzNcKjSTgpw6cDMXSEa2Mx07FUvuyvjXSzlUG_fEPGIhyEJXqD5NZ89CrgHy55kizSuvgxcpQLkvSddBXVYnccWRGXfCurj7BkY1ycxvm55LAkPkaEtSWmnX8gWX6289SeKx-3rD0Xl20lhoe0_f4nChWibn-2egKBfrq-d1nXnsyxOcDhOZHS9nC4N4UeiZyQ6ervyGDg1fxzi98gxe4qb14J3vogX3KUdyG0YuC4D1SgUtEnmrVbbQl9y3fYBKZy7ysk48j9CdWjA9KYoWUQ\",\"kty\":\"RSA\"}]}");
        });

        let issuer = "https://op.example.com".to_string();
        let jwks_uri = "https://op.example.com/jwks".to_string();

        let metadata = IssuerMetadata {
            issuer,
            jwks_uri: Some(jwks_uri),
            ..IssuerMetadata::default()
        };

        let mut issuer = Issuer::new(
            metadata,
            get_default_test_interceptor(mock_http_server.port()),
        );

        let jwk_result = issuer.get_jwk(Some("RS256".to_string()), Some("sig".to_string()), None);

        let expected_error = "multiple matching keys found in issuer\'s jwks_uri for key parameters kid: , key_use: sig, alg: RS256, kid must be provided in this case";

        assert!(jwk_result.is_err());

        let error = jwk_result.unwrap_err();

        assert_eq!(expected_error, error.error().error.message);

        let async_runtime = tokio::runtime::Runtime::new().unwrap();
        async_runtime.block_on(async {
            let jwk_result_async = issuer
                .get_jwk_async(Some("RS256".to_string()), Some("sig".to_string()), None)
                .await;

            assert!(jwk_result_async.is_err());

            let error_async = jwk_result_async.unwrap_err();

            assert_eq!(expected_error, error_async.error().error.message);
        });
    }

    #[test]
    fn multiple_keys_can_match_jwt_header() {
        let mock_http_server = MockServer::start();

        let _jwks_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .header("Accept", "application/json,application/jwk-set+json")
                .path("/jwks");

            then.status(200)
                .header("content-type", "application/jwk-set+json")
                .body("{\"keys\":[{\"e\":\"AQAB\",\"n\":\"5RnVQ2VT79TaW_Louj5ib7_dVJ1vX5ebaVeifBjNDlUp3KsrHm5sq1KWzPVz-XE6m4GBGXnVxMc5pmN7pQcqGe2rzw_jTAOIQzjYZ2UPTvl8HSjPCf9VwJleHiy4195YgnOcAF-PVASLKNKnoHjgn4b2gXpikMnztvdTFZrQAAlEVwslbW0Z17imHQsYzDXDYVzwpxjiRl4tWretNXhJS2Bk1NZoctW5kY6otkeMZ8VLpCUfbBzrhhLh5b_7Q0JKQjGX94f8j5tpVz_CXkpwQUXyymfBH9B-FY5s7LDZRKCEneSnCwSFce_nVzPqcO5J4SwsVF6FhwVQMvCC0QmNGw\",\"kty\":\"RSA\",\"kid\":\"0pWEDfNcRM4-Lnqq6QDkmVzElFEdYE96gJff6yesi0A\"},{\"e\":\"AQAB\",\"n\":\"3ANc8Uhup5_tnZfJuR4jQIwzobzEegcPGySt_EVzdF8ft2L4RoOE8wWq2fff9tRtrzNcKjSTgpw6cDMXSEa2Mx07FUvuyvjXSzlUG_fEPGIhyEJXqD5NZ89CrgHy55kizSuvgxcpQLkvSddBXVYnccWRGXfCurj7BkY1ycxvm55LAkPkaEtSWmnX8gWX6289SeKx-3rD0Xl20lhoe0_f4nChWibn-2egKBfrq-d1nXnsyxOcDhOZHS9nC4N4UeiZyQ6ervyGDg1fxzi98gxe4qb14J3vogX3KUdyG0YuC4D1SgUtEnmrVbbQl9y3fYBKZy7ysk48j9CdWjA9KYoWUQ\",\"kty\":\"RSA\",\"kid\":\"0pWEDfNcRM4-Lnqq6QDkmVzElFEdYE96gJff6yesi0A\"}]}");
        });

        let issuer = "https://op.example.com".to_string();
        let jwks_uri = "https://op.example.com/jwks".to_string();

        let metadata = IssuerMetadata {
            issuer,
            jwks_uri: Some(jwks_uri),
            ..IssuerMetadata::default()
        };

        let mut issuer = Issuer::new(
            metadata,
            get_default_test_interceptor(mock_http_server.port()),
        );

        let jwk_result = issuer.get_jwk(
            Some("RS256".to_string()),
            Some("sig".to_string()),
            Some("0pWEDfNcRM4-Lnqq6QDkmVzElFEdYE96gJff6yesi0A".to_string()),
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
                    Some("0pWEDfNcRM4-Lnqq6QDkmVzElFEdYE96gJff6yesi0A".to_string()),
                )
                .await;

            assert!(jwk_result_async.is_ok());

            let matched_jwks_async = jwk_result_async.unwrap();

            assert!(matched_jwks_async.len() > 1);
        });
    }

    #[cfg(test)]
    mod http_options {

        use crate::tests::test_interceptors::TestInterceptor;

        use super::*;

        #[test]
        fn allows_for_http_options_to_be_defined_for_issuer_keystore_calls() {
            let mock_http_server = MockServer::start();

            let issuer = "https://op.example.com".to_string();
            let jwks_uri = "https://op.example.com/jwks".to_string();

            let jwks_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET)
                    .header("testHeader", "testHeaderValue")
                    .path("/jwks");

                then.status(200)
                    .header("content-type", "application/jwk-set+json")
                    .body(get_default_jwks());
            });

            let _ = Issuer::discover(
                "https://op.example.com/.well-known/custom-configuration",
                Some(Box::new(TestInterceptor {
                    test_header: Some("testHeader".to_string()),
                    test_header_value: Some("testHeaderValue".to_string()),
                    test_server_port: Some(mock_http_server.port()),
                })),
            );

            let metadata = IssuerMetadata {
                issuer,
                jwks_uri: Some(jwks_uri),
                ..IssuerMetadata::default()
            };

            let mut issuer = Issuer::new(
                metadata,
                Some(Box::new(TestInterceptor {
                    test_header: Some("testHeader".to_string()),
                    test_header_value: Some("testHeaderValue".to_string()),
                    test_server_port: Some(mock_http_server.port()),
                })),
            );

            let _ = issuer.get_keystore(false);

            jwks_mock_server.assert_hits(1);
        }

        #[test]
        fn allows_for_http_options_to_be_defined_for_issuer_keystore_calls_async() {
            let mock_http_server = MockServer::start();

            let issuer = "https://op.example.com".to_string();
            let jwks_uri = "https://op.example.com/jwks".to_string();

            let jwks_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET)
                    .header("testHeader", "testHeaderValue")
                    .path("/jwks");

                then.status(200)
                    .header("content-type", "application/jwk-set+json")
                    .body(get_default_jwks());
            });

            let _ = Issuer::discover(
                "https://op.example.com/.well-known/custom-configuration",
                Some(Box::new(TestInterceptor {
                    test_header: Some("testHeader".to_string()),
                    test_header_value: Some("testHeaderValue".to_string()),
                    test_server_port: Some(mock_http_server.port()),
                })),
            );

            let metadata = IssuerMetadata {
                issuer,
                jwks_uri: Some(jwks_uri),
                ..IssuerMetadata::default()
            };

            let mut issuer = Issuer::new(
                metadata,
                Some(Box::new(TestInterceptor {
                    test_header: Some("testHeader".to_string()),
                    test_header_value: Some("testHeaderValue".to_string()),
                    test_server_port: Some(mock_http_server.port()),
                })),
            );

            let async_runtime = tokio::runtime::Runtime::new().unwrap();

            async_runtime.block_on(async {
                let _ = issuer.get_keystore_async(false).await;
                jwks_mock_server.assert_hits(1);
            });
        }
    }
}
