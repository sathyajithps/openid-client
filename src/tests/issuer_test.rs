#[cfg(test)]
mod issuer_discovery_tests {
    use crate::issuer::Issuer;
    use crate::tests::{get_url_with_count, set_mock_domain};
    use crate::types::OidcClientError;
    pub use httpmock::Method::GET;
    pub use httpmock::MockServer;

    pub fn get_async_issuer_discovery(issuer: &str) -> Result<Issuer, OidcClientError> {
        let async_runtime = tokio::runtime::Runtime::new().unwrap();

        let result: Result<Issuer, OidcClientError> = async_runtime.block_on(async {
            let iss = Issuer::discover_async(issuer, None).await;
            return iss;
        });
        result
    }

    pub fn get_default_expected_discovery_document(domain: &str) -> String {
        format!("{{\"authorization_endpoint\":\"https://{0}/o/oauth2/v2/auth\",\"issuer\":\"https://{0}\",\"jwks_uri\":\"https://{0}/oauth2/v3/certs\",\"token_endpoint\":\"https://{0}/oauth2/v4/token\",\"userinfo_endpoint\":\"https://{0}/oauth2/v3/userinfo\"}}", domain)
    }

    #[cfg(test)]
    mod custom_well_known {
        use crate::tests::{get_url_with_count, set_mock_domain};

        use super::*;

        #[test]
        fn accepts_and_assigns_the_discovered_metadata() {
            let mock_http_server = MockServer::start();

            let auth_server_domain = get_url_with_count("op.example<>.com");

            let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET).path("/.well-known/custom-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(get_default_expected_discovery_document(&auth_server_domain));
            });

            set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

            let issuer_discovery_url = format!(
                "https://{}/.well-known/custom-configuration",
                auth_server_domain
            );

            let issuer = Issuer::discover(&issuer_discovery_url, None).unwrap();
            let async_issuer = get_async_issuer_discovery(&issuer_discovery_url).unwrap();

            assert_eq!(issuer.issuer, format!("https://{0}", &auth_server_domain));
            assert_eq!(
                async_issuer.issuer,
                format!("https://{0}", &auth_server_domain)
            );

            assert_eq!(
                issuer.jwks_uri.unwrap(),
                format!("https://{0}/oauth2/v3/certs", &auth_server_domain)
            );
            assert_eq!(
                async_issuer.jwks_uri.unwrap(),
                format!("https://{0}/oauth2/v3/certs", &auth_server_domain)
            );

            assert_eq!(
                issuer.token_endpoint.unwrap(),
                format!("https://{0}/oauth2/v4/token", &auth_server_domain)
            );
            assert_eq!(
                async_issuer.token_endpoint.unwrap(),
                format!("https://{0}/oauth2/v4/token", &auth_server_domain)
            );

            assert_eq!(
                issuer.userinfo_endpoint.unwrap(),
                format!("https://{0}/oauth2/v3/userinfo", &auth_server_domain)
            );
            assert_eq!(
                async_issuer.userinfo_endpoint.unwrap(),
                format!("https://{0}/oauth2/v3/userinfo", &auth_server_domain)
            );

            assert_eq!(
                issuer.authorization_endpoint.unwrap(),
                format!("https://{0}/o/oauth2/v2/auth", &auth_server_domain)
            );
            assert_eq!(
                async_issuer.authorization_endpoint.unwrap(),
                format!("https://{0}/o/oauth2/v2/auth", &auth_server_domain)
            );
        }
    }

    #[cfg(test)]
    mod well_known {
        use crate::tests::{get_url_with_count, set_mock_domain};

        use super::*;

        #[test]
        fn accepts_and_assigns_the_discovered_metadata() {
            let mock_http_server = MockServer::start();

            let auth_server_domain = get_url_with_count("op.example<>.com");

            let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET).path("/.well-known/openid-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(get_default_expected_discovery_document(&auth_server_domain));
            });

            set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

            let issuer_discovery_url = format!(
                "https://{}/.well-known/openid-configuration",
                auth_server_domain
            );

            let issuer = Issuer::discover(&issuer_discovery_url, None).unwrap();
            let async_issuer = get_async_issuer_discovery(&issuer_discovery_url).unwrap();

            assert_eq!(issuer.issuer, format!("https://{0}", &auth_server_domain));
            assert_eq!(
                async_issuer.issuer,
                format!("https://{0}", &auth_server_domain)
            );

            assert_eq!(
                issuer.jwks_uri.unwrap(),
                format!("https://{0}/oauth2/v3/certs", &auth_server_domain)
            );
            assert_eq!(
                async_issuer.jwks_uri.unwrap(),
                format!("https://{0}/oauth2/v3/certs", &auth_server_domain)
            );

            assert_eq!(
                issuer.token_endpoint.unwrap(),
                format!("https://{0}/oauth2/v4/token", &auth_server_domain)
            );
            assert_eq!(
                async_issuer.token_endpoint.unwrap(),
                format!("https://{0}/oauth2/v4/token", &auth_server_domain)
            );

            assert_eq!(
                issuer.userinfo_endpoint.unwrap(),
                format!("https://{0}/oauth2/v3/userinfo", &auth_server_domain)
            );
            assert_eq!(
                async_issuer.userinfo_endpoint.unwrap(),
                format!("https://{0}/oauth2/v3/userinfo", &auth_server_domain)
            );

            assert_eq!(
                issuer.authorization_endpoint.unwrap(),
                format!("https://{0}/o/oauth2/v2/auth", &auth_server_domain)
            );
            assert_eq!(
                async_issuer.authorization_endpoint.unwrap(),
                format!("https://{0}/o/oauth2/v2/auth", &auth_server_domain)
            );
        }

        #[test]
        fn can_be_discovered_by_omitting_well_known() {
            let mock_http_server = MockServer::start();

            let auth_server_domain = get_url_with_count("op.example<>.com");

            let expected_discovery_document =
                format!("{{\"issuer\":\"https://{}\"}}", &auth_server_domain);

            let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET).path("/.well-known/openid-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(expected_discovery_document);
            });

            set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

            let issuer_discovery_url = format!("https://{}", auth_server_domain);

            let issuer = Issuer::discover(&issuer_discovery_url, None).unwrap();
            let async_issuer = get_async_issuer_discovery(&issuer_discovery_url).unwrap();

            assert_eq!(issuer.issuer, issuer_discovery_url);
            assert_eq!(async_issuer.issuer, issuer_discovery_url);
        }

        #[test]
        fn discovers_issuers_with_path_components_with_trailing_slash() {
            let mock_http_server = MockServer::start();

            let auth_server_domain = get_url_with_count("op.example<>.com");

            let expected_discovery_document =
                format!("{{\"issuer\":\"https://{}/oidc\"}}", &auth_server_domain);

            let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET)
                    .path("/oidc/.well-known/openid-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(expected_discovery_document);
            });

            set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

            let issuer_discovery_url = format!("https://{}/oidc/", auth_server_domain);

            let issuer = Issuer::discover(&issuer_discovery_url, None).unwrap();
            let async_issuer = get_async_issuer_discovery(&issuer_discovery_url).unwrap();

            assert_eq!(
                issuer.issuer,
                format!("https://{}/oidc", auth_server_domain)
            );
            assert_eq!(
                async_issuer.issuer,
                format!("https://{}/oidc", auth_server_domain)
            );
        }

        #[test]
        fn discovers_issuers_with_path_components_without_trailing_slash() {
            let mock_http_server = MockServer::start();

            let auth_server_domain = get_url_with_count("op.example<>.com");

            let expected_discovery_document =
                format!("{{\"issuer\":\"https://{}/oidc\"}}", &auth_server_domain);

            let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET)
                    .path("/oidc/.well-known/openid-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(&expected_discovery_document);
            });

            set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

            let issuer_discovery_url = format!("https://{}/oidc", auth_server_domain);

            let issuer = Issuer::discover(&issuer_discovery_url, None).unwrap();
            let async_issuer = get_async_issuer_discovery(&issuer_discovery_url).unwrap();

            assert_eq!(
                issuer.issuer,
                format!("https://{}/oidc", auth_server_domain)
            );
            assert_eq!(
                async_issuer.issuer,
                format!("https://{}/oidc", auth_server_domain)
            );
        }

        #[test]
        fn discovering_issuers_with_well_known_uri_including_path_and_query() {
            let mock_http_server = MockServer::start();

            let auth_server_domain = get_url_with_count("op.example<>.com");

            let expected_discovery_document =
                format!("{{\"issuer\":\"https://{}/oidc\"}}", &auth_server_domain);

            let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET)
                    .path("/oidc/.well-known/openid-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(&expected_discovery_document);
            });

            set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

            let issuer_discovery_url = format!(
                "https://{}/oidc/.well-known/openid-configuration?foo=bar",
                auth_server_domain
            );

            let issuer = Issuer::discover(&issuer_discovery_url, None).unwrap();
            let async_issuer = get_async_issuer_discovery(&issuer_discovery_url).unwrap();

            assert_eq!(
                issuer.issuer,
                format!("https://{}/oidc", auth_server_domain)
            );
            assert_eq!(
                async_issuer.issuer,
                format!("https://{}/oidc", auth_server_domain)
            );
        }
    }

    mod well_known_oauth_authorization_server {
        use crate::tests::set_mock_domain;

        use super::*;

        #[test]
        fn accepts_and_assigns_the_discovered_metadata() {
            let mock_http_server = MockServer::start();

            let auth_server_domain = get_url_with_count("op.example<>.com");

            let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET)
                    .path("/.well-known/oauth-authorization-server");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(get_default_expected_discovery_document(&auth_server_domain));
            });

            set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

            let issuer_discovery_url = format!(
                "https://{}/.well-known/oauth-authorization-server",
                auth_server_domain
            );

            let issuer = Issuer::discover(&issuer_discovery_url, None).unwrap();
            let async_issuer = get_async_issuer_discovery(&issuer_discovery_url).unwrap();

            assert_eq!(issuer.issuer, format!("https://{}", &auth_server_domain));
            assert_eq!(
                async_issuer.issuer,
                format!("https://{}", &auth_server_domain)
            );

            assert_eq!(
                issuer.jwks_uri.unwrap(),
                format!("https://{}/oauth2/v3/certs", &auth_server_domain)
            );
            assert_eq!(
                async_issuer.jwks_uri.unwrap(),
                format!("https://{}/oauth2/v3/certs", &auth_server_domain)
            );

            assert_eq!(
                issuer.token_endpoint.unwrap(),
                format!("https://{}/oauth2/v4/token", &auth_server_domain)
            );
            assert_eq!(
                async_issuer.token_endpoint.unwrap(),
                format!("https://{}/oauth2/v4/token", &auth_server_domain)
            );

            assert_eq!(
                issuer.userinfo_endpoint.unwrap(),
                format!("https://{}/oauth2/v3/userinfo", &auth_server_domain)
            );
            assert_eq!(
                async_issuer.userinfo_endpoint.unwrap(),
                format!("https://{}/oauth2/v3/userinfo", &auth_server_domain)
            );

            assert_eq!(
                issuer.authorization_endpoint.unwrap(),
                format!("https://{}/o/oauth2/v2/auth", &auth_server_domain)
            );
            assert_eq!(
                async_issuer.authorization_endpoint.unwrap(),
                format!("https://{}/o/oauth2/v2/auth", &auth_server_domain)
            );
        }

        #[test]
        fn discovering_issuers_with_well_known_uri_including_path_and_query() {
            let mock_http_server = MockServer::start();

            let auth_server_domain = get_url_with_count("op.example<>.com");

            let expected_discovery_document =
                format!("{{\"issuer\":\"https://{}/oauth2\"}}", &auth_server_domain);

            let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET)
                    .path("/.well-known/oauth-authorization-server/oauth2");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(&expected_discovery_document);
            });

            set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

            let issuer_discovery_url = format!(
                "https://{}/.well-known/oauth-authorization-server/oauth2?foo=bar",
                auth_server_domain
            );

            let issuer = Issuer::discover(&issuer_discovery_url, None).unwrap();
            let async_issuer = get_async_issuer_discovery(&issuer_discovery_url).unwrap();

            assert_eq!(
                issuer.issuer,
                format!("https://{}/oauth2", &auth_server_domain)
            );
            assert_eq!(
                async_issuer.issuer,
                format!("https://{}/oauth2", &auth_server_domain)
            );
        }
    }

    #[test]
    fn assigns_discovery_1_0_defaults_1_of_2() {
        let mock_http_server = MockServer::start();

        let auth_server_domain = get_url_with_count("op.example<>.com");

        let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200)
                .header("content-type", "application/json")
                .body(get_default_expected_discovery_document(&auth_server_domain));
        });

        set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

        let issuer_discovery_url = format!(
            "https://{}/.well-known/openid-configuration",
            auth_server_domain
        );

        let issuer = Issuer::discover(&issuer_discovery_url, None).unwrap();
        let async_issuer = get_async_issuer_discovery(&issuer_discovery_url).unwrap();

        assert_eq!(issuer.claims_parameter_supported.unwrap(), false);
        assert_eq!(async_issuer.claims_parameter_supported.unwrap(), false);

        assert_eq!(
            issuer.grant_types_supported.unwrap(),
            vec!["authorization_code".to_string(), "implicit".to_string(),]
        );
        assert_eq!(
            async_issuer.grant_types_supported.unwrap(),
            vec!["authorization_code".to_string(), "implicit".to_string(),]
        );

        assert_eq!(issuer.request_parameter_supported.unwrap(), false);
        assert_eq!(async_issuer.request_parameter_supported.unwrap(), false);

        assert_eq!(issuer.request_uri_parameter_supported.unwrap(), true);
        assert_eq!(async_issuer.request_uri_parameter_supported.unwrap(), true);

        assert_eq!(issuer.require_request_uri_registration.unwrap(), false);
        assert_eq!(
            async_issuer.require_request_uri_registration.unwrap(),
            false
        );

        assert_eq!(
            issuer.response_modes_supported.unwrap(),
            vec!["query".to_string(), "fragment".to_string()]
        );
        assert_eq!(
            async_issuer.response_modes_supported.unwrap(),
            vec!["query".to_string(), "fragment".to_string()]
        );

        assert_eq!(issuer.claim_types_supported, vec!["normal".to_string()]);
        assert_eq!(
            async_issuer.claim_types_supported,
            vec!["normal".to_string()]
        );

        assert_eq!(
            issuer.token_endpoint_auth_methods_supported.unwrap(),
            vec!["client_secret_basic".to_string()]
        );
        assert_eq!(
            async_issuer.token_endpoint_auth_methods_supported.unwrap(),
            vec!["client_secret_basic".to_string()]
        );
    }

    #[test]
    fn assigns_discovery_1_0_defaults_2_of_2() {
        let mock_http_server = MockServer::start();

        let auth_server_domain = get_url_with_count("op.example<>.com");

        let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200)
                .header("content-type", "application/json")
                .body(get_default_expected_discovery_document(&auth_server_domain));
        });

        set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

        let issuer_discovery_url = format!("https://{}", auth_server_domain);

        let issuer = Issuer::discover(&issuer_discovery_url, None).unwrap();
        let async_issuer = get_async_issuer_discovery(&issuer_discovery_url).unwrap();

        assert_eq!(issuer.claims_parameter_supported.unwrap(), false);
        assert_eq!(async_issuer.claims_parameter_supported.unwrap(), false);

        assert_eq!(
            issuer.grant_types_supported.unwrap(),
            vec!["authorization_code".to_string(), "implicit".to_string(),]
        );
        assert_eq!(
            async_issuer.grant_types_supported.unwrap(),
            vec!["authorization_code".to_string(), "implicit".to_string(),]
        );

        assert_eq!(issuer.request_parameter_supported.unwrap(), false);
        assert_eq!(async_issuer.request_parameter_supported.unwrap(), false);

        assert_eq!(issuer.request_uri_parameter_supported.unwrap(), true);
        assert_eq!(async_issuer.request_uri_parameter_supported.unwrap(), true);

        assert_eq!(issuer.require_request_uri_registration.unwrap(), false);
        assert_eq!(
            async_issuer.require_request_uri_registration.unwrap(),
            false
        );

        assert_eq!(
            issuer.response_modes_supported.unwrap(),
            vec!["query".to_string(), "fragment".to_string()]
        );
        assert_eq!(
            async_issuer.response_modes_supported.unwrap(),
            vec!["query".to_string(), "fragment".to_string()]
        );

        assert_eq!(issuer.claim_types_supported, vec!["normal".to_string()]);
        assert_eq!(
            async_issuer.claim_types_supported,
            vec!["normal".to_string()]
        );

        assert_eq!(
            issuer.token_endpoint_auth_methods_supported.unwrap(),
            vec!["client_secret_basic".to_string()]
        );
        assert_eq!(
            async_issuer.token_endpoint_auth_methods_supported.unwrap(),
            vec!["client_secret_basic".to_string()]
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

        let auth_server_domain = get_url_with_count("op.example<>.com");

        set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

        let issuer_discovery_url = format!("https://{}", auth_server_domain);

        let error = Issuer::discover(&issuer_discovery_url, None).unwrap_err();
        let async_error = get_async_issuer_discovery(&issuer_discovery_url).unwrap_err();

        assert_eq!(error.name, "OPError");
        assert_eq!(async_error.name, "OPError");

        assert_eq!(error.error, "server_error");
        assert_eq!(async_error.error, "server_error");

        assert_eq!(error.error_description, "bad things are happening");
        assert_eq!(async_error.error_description, "bad things are happening");
    }

    #[test]
    fn is_rejected_with_error_when_no_absolute_url_is_provided() {
        let error = Issuer::discover("op.example.com/.well-known/foobar", None).unwrap_err();
        let async_error =
            get_async_issuer_discovery("op.example.com/.well-known/foobar").unwrap_err();

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
        let mock_http_server = MockServer::start();

        let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(400)
                .body("{\"error\": {},\"error_description\":\"bad things are happening\"}");
        });

        let auth_server_domain = get_url_with_count("op.example<>.com");

        set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

        let issuer_discovery_url = format!("https://{}", auth_server_domain);

        let error = Issuer::discover(&issuer_discovery_url, None).unwrap_err();
        let async_error = get_async_issuer_discovery(&issuer_discovery_url).unwrap_err();

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
        let mock_http_server = MockServer::start();

        let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(500);
        });

        let auth_server_domain = get_url_with_count("op.example<>.com");

        set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

        let issuer_discovery_url = format!("https://{}", auth_server_domain);

        let error = Issuer::discover(&issuer_discovery_url, None).unwrap_err();
        let async_error = get_async_issuer_discovery(&issuer_discovery_url).unwrap_err();

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
        let mock_http_server = MockServer::start();

        let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).body("{\"notavalid\"}");
        });

        let auth_server_domain = get_url_with_count("op.example<>.com");

        set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

        let issuer_discovery_url = format!("https://{}", auth_server_domain);

        let error = Issuer::discover(&issuer_discovery_url, None).unwrap_err();
        let async_error = get_async_issuer_discovery(&issuer_discovery_url).unwrap_err();

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
        let mock_http_server = MockServer::start();

        let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200);
        });

        let auth_server_domain = get_url_with_count("op.example<>.com");

        set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

        let issuer_discovery_url = format!("https://{}", auth_server_domain);

        let error = Issuer::discover(&issuer_discovery_url, None).unwrap_err();
        let async_error = get_async_issuer_discovery(&issuer_discovery_url).unwrap_err();

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
        let mock_http_server = MockServer::start();

        let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(301);
        });

        let auth_server_domain = get_url_with_count("op.example<>.com");

        set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

        let issuer_discovery_url = format!("https://{}", auth_server_domain);

        let error = Issuer::discover(&issuer_discovery_url, None).unwrap_err();
        let async_error = get_async_issuer_discovery(&issuer_discovery_url).unwrap_err();

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
            let mock_http_server = MockServer::start();

            let auth_server_domain = get_url_with_count("op.example<>.com");

            let auth_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET)
                    .header_exists("testHeader")
                    .path("/.well-known/custom-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(get_default_expected_discovery_document(&auth_server_domain));
            });

            let interceptor = |_request: &crate::types::Request| {
                let mut headers = HeaderMap::new();
                headers.append("testHeader", HeaderValue::from_static("testHeaderValue"));

                RequestOptions {
                    headers,
                    timeout: Duration::from_millis(3500),
                }
            };

            set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

            let _ = Issuer::discover(
                &format!(
                    "https://{}/.well-known/custom-configuration",
                    auth_server_domain
                ),
                Some(Box::new(interceptor)),
            );

            auth_mock_server.assert_hits(1);
        }

        #[test]
        fn allows_for_http_options_to_be_defined_for_issuer_discover_calls_async() {
            let mock_http_server = MockServer::start();

            let auth_server_domain = get_url_with_count("op.example<>.com");

            let auth_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET)
                    .header_exists("testHeader")
                    .path("/.well-known/custom-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(get_default_expected_discovery_document(&auth_server_domain));
            });

            let interceptor = |_request: &crate::types::Request| {
                let mut headers = HeaderMap::new();
                headers.append("testHeader", HeaderValue::from_static("testHeaderValue"));

                RequestOptions {
                    headers,
                    timeout: Duration::from_millis(3500),
                }
            };

            set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

            let async_runtime = tokio::runtime::Runtime::new().unwrap();

            let _ = async_runtime.block_on(async {
                Issuer::discover_async(
                    &format!(
                        "https://{}/.well-known/custom-configuration",
                        auth_server_domain
                    ),
                    Some(Box::new(interceptor)),
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
    use crate::tests::{get_url_with_count, set_mock_domain};
    use crate::types::OidcClientError;

    pub fn get_async_webfinger_discovery(input: &str) -> Result<Issuer, OidcClientError> {
        let async_runtime = tokio::runtime::Runtime::new().unwrap();

        let result: Result<Issuer, OidcClientError> = async_runtime.block_on(async {
            let iss = Issuer::webfinger_async(input, None).await;
            return iss;
        });
        result
    }

    #[test]
    fn can_discover_using_the_email_syntax() {
        let mock_http_server = MockServer::start();

        let auth_server_domain = get_url_with_count("opemail.example<>.com");

        let webfinger_response_body = format!("{{\"subject\":\"https://{0}/joe\",\"links\":[{{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://{0}\"}}]}}", auth_server_domain);
        let discovery_document_response_body = format!("{{\"authorization_endpoint\":\"https://{0}/o/oauth2/v2/auth\",\"issuer\":\"https://{0}\",\"jwks_uri\":\"https://{0}/oauth2/v3/certs\",\"token_endpoint\":\"https://{0}/oauth2/v4/token\",\"userinfo_endpoint\":\"https://{0}/oauth2/v3/userinfo\"}}", auth_server_domain);

        set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

        let resource = format!("joe@{}", auth_server_domain);

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

        let _ = Issuer::webfinger(&resource, None);

        let _ = get_async_webfinger_discovery(&resource);

        webfinger_mock_server.assert_hits(2);
        issuer_discovery_mock_server.assert_hits(2);
    }

    #[test]
    fn verifies_the_webfinger_responds_with_an_issuer() {
        let mock_http_server = MockServer::start();

        let auth_server_domain = get_url_with_count("opemail.example<>.com");

        let webfinger_response_body = format!(
            "{{\"subject\":\"https://{0}/joe\",\"links\":[]}}",
            auth_server_domain
        );

        set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

        let _webfinger_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .path("/.well-known/webfinger")
                .header("Accept", "application/json");
            then.status(200).body(webfinger_response_body);
        });

        let resource = format!("joe@{}", auth_server_domain);

        let error = Issuer::webfinger(&resource, None).unwrap_err();
        let async_error = get_async_webfinger_discovery(&resource).unwrap_err();

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
        let mock_http_server = MockServer::start();

        let auth_server_domain = get_url_with_count("opemail.example<>.com");

        let webfinger_response_body = format!("{{\"subject\":\"https://{0}/joe\",\"links\":[{{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://{0}\"}}]}}", auth_server_domain);

        set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

        let _webfinger_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/webfinger");
            then.status(200).body(webfinger_response_body);
        });

        let resource = format!("joe@{}", auth_server_domain);

        let error = Issuer::webfinger(&resource, None).unwrap_err();
        let async_error = get_async_webfinger_discovery(&resource).unwrap_err();

        assert_eq!(
            error.error_description,
            format!("invalid issuer location https://{}", auth_server_domain)
        );
        assert_eq!(
            async_error.error_description,
            format!("invalid issuer location https://{}", auth_server_domain)
        );
    }

    #[test]
    fn verifies_the_webfinger_responds_with_an_issuer_which_is_a_valid_issuer_value_2_of_2() {
        let mock_http_server = MockServer::start();

        let auth_server_domain = get_url_with_count("opemail.example<>.com");

        let webfinger_response_body = format!("{{\"subject\":\"https://{}/joe\",\"links\":[{{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"1\"}}]}}", auth_server_domain);

        set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

        let _webfinger = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/webfinger");
            then.status(200).body(webfinger_response_body);
        });

        let resource = format!("joe@{}", auth_server_domain);

        let error = Issuer::webfinger(&resource, None).unwrap_err();
        let async_error = get_async_webfinger_discovery(&resource).unwrap_err();

        assert_eq!(error.error_description, "invalid issuer location 1");
        assert_eq!(async_error.error_description, "invalid issuer location 1");
    }

    // Todo: not implementing cache right now
    // #[test]
    // fn uses_cached_issuer_if_it_has_one() {
    //  mock_http_server server = MockServer::start();

    //     let auth_server_domain = get_url_with_count("opemail.example<>.com");

    //     let webfinger_response_body = format!("{{\"subject\":\"https://{0}/joe\",\"links\":[{{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://{0}\"}}]}}", auth_server_domain);
    //     let discovery_document_response_body = format!("{{\"authorization_endpoint\":\"https://{0}/o/oauth2/v2/auth\",\"issuer\":\"https://{0}\",\"jwks_uri\":\"https://{0}/oauth2/v3/certs\",\"token_endpoint\":\"https://{0}/oauth2/v4/token\",\"userinfo_endpoint\":\"https://{0}/oauth2/v3/userinfo\"}}", auth_server_domain);

    //     let resource = format!("joe@{}", auth_server_domain);

    //     set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

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

        let auth_server_domain = get_url_with_count("opemail.example<>.com");

        let webfinger_response_body = format!("{{\"subject\":\"https://{0}/joe\",\"links\":[{{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://{0}\"}}]}}", auth_server_domain);
        let discovery_document_response_body = format!("{{\"authorization_endpoint\":\"https://{0}/o/oauth2/v2/auth\",\"issuer\":\"https://another.issuer.com\",\"jwks_uri\":\"https://{0}/oauth2/v3/certs\",\"token_endpoint\":\"https://{0}/oauth2/v4/token\",\"userinfo_endpoint\":\"https://{0}/oauth2/v3/userinfo\"}}", auth_server_domain);

        set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

        let webfinger_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/webfinger");
            then.status(200).body(webfinger_response_body);
        });

        let issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).body(discovery_document_response_body);
        });

        let resource = format!("joe@{}", auth_server_domain);

        let error = Issuer::webfinger(&resource, None).unwrap_err();
        let async_error = get_async_webfinger_discovery(&resource).unwrap_err();

        assert_eq!(
            format!(
                "discovered issuer mismatch, expected https://{}, got: https://another.issuer.com",
                auth_server_domain
            ),
            error.error_description
        );
        assert_eq!(
            format!(
                "discovered issuer mismatch, expected https://{}, got: https://another.issuer.com",
                auth_server_domain
            ),
            async_error.error_description
        );

        webfinger_mock_server.assert_hits(2);
        issuer_discovery_mock_server.assert_hits(2);
    }

    #[test]
    fn can_discover_using_the_url_syntax() {
        let mock_http_server = MockServer::start();

        let auth_server_domain = get_url_with_count("opurl.example<>.com");

        let webfinger_response_body = format!("{{\"subject\":\"https://{0}/joe\",\"links\":[{{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://{0}\"}}]}}", auth_server_domain);
        let discovery_document_response_body = format!("{{\"authorization_endpoint\":\"https://{0}/o/oauth2/v2/auth\",\"issuer\":\"https://{0}\",\"jwks_uri\":\"https://{0}/oauth2/v3/certs\",\"token_endpoint\":\"https://{0}/oauth2/v4/token\",\"userinfo_endpoint\":\"https://{0}/oauth2/v3/userinfo\"}}", auth_server_domain);

        let webfinger_url = format!("https://{}/joe", auth_server_domain);

        set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

        let webfinger_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .path("/.well-known/webfinger")
                .query_param("resource", &webfinger_url);
            then.status(200).body(webfinger_response_body);
        });

        let issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).body(discovery_document_response_body);
        });

        let issuer_result = Issuer::webfinger(&webfinger_url, None);
        let async_issuer_result = get_async_webfinger_discovery(&webfinger_url);

        assert!(issuer_result.is_ok());
        assert!(async_issuer_result.is_ok());

        webfinger_mock_server.assert_hits(2);
        issuer_discovery_mock_server.assert_hits(2);
    }

    #[test]
    fn can_discover_using_the_hostname_and_port_syntax() {
        let mock_http_server = MockServer::start();

        let auth_server_domain = get_url_with_count("ophp.example<>.com");

        let auth_server_domain_with_port = format!("{}:8080", auth_server_domain);

        let webfinger_response_body = format!("{{\"subject\":\"https://{0}:8080\",\"links\":[{{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://{0}\"}}]}}", auth_server_domain);
        let discovery_document_response_body = format!("{{\"authorization_endpoint\":\"https://{0}/o/oauth2/v2/auth\",\"issuer\":\"https://{0}\",\"jwks_uri\":\"https://{0}/oauth2/v3/certs\",\"token_endpoint\":\"https://{0}/oauth2/v4/token\",\"userinfo_endpoint\":\"https://{0}/oauth2/v3/userinfo\"}}", auth_server_domain);

        // for webfinger
        set_mock_domain(&auth_server_domain_with_port, mock_http_server.port());
        // for oidc discovery
        set_mock_domain(&auth_server_domain, mock_http_server.port());

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

        let issuer_result = Issuer::webfinger(&auth_server_domain_with_port, None);
        let async_issuer_result = get_async_webfinger_discovery(&auth_server_domain_with_port);

        assert!(issuer_result.is_ok());
        assert!(async_issuer_result.is_ok());

        webfinger_mock_server.assert_hits(2);
        issuer_discovery_mock_server.assert_hits(2);
    }

    #[test]
    fn can_discover_using_the_acct_syntax() {
        let mock_http_server = MockServer::start();

        let auth_server_domain = get_url_with_count("opacct.example<>.com");
        let resource = format!("acct:juliet%40capulet.example@{}", auth_server_domain);

        let webfinger_response_body = format!("{{\"subject\":\"{0}\",\"links\":[{{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://{1}\"}}]}}", resource, auth_server_domain);
        let discovery_document_response_body = format!("{{\"authorization_endpoint\":\"https://{0}/o/oauth2/v2/auth\",\"issuer\":\"https://{0}\",\"jwks_uri\":\"https://{0}/oauth2/v3/certs\",\"token_endpoint\":\"https://{0}/oauth2/v4/token\",\"userinfo_endpoint\":\"https://{0}/oauth2/v3/userinfo\"}}", auth_server_domain);

        set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

        let webfinger_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .path("/.well-known/webfinger")
                .query_param("resource", &resource);
            then.status(200).body(webfinger_response_body);
        });

        let issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).body(discovery_document_response_body);
        });

        let issuer_result = Issuer::webfinger(&resource, None);
        let async_issuer_result = get_async_webfinger_discovery(&resource);

        assert!(issuer_result.is_ok());
        assert!(async_issuer_result.is_ok());

        webfinger_mock_server.assert_hits(2);
        issuer_discovery_mock_server.assert_hits(2);
    }

    #[cfg(test)]
    mod http_options {
        use std::time::Duration;

        use httpmock::{Method::GET, MockServer};
        use reqwest::header::{HeaderMap, HeaderValue};

        use crate::{
            issuer::Issuer,
            tests::{get_url_with_count, set_mock_domain},
            types::{OidcClientError, RequestOptions},
        };

        #[test]
        fn allows_for_http_options_to_be_defined_for_issuer_webfinger_calls() {
            let mock_http_server = MockServer::start();

            let auth_server_domain = get_url_with_count("op.example<>.com");

            let resource = format!("acct:juliet@{}", auth_server_domain);

            let webfinger_response_body = format!("{{\"subject\":\"{0}\",\"links\":[{{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://{1}\"}}]}}", resource, auth_server_domain);
            let discovery_document_response_body = format!("{{\"authorization_endpoint\":\"https://{0}/o/oauth2/v2/auth\",\"issuer\":\"https://{0}\",\"jwks_uri\":\"https://{0}/oauth2/v3/certs\",\"token_endpoint\":\"https://{0}/oauth2/v4/token\",\"userinfo_endpoint\":\"https://{0}/oauth2/v3/userinfo\"}}", auth_server_domain);

            set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

            let webfinger_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET)
                    .path("/.well-known/webfinger")
                    .header("custom", "foo")
                    .query_param("resource", &resource);
                then.status(200).body(webfinger_response_body);
            });

            let issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET)
                    .path("/.well-known/openid-configuration")
                    .header("custom", "foo");
                then.status(200).body(discovery_document_response_body);
            });

            let interceptor = |_request: &crate::types::Request| {
                let mut headers = HeaderMap::new();
                headers.append("custom", HeaderValue::from_static("foo"));
                RequestOptions {
                    headers,
                    timeout: Duration::from_millis(3500),
                }
            };

            let issuer_result = Issuer::webfinger(&resource, Some(Box::new(interceptor)));

            webfinger_mock_server.assert();
            issuer_discovery_mock_server.assert();
            assert!(issuer_result.is_ok());
        }

        #[test]
        fn allows_for_http_options_to_be_defined_for_issuer_webfinger_calls_async() {
            let mock_http_server = MockServer::start();

            let auth_server_domain = get_url_with_count("op.example<>.com");
            let resource = format!("acct:juliet@{}", auth_server_domain);

            let webfinger_response_body = format!("{{\"subject\":\"{0}\",\"links\":[{{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://{1}\"}}]}}", resource, auth_server_domain);
            let discovery_document_response_body = format!("{{\"authorization_endpoint\":\"https://{0}/o/oauth2/v2/auth\",\"issuer\":\"https://{0}\",\"jwks_uri\":\"https://{0}/oauth2/v3/certs\",\"token_endpoint\":\"https://{0}/oauth2/v4/token\",\"userinfo_endpoint\":\"https://{0}/oauth2/v3/userinfo\"}}", auth_server_domain);

            set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

            let webfinger_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET)
                    .path("/.well-known/webfinger")
                    .header("custom", "foo")
                    .query_param("resource", &resource);
                then.status(200).body(webfinger_response_body);
            });

            let issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET)
                    .path("/.well-known/openid-configuration")
                    .header("custom", "foo");
                then.status(200).body(discovery_document_response_body);
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

            let issuer_result: Result<Issuer, OidcClientError> = async_runtime.block_on(async {
                Issuer::webfinger_async(&resource, Some(Box::new(interceptor))).await
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
            issuer
                .introspection_endpoint_auth_methods_supported
                .unwrap(),
            token_endpoint_auth_methods_supported()
        );
        assert_eq!(
            issuer.revocation_endpoint_auth_methods_supported.unwrap(),
            token_endpoint_auth_methods_supported()
        );

        assert_eq!(
            issuer
                .revocation_endpoint_auth_signing_alg_values_supported
                .unwrap(),
            token_endpoint_auth_signing_alg_values_supported()
        );
        assert_eq!(
            issuer
                .introspection_endpoint_auth_signing_alg_values_supported
                .unwrap(),
            token_endpoint_auth_signing_alg_values_supported()
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
        let auth_server_domain = get_url_with_count("op.example<>.com");

        let mock_http_server = MockServer::start();

        let jwks_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .header("Accept", "application/json,application/jwk-set+json")
                .path("/jwks");
            then.status(200)
                .header("content-type", "application/jwk-set+json")
                .body(get_default_jwks());
        });

        set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

        let issuer = format!("https://{}", auth_server_domain);
        let jwks_uri = format!("https://{}/jwks", auth_server_domain);

        let metadata = IssuerMetadata {
            issuer,
            jwks_uri: Some(jwks_uri),
            ..IssuerMetadata::default()
        };

        let mut issuer = Issuer::new(metadata, None);

        assert!(issuer.get_keystore(true).is_ok());

        let _ = issuer.get_keystore(false).unwrap();

        jwks_mock_server.assert_hits(1);
    }

    #[test]
    fn does_not_refetch_immediately_async() {
        let auth_server_domain = get_url_with_count("op.example<>.com");

        let mock_http_server = MockServer::start();

        let jwks_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .header("Accept", "application/json,application/jwk-set+json")
                .path("/jwks");
            then.status(200)
                .header("content-type", "application/jwk-set+json")
                .body(get_default_jwks());
        });

        set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

        let issuer = format!("https://{}", auth_server_domain);
        let jwks_uri = format!("https://{}/jwks", auth_server_domain);

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

        jwks_mock_server.assert_hits(1);
    }

    #[test]
    fn refetches_if_asked_to() {
        let auth_server_domain = get_url_with_count("op.example<>.com");

        let mock_http_server = MockServer::start();

        let jwks_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .header("Accept", "application/json,application/jwk-set+json")
                .path("/jwks");
            then.status(200)
                .header("content-type", "application/jwk-set+json")
                .body(get_default_jwks());
        });

        set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

        let issuer = format!("https://{}", auth_server_domain);
        let jwks_uri = format!("https://{}/jwks", auth_server_domain);

        let metadata = IssuerMetadata {
            issuer,
            jwks_uri: Some(jwks_uri),
            ..IssuerMetadata::default()
        };

        let mut issuer = Issuer::new(metadata, None);

        assert!(issuer.get_keystore(true).is_ok());
        assert!(issuer.get_keystore(true).is_ok());

        jwks_mock_server.assert_hits(2);
    }

    #[test]
    fn refetches_if_asked_to_async() {
        let auth_server_domain = get_url_with_count("op.example<>.com");

        let mock_http_server = MockServer::start();

        let jwks_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .header("Accept", "application/json,application/jwk-set+json")
                .path("/jwks");
            then.status(200)
                .header("content-type", "application/jwk-set+json")
                .body(get_default_jwks());
        });

        set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

        let issuer = format!("https://{}", auth_server_domain);
        let jwks_uri = format!("https://{}/jwks", auth_server_domain);

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

        jwks_mock_server.assert_hits(2);
    }

    #[test]
    fn rejects_when_no_matching_key_is_found() {
        let auth_server_domain = get_url_with_count("op.example<>.com");

        let mock_http_server = MockServer::start();

        let _jwks_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .header("Accept", "application/json,application/jwk-set+json")
                .path("/jwks");
            then.status(200)
                .header("content-type", "application/jwk-set+json")
                .body(get_default_jwks());
        });

        set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

        let issuer = format!("https://{}", auth_server_domain);
        let jwks_uri = format!("https://{}/jwks", auth_server_domain);

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
        let auth_server_domain = get_url_with_count("op.example<>.com");

        let mock_http_server = MockServer::start();

        let _jwks_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .header("Accept", "application/json,application/jwk-set+json")
                .path("/jwks");

            then.status(200)
                .header("content-type", "application/jwk-set+json")
                .body("{\"keys\":[{\"e\":\"AQAB\",\"n\":\"5RnVQ2VT79TaW_Louj5ib7_dVJ1vX5ebaVeifBjNDlUp3KsrHm5sq1KWzPVz-XE6m4GBGXnVxMc5pmN7pQcqGe2rzw_jTAOIQzjYZ2UPTvl8HSjPCf9VwJleHiy4195YgnOcAF-PVASLKNKnoHjgn4b2gXpikMnztvdTFZrQAAlEVwslbW0Z17imHQsYzDXDYVzwpxjiRl4tWretNXhJS2Bk1NZoctW5kY6otkeMZ8VLpCUfbBzrhhLh5b_7Q0JKQjGX94f8j5tpVz_CXkpwQUXyymfBH9B-FY5s7LDZRKCEneSnCwSFce_nVzPqcO5J4SwsVF6FhwVQMvCC0QmNGw\",\"kty\":\"RSA\"},{\"e\":\"AQAB\",\"n\":\"3ANc8Uhup5_tnZfJuR4jQIwzobzEegcPGySt_EVzdF8ft2L4RoOE8wWq2fff9tRtrzNcKjSTgpw6cDMXSEa2Mx07FUvuyvjXSzlUG_fEPGIhyEJXqD5NZ89CrgHy55kizSuvgxcpQLkvSddBXVYnccWRGXfCurj7BkY1ycxvm55LAkPkaEtSWmnX8gWX6289SeKx-3rD0Xl20lhoe0_f4nChWibn-2egKBfrq-d1nXnsyxOcDhOZHS9nC4N4UeiZyQ6ervyGDg1fxzi98gxe4qb14J3vogX3KUdyG0YuC4D1SgUtEnmrVbbQl9y3fYBKZy7ysk48j9CdWjA9KYoWUQ\",\"kty\":\"RSA\"}]}");
        });

        set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

        let issuer = format!("https://{}", auth_server_domain);
        let jwks_uri = format!("https://{}/jwks", auth_server_domain);

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
        let auth_server_domain = get_url_with_count("op.example<>.com");

        let mock_http_server = MockServer::start();

        let _jwks_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .header("Accept", "application/json,application/jwk-set+json")
                .path("/jwks");

            then.status(200)
                .header("content-type", "application/jwk-set+json")
                .body("{\"keys\":[{\"e\":\"AQAB\",\"n\":\"5RnVQ2VT79TaW_Louj5ib7_dVJ1vX5ebaVeifBjNDlUp3KsrHm5sq1KWzPVz-XE6m4GBGXnVxMc5pmN7pQcqGe2rzw_jTAOIQzjYZ2UPTvl8HSjPCf9VwJleHiy4195YgnOcAF-PVASLKNKnoHjgn4b2gXpikMnztvdTFZrQAAlEVwslbW0Z17imHQsYzDXDYVzwpxjiRl4tWretNXhJS2Bk1NZoctW5kY6otkeMZ8VLpCUfbBzrhhLh5b_7Q0JKQjGX94f8j5tpVz_CXkpwQUXyymfBH9B-FY5s7LDZRKCEneSnCwSFce_nVzPqcO5J4SwsVF6FhwVQMvCC0QmNGw\",\"kty\":\"RSA\",\"kid\":\"0pWEDfNcRM4-Lnqq6QDkmVzElFEdYE96gJff6yesi0A\"},{\"e\":\"AQAB\",\"n\":\"3ANc8Uhup5_tnZfJuR4jQIwzobzEegcPGySt_EVzdF8ft2L4RoOE8wWq2fff9tRtrzNcKjSTgpw6cDMXSEa2Mx07FUvuyvjXSzlUG_fEPGIhyEJXqD5NZ89CrgHy55kizSuvgxcpQLkvSddBXVYnccWRGXfCurj7BkY1ycxvm55LAkPkaEtSWmnX8gWX6289SeKx-3rD0Xl20lhoe0_f4nChWibn-2egKBfrq-d1nXnsyxOcDhOZHS9nC4N4UeiZyQ6ervyGDg1fxzi98gxe4qb14J3vogX3KUdyG0YuC4D1SgUtEnmrVbbQl9y3fYBKZy7ysk48j9CdWjA9KYoWUQ\",\"kty\":\"RSA\",\"kid\":\"0pWEDfNcRM4-Lnqq6QDkmVzElFEdYE96gJff6yesi0A\"}]}");
        });

        set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

        let issuer = format!("https://{}", auth_server_domain);
        let jwks_uri = format!("https://{}/jwks", auth_server_domain);

        let metadata = IssuerMetadata {
            issuer,
            jwks_uri: Some(jwks_uri),
            ..IssuerMetadata::default()
        };

        let mut issuer = Issuer::new(metadata, None);

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
        use std::time::Duration;

        use reqwest::header::{HeaderMap, HeaderValue};

        use crate::{tests::get_url_with_count, types::RequestOptions};

        use super::*;

        #[test]
        fn allows_for_http_options_to_be_defined_for_issuer_keystore_calls() {
            let mock_http_server = MockServer::start();

            let auth_server_domain = get_url_with_count("op.example<>.com");
            let issuer = format!("https://{}", auth_server_domain);
            let jwks_uri = format!("https://{}/jwks", auth_server_domain);

            let jwks_mock_server = mock_http_server.mock(|when, then| {
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

            set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

            let _ = Issuer::discover(
                &format!(
                    "https://{}/.well-known/custom-configuration",
                    auth_server_domain
                ),
                Some(Box::new(interceptor)),
            );

            let metadata = IssuerMetadata {
                issuer,
                jwks_uri: Some(jwks_uri),
                ..IssuerMetadata::default()
            };

            let mut issuer = Issuer::new(metadata, Some(Box::new(interceptor)));

            let _ = issuer.get_keystore(false);

            jwks_mock_server.assert_hits(1);
        }

        #[test]
        fn allows_for_http_options_to_be_defined_for_issuer_keystore_calls_async() {
            let mock_http_server = MockServer::start();

            let auth_server_domain = get_url_with_count("op.example<>.com");
            let issuer = format!("https://{}", auth_server_domain);
            let jwks_uri = format!("https://{}/jwks", auth_server_domain);

            let jwks_mock_server = mock_http_server.mock(|when, then| {
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

            set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

            let _ = Issuer::discover(
                &format!(
                    "https://{}/.well-known/custom-configuration",
                    auth_server_domain
                ),
                Some(Box::new(interceptor)),
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
                jwks_mock_server.assert_hits(1);
            });
        }
    }
}
