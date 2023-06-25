#[cfg(test)]
mod client_new_tests {
    use std::collections::HashMap;

    use crate::issuer::Issuer;
    use crate::types::{ClientMetadata, IssuerMetadata};

    #[test]
    fn requires_client_id() {
        let issuer_metadata = IssuerMetadata::default();
        let issuer = Issuer::new(issuer_metadata, None);
        let client_result = issuer.client(ClientMetadata::default(), None, None, None);

        assert!(client_result.is_err());

        let error = client_result.unwrap_err();

        assert_eq!("client_id is required", error.error_description);
    }

    #[test]
    fn accepts_the_recognized_metadata() {
        let issuer_metadata = IssuerMetadata::default();
        let issuer = Issuer::new(issuer_metadata, None);

        let client_id = "identifier".to_string();
        let client_secret = Some("secure".to_string());

        let client_metadata = ClientMetadata {
            client_id: Some(client_id.clone()),
            client_secret: client_secret.clone(),
            ..ClientMetadata::default()
        };
        let client_result = issuer.client(client_metadata, None, None, None);

        assert!(client_result.is_ok());

        let client = client_result.unwrap();

        assert_eq!(client_id, client.get_client_id());
        assert_eq!(client_secret.unwrap(), client.get_client_secret().unwrap());
    }

    #[test]
    fn assigns_defaults_to_some_properties() {
        let issuer_metadata = IssuerMetadata::default();
        let issuer = Issuer::new(issuer_metadata, None);

        let client_id = "identifier".to_string();

        let client_metadata = ClientMetadata {
            client_id: Some(client_id.clone()),
            ..ClientMetadata::default()
        };

        let client_result = issuer.client(client_metadata, None, None, None);

        assert!(client_result.is_ok());

        let client = client_result.unwrap();

        assert_eq!(client_id, client.get_client_id());
        assert_eq!(vec!["authorization_code"], client.get_grant_types());
        assert_eq!(
            "RS256".to_string(),
            client.get_id_token_signed_response_alg()
        );
        assert_eq!(vec!["code".to_string()], client.get_response_types());
        assert_eq!(
            "client_secret_basic".to_string(),
            client.get_token_endpoint_auth_method()
        );
    }

    #[test]
    fn autofills_introspection_endpoint_auth_method() {
        let issuer_metadata = IssuerMetadata {
            introspection_endpoint: Some("https://op.example.com/token/introspection".to_string()),
            ..IssuerMetadata::default()
        };

        let issuer = Issuer::new(issuer_metadata, None);

        let token_endpoint_auth_method = || "client_secret_jwt".to_string();
        let token_endpoint_auth_signing_alg = || "HS512".to_string();

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            token_endpoint_auth_method: Some(token_endpoint_auth_method()),
            token_endpoint_auth_signing_alg: Some(token_endpoint_auth_signing_alg()),
            ..ClientMetadata::default()
        };

        let client = issuer.client(client_metadata, None, None, None).unwrap();

        assert_eq!(
            token_endpoint_auth_method(),
            client.get_introspection_endpoint_auth_method().unwrap()
        );

        assert_eq!(
            token_endpoint_auth_signing_alg(),
            client
                .get_introspection_endpoint_auth_signing_alg()
                .unwrap()
        );
    }

    #[test]
    fn autofills_revocation_endpoint_auth_method() {
        let issuer_metadata = IssuerMetadata {
            revocation_endpoint: Some("https://op.example.com/token/revocation".to_string()),
            ..IssuerMetadata::default()
        };

        let issuer = Issuer::new(issuer_metadata, None);

        let token_endpoint_auth_method = || "client_secret_jwt".to_string();
        let token_endpoint_auth_signing_alg = || "HS512".to_string();

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            token_endpoint_auth_method: Some(token_endpoint_auth_method()),
            token_endpoint_auth_signing_alg: Some(token_endpoint_auth_signing_alg()),
            ..ClientMetadata::default()
        };

        let client = issuer.client(client_metadata, None, None, None).unwrap();

        assert_eq!(
            token_endpoint_auth_method(),
            client.get_revocation_endpoint_auth_method().unwrap()
        );

        assert_eq!(
            token_endpoint_auth_signing_alg(),
            client.get_revocation_endpoint_auth_signing_alg().unwrap()
        );
    }

    #[test]
    fn validates_the_issuer_has_supported_algs_announced_if_token_endpoint_signing_alg_is_not_defined_on_the_client(
    ) {
        let issuer_metadata = IssuerMetadata {
            token_endpoint: Some("https://op.example.com/token".to_string()),
            ..IssuerMetadata::default()
        };

        let issuer = Issuer::new(issuer_metadata, None);

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            token_endpoint_auth_method: Some("_jwt".to_string()),
            ..ClientMetadata::default()
        };

        let client_error = issuer
            .client(client_metadata, None, None, None)
            .unwrap_err();

        let expected_error = "token_endpoint_auth_signing_alg_values_supported must be configured on the issuer if token_endpoint_auth_signing_alg is not defined on a client";

        assert_eq!(client_error.error_description, expected_error);
    }

    #[test]
    fn validates_the_issuer_has_supported_algs_announced_if_introspection_endpoint_signing_alg_is_not_defined_on_the_client(
    ) {
        let issuer_metadata = IssuerMetadata {
            introspection_endpoint: Some("https://op.example.com/token/introspection".to_string()),
            ..IssuerMetadata::default()
        };

        let issuer = Issuer::new(issuer_metadata, None);

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            introspection_endpoint_auth_method: Some("_jwt".to_string()),
            ..ClientMetadata::default()
        };

        let client_error = issuer
            .client(client_metadata, None, None, None)
            .unwrap_err();

        let expected_error = "introspection_endpoint_auth_signing_alg_values_supported must be configured on the issuer if introspection_endpoint_auth_signing_alg is not defined on a client";

        assert_eq!(client_error.error_description, expected_error);
    }

    #[test]
    fn validates_the_issuer_has_supported_algs_announced_if_revocation_endpoint_signing_alg_is_not_defined_on_the_client(
    ) {
        let issuer_metadata = IssuerMetadata {
            revocation_endpoint: Some("https://op.example.com/token/revocation".to_string()),
            ..IssuerMetadata::default()
        };

        let issuer = Issuer::new(issuer_metadata, None);

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            revocation_endpoint_auth_method: Some("_jwt".to_string()),
            ..ClientMetadata::default()
        };

        let client_error = issuer
            .client(client_metadata, None, None, None)
            .unwrap_err();

        let expected_error = "revocation_endpoint_auth_signing_alg_values_supported must be configured on the issuer if revocation_endpoint_auth_signing_alg is not defined on a client";

        assert_eq!(client_error.error_description, expected_error);
    }

    #[test]
    fn is_able_to_assign_custom_or_non_recognized_properties() {
        let issuer = Issuer::new(IssuerMetadata::default(), None);

        let mut other_fields: HashMap<String, serde_json::Value> = HashMap::new();

        other_fields.insert(
            "foo".to_string(),
            serde_json::Value::String("bar".to_string()),
        );

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            other_fields,
            ..ClientMetadata::default()
        };

        let client = issuer.client(client_metadata, None, None, None).unwrap();

        assert!(client.get_field("foo").is_some());
    }

    #[test]
    fn handles_redirect_uri() {
        let issuer = Issuer::new(IssuerMetadata::default(), None);

        let redirect_uri = || "https://rp.example.com/cb".to_string();

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            redirect_uri: Some(redirect_uri()),
            ..ClientMetadata::default()
        };

        let client = issuer.client(client_metadata, None, None, None).unwrap();

        assert_eq!(client.get_redirect_uri().unwrap(), redirect_uri());
        assert_eq!(client.get_redirect_uris().unwrap(), vec![redirect_uri()]);
    }

    #[test]
    fn returns_error_if_redirect_uri_and_redirect_uris_are_given() {
        let issuer = Issuer::new(IssuerMetadata::default(), None);

        let redirect_uri = || "https://rp.example.com/cb".to_string();

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            redirect_uri: Some(redirect_uri()),
            redirect_uris: Some(vec![redirect_uri()]),
            ..ClientMetadata::default()
        };

        let client_error = issuer
            .client(client_metadata, None, None, None)
            .unwrap_err();
        assert_eq!(
            "provide a redirect_uri or redirect_uris, not both".to_string(),
            client_error.error_description
        );
    }

    #[test]
    fn handles_response_type() {
        let issuer = Issuer::new(IssuerMetadata::default(), None);

        let response_type = || "code id_token".to_string();

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            response_type: Some(response_type()),
            ..ClientMetadata::default()
        };

        let client = issuer.client(client_metadata, None, None, None).unwrap();

        assert_eq!(client.get_response_type().unwrap(), response_type());
        assert_eq!(client.get_response_types(), vec![response_type()]);
    }

    #[test]
    fn returns_error_if_response_type_and_response_types_are_given() {
        let issuer = Issuer::new(IssuerMetadata::default(), None);

        let response_type = || "code id_token".to_string();

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            response_type: Some(response_type()),
            response_types: Some(vec![response_type()]),
            ..ClientMetadata::default()
        };

        let client_error = issuer
            .client(client_metadata, None, None, None)
            .unwrap_err();
        assert_eq!(
            "provide a response_type or response_types, not both".to_string(),
            client_error.error_description
        );
    }

    #[cfg(test)]
    mod dynamic_registration_defaults_not_supported_by_issuer {
        use crate::{
            issuer::Issuer,
            types::{ClientMetadata, IssuerMetadata},
        };

        #[test]
        fn token_endpoint_auth_method_vs_token_endpoint_auth_methods_supported() {
            let issuer_metadata = IssuerMetadata {
                issuer: "https://op.example.com".to_string(),
                token_endpoint_auth_methods_supported: Some(vec![
                    "client_secret_post".to_string(),
                    "private_key_jwt".to_string(),
                ]),
                ..IssuerMetadata::default()
            };
            let issuer = Issuer::new(issuer_metadata, None);

            let client_metadata = ClientMetadata {
                client_id: Some("identifier".to_string()),
                ..ClientMetadata::default()
            };

            let client = issuer.client(client_metadata, None, None, None).unwrap();
            assert_eq!(
                "client_secret_post".to_string(),
                client.get_token_endpoint_auth_method()
            );
        }
    }

    #[cfg(test)]
    mod client_read_discovery {
        use httpmock::{Method::GET, MockServer};

        use crate::{
            client::Client,
            helpers::convert_json_to,
            jwks::Jwks,
            tests::{get_url_with_count, set_mock_domain},
            types::OidcClientError,
        };

        pub fn get_default_expected_client_read_response() -> String {
            "{\"client_id\":\"identifier\",\"client_secret\":\"secure\"}".to_string()
        }

        pub fn get_async_client_discovery(
            client_registration_uri: &str,
        ) -> Result<Client, OidcClientError> {
            let async_runtime = tokio::runtime::Runtime::new().unwrap();

            let result: Result<Client, OidcClientError> = async_runtime.block_on(async {
                Client::from_uri_async(client_registration_uri, None, None, None, None, None).await
            });
            result
        }

        #[test]
        fn accepts_and_assigns_discovered_metadata() {
            let mock_http_server = MockServer::start();

            let auth_server_domain = get_url_with_count("op.example<>.com");

            let _auth_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET).path("/client/identifier");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(get_default_expected_client_read_response());
            });

            set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

            let client_registration_uri =
                format!("https://{}/client/identifier", auth_server_domain);

            let client =
                Client::from_uri(&client_registration_uri, None, None, None, None, None).unwrap();

            let client_async = get_async_client_discovery(&client_registration_uri).unwrap();

            assert_eq!("identifier", client.get_client_id());
            assert_eq!("identifier", client_async.get_client_id());

            assert_eq!("secure", client.get_client_secret().unwrap());
            assert_eq!("secure", client_async.get_client_secret().unwrap());
        }

        #[test]
        fn is_rejected_with_op_error_upon_oidc_error() {
            let mock_http_server = MockServer::start();

            let auth_server_domain = get_url_with_count("op.example<>.com");

            let _auth_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET).path("/client/identifier");
                then.status(500).body(
                "{\"error\":\"server_error\",\"error_description\":\"bad things are happening\"}",
            );
            });

            set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

            let client_registration_uri =
                format!("https://{}/client/identifier", auth_server_domain);

            let client_error =
                Client::from_uri(&client_registration_uri, None, None, None, None, None)
                    .unwrap_err();

            let client_error_async =
                get_async_client_discovery(&client_registration_uri).unwrap_err();

            assert_eq!("OPError", client_error.name);
            assert_eq!("OPError", client_error_async.name);

            assert_eq!("server_error", client_error.error);
            assert_eq!("server_error", client_error_async.error);

            assert_eq!("bad things are happening", client_error.error_description);
            assert_eq!(
                "bad things are happening",
                client_error_async.error_description
            );
        }

        #[test]
        fn is_rejected_with_op_error_upon_oidc_error_in_www_authenticate_header() {
            let mock_http_server = MockServer::start();

            let auth_server_domain = get_url_with_count("op.example<>.com");

            let _auth_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET).path("/client/identifier");
                then.status(401)
                    .body("Unauthorized")
                    .header("WWW-Authenticate", "Bearer error=\"invalid_token\", error_description=\"bad things are happening\"");
            });

            set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

            let client_registration_uri =
                format!("https://{}/client/identifier", auth_server_domain);

            let client_error =
                Client::from_uri(&client_registration_uri, None, None, None, None, None)
                    .unwrap_err();

            let client_error_async =
                get_async_client_discovery(&client_registration_uri).unwrap_err();

            assert_eq!("OPError", client_error.name);
            assert_eq!("OPError", client_error_async.name);

            assert_eq!("invalid_token", client_error.error);
            assert_eq!("invalid_token", client_error_async.error);

            assert_eq!("bad things are happening", client_error.error_description);
            assert_eq!(
                "bad things are happening",
                client_error_async.error_description
            );
        }

        #[test]
        fn is_rejected_with_when_non_200_is_returned() {
            let mock_http_server = MockServer::start();

            let auth_server_domain = get_url_with_count("op.example<>.com");

            let _auth_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET).path("/client/identifier");
                then.status(500).body("Internal Server Error");
            });

            set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

            let client_registration_uri =
                format!("https://{}/client/identifier", auth_server_domain);

            let client_error =
                Client::from_uri(&client_registration_uri, None, None, None, None, None)
                    .unwrap_err();

            let client_error_async =
                get_async_client_discovery(&client_registration_uri).unwrap_err();

            assert_eq!("OPError", client_error.name);
            assert_eq!("OPError", client_error_async.name);

            assert!(client_error.response.is_some());
            assert!(client_error_async.response.is_some());

            assert_eq!(
                "expected 200 OK, got: 500 Internal Server Error",
                client_error.error_description
            );
            assert_eq!(
                "expected 200 OK, got: 500 Internal Server Error",
                client_error_async.error_description
            );
        }

        #[test]
        fn is_rejected_with_json_parse_error_upon_invalid_response() {
            let mock_http_server = MockServer::start();

            let auth_server_domain = get_url_with_count("op.example<>.com");

            let _auth_mock_server = mock_http_server.mock(|when, then| {
                when.method(GET).path("/client/identifier");
                then.status(200).body("{\"notavalid\"}");
            });

            set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

            let client_registration_uri =
                format!("https://{}/client/identifier", auth_server_domain);

            let client_error =
                Client::from_uri(&client_registration_uri, None, None, None, None, None)
                    .unwrap_err();

            let client_error_async =
                get_async_client_discovery(&client_registration_uri).unwrap_err();

            assert_eq!(client_error.name, "TypeError");
            assert_eq!(client_error_async.name, "TypeError");

            assert_eq!(client_error.error, "parse_error");
            assert_eq!(client_error_async.error, "parse_error");

            assert_eq!(client_error.error_description, "unexpected body type");
            assert_eq!(client_error_async.error_description, "unexpected body type");
        }

        #[test]
        fn does_not_accept_oct_keys() {
            let client_registration_uri = "https://op.example.com/client/registration";

            let jwks = Some(convert_json_to::<Jwks>("{\"keys\":[{\"k\":\"qHedLw\",\"kty\":\"oct\",\"kid\":\"R5OsS5S7xvrW7E0k0t0PwRsskJpdOkyfnAZi8S806Bg\"}]}").unwrap());

            let client_error = Client::from_uri(
                &client_registration_uri,
                None,
                jwks.clone(),
                None,
                None,
                None,
            )
            .unwrap_err();

            let async_runtime = tokio::runtime::Runtime::new().unwrap();

            let _ = async_runtime.block_on(async {
                let client_error_async =
                    Client::from_uri_async(&client_registration_uri, None, jwks, None, None, None)
                        .await
                        .unwrap_err();

                assert_eq!(
                    "jwks must only contain private keys",
                    client_error_async.error_description
                );
            });

            assert_eq!(
                "jwks must only contain private keys",
                client_error.error_description
            );
        }

        #[test]
        fn does_not_accept_public_keys() {
            let client_registration_uri = "https://op.example.com/client/registration";

            let jwks = Some(convert_json_to::<Jwks>("{\"keys\":[{\"kty\":\"EC\",\"kid\":\"MFZeG102dQiqbANoaMlW_Jmf7fOZmtRsHt77JFhTpF0\",\"crv\":\"P-256\",\"x\":\"FWZ9rSkLt6Dx9E3pxLybhdM6xgR5obGsj5_pqmnz5J4\",\"y\":\"_n8G69C-A2Xl4xUW2lF0i8ZGZnk_KPYrhv4GbTGu5G4\"}]}").unwrap());
            let client_error = Client::from_uri(
                &client_registration_uri,
                None,
                jwks.clone(),
                None,
                None,
                None,
            )
            .unwrap_err();

            let async_runtime = tokio::runtime::Runtime::new().unwrap();

            let _ = async_runtime.block_on(async {
                let client_error_async =
                    Client::from_uri_async(&client_registration_uri, None, jwks, None, None, None)
                        .await
                        .unwrap_err();

                assert_eq!(
                    "jwks must only contain private keys",
                    client_error_async.error_description
                );
            });

            assert_eq!(
                "jwks must only contain private keys",
                client_error.error_description
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
                        .path("/client/identifier");
                    then.status(200)
                        .header("content-type", "application/json")
                        .body(get_default_expected_client_read_response());
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

                let client_registration_uri =
                    format!("https://{}/client/identifier", auth_server_domain);

                let _ = Client::from_uri(
                    &client_registration_uri,
                    None,
                    None,
                    None,
                    None,
                    Some(Box::new(interceptor)),
                )
                .unwrap();

                auth_mock_server.assert_hits(1);
            }

            #[test]
            fn allows_for_http_options_to_be_defined_for_issuer_discover_calls_async() {
                let mock_http_server = MockServer::start();

                let auth_server_domain = get_url_with_count("op.example<>.com");

                let auth_mock_server = mock_http_server.mock(|when, then| {
                    when.method(GET)
                        .header_exists("testHeader")
                        .path("/client/identifier");
                    then.status(200)
                        .header("content-type", "application/json")
                        .body(get_default_expected_client_read_response());
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

                let client_registration_uri =
                    format!("https://{}/client/identifier", auth_server_domain);

                let async_runtime = tokio::runtime::Runtime::new().unwrap();

                let _ = async_runtime.block_on(async {
                    let _ = Client::from_uri_async(
                        &client_registration_uri,
                        None,
                        None,
                        None,
                        None,
                        Some(Box::new(interceptor)),
                    )
                    .await
                    .unwrap();
                    auth_mock_server.assert_hits(1);
                });
            }
        }
    }

    #[cfg(test)]
    mod client_register {
        use httpmock::{prelude::HttpMockRequest, Method::POST, MockServer};

        use crate::{
            client::Client,
            issuer::Issuer,
            tests::{get_url_with_count, set_mock_domain},
            types::{ClientMetadata, IssuerMetadata},
        };

        pub fn get_default_expected_client_read_response() -> String {
            "{\"client_id\":\"identifier\",\"client_secret\":\"secure\"}".to_string()
        }

        #[test]
        fn asserts_the_issuer_has_a_registration_endpoint() {
            let issuer_metadata = IssuerMetadata::default();

            let issuer = Issuer::new(issuer_metadata, None);

            let client_error =
                Client::register(&issuer, ClientMetadata::default(), None, None).unwrap_err();

            let async_runtime = tokio::runtime::Runtime::new().unwrap();

            let _ = async_runtime.block_on(async {
                let client_error_async =
                    Client::register_async(&issuer, ClientMetadata::default(), None, None)
                        .await
                        .unwrap_err();

                assert_eq!(
                    "registration_endpoint must be configured on the issuer",
                    client_error_async.error_description
                );
            });

            assert_eq!(
                "registration_endpoint must be configured on the issuer",
                client_error.error_description
            );
        }

        #[test]
        fn accepts_and_assigns_the_registered_metadata() {
            let mock_http_server = MockServer::start();

            let auth_server_domain = get_url_with_count("op.example<>.com");

            let _auth_mock_server = mock_http_server.mock(|when, then| {
                when.method(POST)
                    .matches(|req: &HttpMockRequest| {
                        if let Some(headers) = &req.headers {
                            let mut iterator = headers.iter();
                            let accept_header = iterator.find(|(header, value)| {
                                header.to_lowercase() == "accept" && value == "application/json"
                            });

                            let content_length = iterator.find(|(header, value)| {
                                header.to_lowercase() == "content-length"
                                    && value.parse::<i64>().is_ok()
                            });
                            let transfer_encoding = iterator
                                .find(|(header, _)| header.to_lowercase() == "transfer-encoding");

                            return accept_header.is_some()
                                && content_length.is_some()
                                && transfer_encoding.is_none();
                        }
                        false
                    })
                    .path("/client/registration");
                then.status(201)
                    .body(get_default_expected_client_read_response());
            });

            set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

            let registration_endpoint =
                format!("https://{}/client/registration", auth_server_domain);

            let issuer_metadata = IssuerMetadata {
                registration_endpoint: Some(registration_endpoint),
                ..IssuerMetadata::default()
            };

            let issuer = Issuer::new(issuer_metadata, None);

            let client = Client::register(&issuer, ClientMetadata::default(), None, None).unwrap();

            let async_runtime = tokio::runtime::Runtime::new().unwrap();

            let _ = async_runtime.block_on(async {
                let client_async =
                    Client::register_async(&issuer, ClientMetadata::default(), None, None)
                        .await
                        .unwrap();

                assert_eq!("identifier", client_async.get_client_id());

                assert_eq!("secure", client_async.get_client_secret().unwrap());
            });

            assert_eq!("identifier", client.get_client_id());

            assert_eq!("secure", client.get_client_secret().unwrap());
        }

        #[test]
        fn is_rejected_with_op_error_upon_oidc_error() {
            let mock_http_server = MockServer::start();

            let auth_server_domain = get_url_with_count("op.example<>.com");

            let _auth_mock_server = mock_http_server.mock(|when, then| {
                when.method(POST).path("/client/registration");
                then.status(500).body(
                "{\"error\":\"server_error\",\"error_description\":\"bad things are happening\"}",
            );
            });

            set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

            let registration_endpoint =
                format!("https://{}/client/registration", auth_server_domain);

            let issuer_metadata = IssuerMetadata {
                registration_endpoint: Some(registration_endpoint),
                ..IssuerMetadata::default()
            };

            let issuer = Issuer::new(issuer_metadata, None);

            let client_error =
                Client::register(&issuer, ClientMetadata::default(), None, None).unwrap_err();

            let async_runtime = tokio::runtime::Runtime::new().unwrap();

            let _ = async_runtime.block_on(async {
                let client_error_async =
                    Client::register_async(&issuer, ClientMetadata::default(), None, None)
                        .await
                        .unwrap_err();

                assert_eq!("OPError", client_error_async.name);

                assert_eq!("server_error", client_error_async.error);

                assert_eq!(
                    "bad things are happening",
                    client_error_async.error_description
                );
            });

            assert_eq!("OPError", client_error.name);

            assert_eq!("server_error", client_error.error);

            assert_eq!("bad things are happening", client_error.error_description);
        }

        #[test]
        fn is_rejected_with_op_error_upon_oidc_error_in_www_authenticate_header() {
            let mock_http_server = MockServer::start();

            let auth_server_domain = get_url_with_count("op.example<>.com");

            let _auth_mock_server = mock_http_server.mock(|when, then| {
                when.method(POST).path("/client/registration");
                then.status(401)
                    .body("Unauthorized")
                    .header("WWW-Authenticate", "Bearer error=\"invalid_token\", error_description=\"bad things are happening\"");
            });

            set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

            let registration_endpoint =
                format!("https://{}/client/registration", auth_server_domain);

            let issuer_metadata = IssuerMetadata {
                registration_endpoint: Some(registration_endpoint),
                ..IssuerMetadata::default()
            };

            let issuer = Issuer::new(issuer_metadata, None);

            let client_error =
                Client::register(&issuer, ClientMetadata::default(), None, None).unwrap_err();

            let async_runtime = tokio::runtime::Runtime::new().unwrap();

            let _ = async_runtime.block_on(async {
                let client_error_async =
                    Client::register_async(&issuer, ClientMetadata::default(), None, None)
                        .await
                        .unwrap_err();

                assert_eq!("OPError", client_error_async.name);

                assert_eq!("invalid_token", client_error_async.error);

                assert_eq!(
                    "bad things are happening",
                    client_error_async.error_description
                );
            });

            assert_eq!("OPError", client_error.name);

            assert_eq!("invalid_token", client_error.error);

            assert_eq!("bad things are happening", client_error.error_description);
        }

        #[test]
        fn is_rejected_with_when_non_200_is_returned() {
            let mock_http_server = MockServer::start();

            let auth_server_domain = get_url_with_count("op.example<>.com");

            let _auth_mock_server = mock_http_server.mock(|when, then| {
                when.method(POST).path("/client/registration");
                then.status(500).body("Internal Server Error");
            });

            set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

            let registration_endpoint =
                format!("https://{}/client/registration", auth_server_domain);

            let issuer_metadata = IssuerMetadata {
                registration_endpoint: Some(registration_endpoint),
                ..IssuerMetadata::default()
            };

            let issuer = Issuer::new(issuer_metadata, None);

            let client_error =
                Client::register(&issuer, ClientMetadata::default(), None, None).unwrap_err();

            let async_runtime = tokio::runtime::Runtime::new().unwrap();

            let _ = async_runtime.block_on(async {
                let client_error_async =
                    Client::register_async(&issuer, ClientMetadata::default(), None, None)
                        .await
                        .unwrap_err();

                assert_eq!("OPError", client_error_async.name);

                assert!(client_error_async.response.is_some());

                assert_eq!(
                    "expected 201 Created, got: 500 Internal Server Error",
                    client_error_async.error_description
                );
            });

            assert_eq!("OPError", client_error.name);

            assert!(client_error.response.is_some());

            assert_eq!(
                "expected 201 Created, got: 500 Internal Server Error",
                client_error.error_description
            );
        }

        #[test]
        fn is_rejected_with_json_parse_error_upon_invalid_response() {
            let mock_http_server = MockServer::start();

            let auth_server_domain = get_url_with_count("op.example<>.com");

            let _auth_mock_server = mock_http_server.mock(|when, then| {
                when.method(POST).path("/client/registration");
                then.status(201).body("{\"notavalid\"}");
            });

            set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());
            let registration_endpoint =
                format!("https://{}/client/registration", auth_server_domain);

            let issuer_metadata = IssuerMetadata {
                registration_endpoint: Some(registration_endpoint),
                ..IssuerMetadata::default()
            };

            let issuer = Issuer::new(issuer_metadata, None);

            let client_error =
                Client::register(&issuer, ClientMetadata::default(), None, None).unwrap_err();

            let async_runtime = tokio::runtime::Runtime::new().unwrap();

            let _ = async_runtime.block_on(async {
                let client_error_async =
                    Client::register_async(&issuer, ClientMetadata::default(), None, None)
                        .await
                        .unwrap_err();

                assert_eq!(client_error_async.name, "TypeError");

                assert_eq!(client_error_async.error, "parse_error");

                assert_eq!(client_error_async.error_description, "unexpected body type");
            });

            assert_eq!(client_error.name, "TypeError");

            assert_eq!(client_error.error, "parse_error");

            assert_eq!(client_error.error_description, "unexpected body type");
        }

        #[cfg(test)]
        mod with_key_store_as_an_option {
            use httpmock::{prelude::HttpMockRequest, Method::POST, MockServer};

            use crate::{
                client::Client,
                helpers::convert_json_to,
                issuer::Issuer,
                jwks::Jwks,
                tests::{get_url_with_count, set_mock_domain},
                types::{ClientMetadata, ClientRegistrationOptions, IssuerMetadata},
            };

            fn get_default_jwks_string() -> String {
                "{\"keys\":[{\"kty\":\"EC\",\"d\":\"okqKR79UYsyRRIVT1cQU8vyJxa4HF14Ig9BaXioH1co\",\"use\":\"sig\",\"crv\":\"P-256\",\"kid\":\"E5e5oAXKlVe1Pp1uYlorEE2XEDzZ-5sTNDuS4RcU_VA\",\"x\":\"hBWMzCM4tmlWWK0ovPlg2oCnpcdWAcVvtr9M5bichiA\",\"y\":\"yP7NOAHMReiT1PG-Nxl4MbegpvwJnUGfLCI_llPQIg4\",\"alg\":\"ES256\"}]}".to_string()
            }

            pub fn get_default_expected_client_register_response() -> String {
                "{\"client_id\":\"identifier\",\"client_secret\":\"secure\"}".to_string()
            }

            #[test]
            fn enriches_the_registration_with_jwks_if_not_provided_or_jwks_uri() {
                let mock_http_server = MockServer::start();

                let auth_server_domain = get_url_with_count("op.example<>.com");

                let auth_mock_server = mock_http_server.mock(|when, then| {
                    when.matches(|req: &HttpMockRequest| {
                        if let Some(body) = req.body.clone() {
                            let body_string = String::from_utf8(body);
                            if let Ok(body_str) = body_string {
                                if let Ok(metadata) = convert_json_to::<ClientMetadata>(&body_str) {
                                    return metadata.jwks.unwrap()
                                        == convert_json_to::<Jwks>("{\"keys\":[{\"kty\":\"EC\",\"use\":\"sig\",\"crv\":\"P-256\",\"x\":\"hBWMzCM4tmlWWK0ovPlg2oCnpcdWAcVvtr9M5bichiA\",\"y\":\"yP7NOAHMReiT1PG-Nxl4MbegpvwJnUGfLCI_llPQIg4\"}]}")
                                            .unwrap();
                                }
                            }
                        }
                        false
                    })
                    .method(POST)
                    .path("/client/registration");
                    then.status(201)
                        .body(get_default_expected_client_register_response());
                });

                set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

                let registration_endpoint =
                    format!("https://{}/client/registration", auth_server_domain);

                let issuer_metadata = IssuerMetadata {
                    registration_endpoint: Some(registration_endpoint),
                    ..IssuerMetadata::default()
                };

                let issuer = Issuer::new(issuer_metadata, None);

                let register_options = ClientRegistrationOptions {
                    jwks: Some(convert_json_to::<Jwks>(&get_default_jwks_string()).unwrap()),
                    ..Default::default()
                };

                let _ = Client::register(
                    &issuer,
                    ClientMetadata::default(),
                    Some(register_options.clone()),
                    None,
                )
                .unwrap();

                let async_runtime = tokio::runtime::Runtime::new().unwrap();

                let _ = async_runtime.block_on(async {
                    let _ = Client::register_async(
                        &issuer,
                        ClientMetadata::default(),
                        Some(register_options.clone()),
                        None,
                    )
                    .await
                    .unwrap();
                    auth_mock_server.assert_hits(2);
                });
            }

            #[test]
            fn ignores_the_keystore_during_registration_if_jwks_is_provided() {
                let mock_http_server = MockServer::start();

                let auth_server_domain = get_url_with_count("op.example<>.com");

                let auth_mock_server = mock_http_server.mock(|when, then| {
                    when.matches(|req: &HttpMockRequest| {
                        if let Some(body) = req.body.clone() {
                            let body_string = String::from_utf8(body);
                            if let Ok(body_str) = body_string {
                                if let Ok(metadata) = convert_json_to::<ClientMetadata>(&body_str) {
                                    return metadata.jwks.unwrap() == Jwks::default();
                                }
                            }
                        }
                        false
                    })
                    .method(POST)
                    .path("/client/registration");
                    then.status(201)
                        .body(get_default_expected_client_register_response());
                });

                set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());
                let registration_endpoint =
                    format!("https://{}/client/registration", auth_server_domain);

                let issuer_metadata = IssuerMetadata {
                    registration_endpoint: Some(registration_endpoint),
                    ..IssuerMetadata::default()
                };

                let issuer = Issuer::new(issuer_metadata, None);

                let register_options = ClientRegistrationOptions {
                    jwks: Some(convert_json_to::<Jwks>(&get_default_jwks_string()).unwrap()),
                    ..Default::default()
                };

                let client_metadata = ClientMetadata {
                    jwks: Some(Jwks::default()),
                    ..Default::default()
                };

                let _ = Client::register(
                    &issuer,
                    client_metadata.clone(),
                    Some(register_options.clone()),
                    None,
                )
                .unwrap();

                let async_runtime = tokio::runtime::Runtime::new().unwrap();

                let _ = async_runtime.block_on(async {
                    let _ = Client::register_async(
                        &issuer,
                        client_metadata,
                        Some(register_options),
                        None,
                    )
                    .await
                    .unwrap();
                    auth_mock_server.assert_hits(2);
                });
            }

            #[test]
            fn ignores_the_keystore_during_registration_if_jwks_uri_is_provided() {
                let mock_http_server = MockServer::start();

                let auth_server_domain = get_url_with_count("op.example<>.com");

                let auth_mock_server = mock_http_server.mock(|when, then| {
                    when.matches(|req: &HttpMockRequest| {
                        if let Some(body) = req.body.clone() {
                            let body_string = String::from_utf8(body);
                            if let Ok(body_str) = body_string {
                                if let Ok(metadata) = convert_json_to::<ClientMetadata>(&body_str) {
                                    return metadata
                                        == ClientMetadata {
                                            jwks_uri: Some(
                                                "https://rp.example.com/certs".to_string(),
                                            ),
                                            ..Default::default()
                                        };
                                }
                            }
                        }
                        false
                    })
                    .method(POST)
                    .path("/client/registration");
                    then.status(201)
                        .body(get_default_expected_client_register_response());
                });

                set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());
                let registration_endpoint =
                    format!("https://{}/client/registration", auth_server_domain);

                let issuer_metadata = IssuerMetadata {
                    registration_endpoint: Some(registration_endpoint),
                    ..IssuerMetadata::default()
                };

                let issuer = Issuer::new(issuer_metadata, None);

                let register_options = ClientRegistrationOptions {
                    jwks: Some(convert_json_to::<Jwks>(&get_default_jwks_string()).unwrap()),
                    ..Default::default()
                };

                let client_metadata = ClientMetadata {
                    jwks_uri: Some("https://rp.example.com/certs".to_string()),
                    ..Default::default()
                };

                let _ = Client::register(
                    &issuer,
                    client_metadata.clone(),
                    Some(register_options.clone()),
                    None,
                )
                .unwrap();

                let async_runtime = tokio::runtime::Runtime::new().unwrap();

                let _ = async_runtime.block_on(async {
                    let _ = Client::register_async(
                        &issuer,
                        client_metadata,
                        Some(register_options),
                        None,
                    )
                    .await
                    .unwrap();
                    auth_mock_server.assert_hits(2);
                });
            }

            #[test]
            fn does_not_accept_oct_keys() {
                let registration_endpoint = "https://op.example.com/client/registration";

                let issuer_metadata = IssuerMetadata {
                    registration_endpoint: Some(registration_endpoint.to_string()),
                    ..IssuerMetadata::default()
                };

                let issuer = Issuer::new(issuer_metadata, None);

                let register_options = ClientRegistrationOptions {
                    jwks: Some(convert_json_to::<Jwks>("{\"keys\":[{\"k\":\"qHedLw\",\"kty\":\"oct\",\"kid\":\"R5OsS5S7xvrW7E0k0t0PwRsskJpdOkyfnAZi8S806Bg\"}]}").unwrap()),
                    ..Default::default()
                };

                let client_metadata = ClientMetadata::default();

                let client_error = Client::register(
                    &issuer,
                    client_metadata.clone(),
                    Some(register_options.clone()),
                    None,
                )
                .unwrap_err();

                let async_runtime = tokio::runtime::Runtime::new().unwrap();

                let _ = async_runtime.block_on(async {
                    let client_error_async = Client::register_async(
                        &issuer,
                        client_metadata,
                        Some(register_options),
                        None,
                    )
                    .await
                    .unwrap_err();

                    assert_eq!(
                        "jwks must only contain private keys",
                        client_error_async.error_description
                    );
                });

                assert_eq!(
                    "jwks must only contain private keys",
                    client_error.error_description
                );
            }

            #[test]
            fn does_not_accept_public_keys() {
                let registration_endpoint = "https://op.example.com/client/registration";

                let issuer_metadata = IssuerMetadata {
                    registration_endpoint: Some(registration_endpoint.to_string()),
                    ..IssuerMetadata::default()
                };

                let issuer = Issuer::new(issuer_metadata, None);

                let register_options = ClientRegistrationOptions {
                    jwks: Some(convert_json_to::<Jwks>("{\"keys\":[{\"kty\":\"EC\",\"kid\":\"MFZeG102dQiqbANoaMlW_Jmf7fOZmtRsHt77JFhTpF0\",\"crv\":\"P-256\",\"x\":\"FWZ9rSkLt6Dx9E3pxLybhdM6xgR5obGsj5_pqmnz5J4\",\"y\":\"_n8G69C-A2Xl4xUW2lF0i8ZGZnk_KPYrhv4GbTGu5G4\"}]}").unwrap()),
                    ..Default::default()
                };

                let client_metadata = ClientMetadata::default();

                let client_error = Client::register(
                    &issuer,
                    client_metadata.clone(),
                    Some(register_options.clone()),
                    None,
                )
                .unwrap_err();

                let async_runtime = tokio::runtime::Runtime::new().unwrap();

                let _ = async_runtime.block_on(async {
                    let client_error_async = Client::register_async(
                        &issuer,
                        client_metadata,
                        Some(register_options),
                        None,
                    )
                    .await
                    .unwrap_err();

                    assert_eq!(
                        "jwks must only contain private keys",
                        client_error_async.error_description
                    );
                });

                assert_eq!(
                    "jwks must only contain private keys",
                    client_error.error_description
                );
            }
        }

        #[cfg(test)]
        mod with_initial_access_token {
            use httpmock::{Method::POST, MockServer};

            use crate::{
                client::Client,
                issuer::Issuer,
                tests::{get_url_with_count, set_mock_domain},
                types::{ClientMetadata, ClientRegistrationOptions, IssuerMetadata},
            };

            pub fn get_default_expected_client_register_response() -> String {
                "{\"client_id\":\"identifier\",\"client_secret\":\"secure\"}".to_string()
            }

            #[test]
            fn uses_the_initial_access_token_in_a_bearer_authorization_scheme() {
                let mock_http_server = MockServer::start();

                let auth_server_domain = get_url_with_count("op.example<>.com");

                let auth_mock_server = mock_http_server.mock(|when, then| {
                    when.method(POST)
                        .path("/client/registration")
                        .header("authorization", "Bearer foobar");
                    then.status(201)
                        .body(get_default_expected_client_register_response());
                });

                set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());
                let registration_endpoint =
                    format!("https://{}/client/registration", auth_server_domain);

                let issuer_metadata = IssuerMetadata {
                    registration_endpoint: Some(registration_endpoint),
                    ..IssuerMetadata::default()
                };

                let issuer = Issuer::new(issuer_metadata, None);

                let register_options = ClientRegistrationOptions {
                    initial_access_token: Some("foobar".to_string()),
                    ..Default::default()
                };

                let _ = Client::register(
                    &issuer,
                    ClientMetadata::default(),
                    Some(register_options.clone()),
                    None,
                )
                .unwrap();

                let async_runtime = tokio::runtime::Runtime::new().unwrap();

                let _ = async_runtime.block_on(async {
                    let _ = Client::register_async(
                        &issuer,
                        ClientMetadata::default(),
                        Some(register_options),
                        None,
                    )
                    .await
                    .unwrap();

                    auth_mock_server.assert_hits(2);
                });
            }
        }

        #[cfg(test)]
        mod http_options {
            use std::time::Duration;

            use reqwest::header::{HeaderMap, HeaderValue};

            use crate::{
                tests::get_url_with_count,
                types::{ClientRegistrationOptions, RequestOptions},
            };

            use super::*;

            pub fn get_default_expected_client_register_response() -> String {
                "{\"client_id\":\"identifier\",\"client_secret\":\"secure\"}".to_string()
            }

            #[test]
            fn allows_for_http_options_to_be_defined_for_issuer_discover_calls() {
                let mock_http_server = MockServer::start();

                let auth_server_domain = get_url_with_count("op.example<>.com");

                let auth_mock_server = mock_http_server.mock(|when, then| {
                    when.method(POST)
                        .header("testHeader", "testHeaderValue")
                        .path("/client/registration");
                    then.status(201)
                        .body(get_default_expected_client_register_response());
                });

                set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

                let interceptor = |_request: &crate::types::Request| {
                    let mut headers = HeaderMap::new();
                    headers.append("testHeader", HeaderValue::from_static("testHeaderValue"));

                    RequestOptions {
                        headers,
                        timeout: Duration::from_millis(3500),
                    }
                };

                let registration_endpoint =
                    format!("https://{}/client/registration", auth_server_domain);

                let issuer_metadata = IssuerMetadata {
                    registration_endpoint: Some(registration_endpoint),
                    ..IssuerMetadata::default()
                };

                let issuer = Issuer::new(issuer_metadata, None);

                let register_options = ClientRegistrationOptions {
                    initial_access_token: Some("foobar".to_string()),
                    ..Default::default()
                };

                let _ = Client::register(
                    &issuer,
                    ClientMetadata::default(),
                    Some(register_options),
                    Some(Box::new(interceptor)),
                )
                .unwrap();

                auth_mock_server.assert_hits(1);
            }

            #[test]
            fn allows_for_http_options_to_be_defined_for_issuer_discover_calls_async() {
                let mock_http_server = MockServer::start();

                let auth_server_domain = get_url_with_count("op.example<>.com");

                let auth_mock_server = mock_http_server.mock(|when, then| {
                    when.method(POST)
                        .header("testHeader", "testHeaderValue")
                        .path("/client/registration");
                    then.status(201)
                        .body(get_default_expected_client_register_response());
                });

                set_mock_domain(&auth_server_domain.to_string(), mock_http_server.port());

                let interceptor = |_request: &crate::types::Request| {
                    let mut headers = HeaderMap::new();
                    headers.append("testHeader", HeaderValue::from_static("testHeaderValue"));

                    RequestOptions {
                        headers,
                        timeout: Duration::from_millis(3500),
                    }
                };

                let registration_endpoint =
                    format!("https://{}/client/registration", auth_server_domain);

                let issuer_metadata = IssuerMetadata {
                    registration_endpoint: Some(registration_endpoint),
                    ..IssuerMetadata::default()
                };

                let issuer = Issuer::new(issuer_metadata, None);

                let register_options = ClientRegistrationOptions {
                    initial_access_token: Some("foobar".to_string()),
                    ..Default::default()
                };

                let async_runtime = tokio::runtime::Runtime::new().unwrap();

                let _ = async_runtime.block_on(async {
                    let _ = Client::register_async(
                        &issuer,
                        ClientMetadata::default(),
                        Some(register_options),
                        Some(Box::new(interceptor)),
                    )
                    .await
                    .unwrap();
                    auth_mock_server.assert_hits(1);
                });
            }
        }
    }
}
