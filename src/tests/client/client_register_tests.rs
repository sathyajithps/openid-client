use httpmock::{prelude::HttpMockRequest, Method::POST, MockServer};

use crate::{
    client::Client,
    issuer::Issuer,
    tests::test_interceptors::get_default_test_interceptor,
    types::{ClientMetadata, IssuerMetadata},
};

pub fn get_default_expected_client_read_response() -> String {
    "{\"client_id\":\"identifier\",\"client_secret\":\"secure\"}".to_string()
}

#[tokio::test]
async fn asserts_the_issuer_has_a_registration_endpoint() {
    let issuer_metadata = IssuerMetadata::default();

    let issuer = Issuer::new(issuer_metadata, None);

    let client_error = Client::register_async(&issuer, ClientMetadata::default(), None, None)
        .await
        .unwrap_err();

    assert_eq!(
        "registration_endpoint must be configured on the issuer",
        client_error.type_error().error.message
    );
}

#[tokio::test]
async fn accepts_and_assigns_the_registered_metadata() {
    let mock_http_server = MockServer::start();

    let _auth_mock_server = mock_http_server.mock(|when, then| {
        when.method(POST)
            .matches(|req: &HttpMockRequest| {
                if let Some(headers) = &req.headers {
                    let mut iterator = headers.iter();
                    let accept_header = iterator.find(|(header, value)| {
                        header.to_lowercase() == "accept" && value == "application/json"
                    });

                    let content_length = iterator.find(|(header, value)| {
                        header.to_lowercase() == "content-length" && value.parse::<i64>().is_ok()
                    });
                    let transfer_encoding =
                        iterator.find(|(header, _)| header.to_lowercase() == "transfer-encoding");

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

    let registration_endpoint = "https://op.example.com/client/registration".to_string();

    let issuer_metadata = IssuerMetadata {
        registration_endpoint: Some(registration_endpoint),
        ..IssuerMetadata::default()
    };

    let issuer = Issuer::new(
        issuer_metadata,
        get_default_test_interceptor(Some(mock_http_server.port())),
    );

    let client = Client::register_async(
        &issuer,
        ClientMetadata::default(),
        None,
        get_default_test_interceptor(Some(mock_http_server.port())),
    )
    .await
    .unwrap();

    assert_eq!("identifier", client.get_client_id());

    assert_eq!("secure", client.get_client_secret().unwrap());
}

#[tokio::test]
async fn is_rejected_with_op_error_upon_oidc_error() {
    let mock_http_server = MockServer::start();

    let _auth_mock_server = mock_http_server.mock(|when, then| {
        when.method(POST).path("/client/registration");
        then.status(500).body(
            "{\"error\":\"server_error\",\"error_description\":\"bad things are happening\"}",
        );
    });

    let registration_endpoint = "https://op.example.com/client/registration".to_string();

    let issuer_metadata = IssuerMetadata {
        registration_endpoint: Some(registration_endpoint),
        ..IssuerMetadata::default()
    };

    let issuer = Issuer::new(
        issuer_metadata,
        get_default_test_interceptor(Some(mock_http_server.port())),
    );

    let client_error = Client::register_async(
        &issuer,
        ClientMetadata::default(),
        None,
        get_default_test_interceptor(Some(mock_http_server.port())),
    )
    .await
    .unwrap_err();

    assert!(client_error.is_op_error());

    let err = client_error.op_error().error;

    assert_eq!("server_error", err.error);

    assert_eq!(
        Some("bad things are happening".to_string()),
        err.error_description
    );
}

#[tokio::test]
async fn is_rejected_with_op_error_upon_oidc_error_in_www_authenticate_header() {
    let mock_http_server = MockServer::start();

    let _auth_mock_server = mock_http_server.mock(|when, then| {
        when.method(POST).path("/client/registration");
        then.status(401).body("Unauthorized").header(
            "WWW-Authenticate",
            "Bearer error=\"invalid_token\", error_description=\"bad things are happening\"",
        );
    });

    let registration_endpoint = "https://op.example.com/client/registration".to_string();

    let issuer_metadata = IssuerMetadata {
        registration_endpoint: Some(registration_endpoint),
        ..IssuerMetadata::default()
    };

    let issuer = Issuer::new(
        issuer_metadata,
        get_default_test_interceptor(Some(mock_http_server.port())),
    );

    let client_error = Client::register_async(
        &issuer,
        ClientMetadata::default(),
        None,
        get_default_test_interceptor(Some(mock_http_server.port())),
    )
    .await
    .unwrap_err();

    assert!(client_error.is_op_error());

    let err = client_error.op_error().error;

    assert_eq!("invalid_token", err.error);

    assert_eq!(
        Some("bad things are happening".to_string()),
        err.error_description
    );
}

#[tokio::test]
async fn is_rejected_with_when_non_200_is_returned() {
    let mock_http_server = MockServer::start();

    let _auth_mock_server = mock_http_server.mock(|when, then| {
        when.method(POST).path("/client/registration");
        then.status(500).body("Internal Server Error");
    });

    let registration_endpoint = "https://op.example.com/client/registration".to_string();

    let issuer_metadata = IssuerMetadata {
        registration_endpoint: Some(registration_endpoint),
        ..IssuerMetadata::default()
    };

    let issuer = Issuer::new(
        issuer_metadata,
        get_default_test_interceptor(Some(mock_http_server.port())),
    );

    let client_error = Client::register_async(
        &issuer,
        ClientMetadata::default(),
        None,
        get_default_test_interceptor(Some(mock_http_server.port())),
    )
    .await
    .unwrap_err();

    assert!(client_error.is_op_error());

    let err = client_error.op_error();

    assert!(err.response.is_some());

    assert_eq!(
        Some("expected 201 Created, got: 500 Internal Server Error".to_string()),
        err.error.error_description
    );
}

#[tokio::test]
async fn is_rejected_with_json_parse_error_upon_invalid_response() {
    let mock_http_server = MockServer::start();

    let _auth_mock_server = mock_http_server.mock(|when, then| {
        when.method(POST).path("/client/registration");
        then.status(201).body("{\"notavalid\"}");
    });

    let registration_endpoint = "https://op.example.com/client/registration".to_string();

    let issuer_metadata = IssuerMetadata {
        registration_endpoint: Some(registration_endpoint),
        ..IssuerMetadata::default()
    };

    let issuer = Issuer::new(
        issuer_metadata,
        get_default_test_interceptor(Some(mock_http_server.port())),
    );

    let client_error = Client::register_async(
        &issuer,
        ClientMetadata::default(),
        None,
        get_default_test_interceptor(Some(mock_http_server.port())),
    )
    .await
    .unwrap_err();

    assert!(client_error.is_type_error());

    let err = client_error.type_error().error;

    assert_eq!("unexpected body type", err.message);
}

#[cfg(test)]
mod with_key_store_as_an_option {
    use httpmock::{prelude::HttpMockRequest, Method::POST, MockServer};

    use crate::{
        client::Client,
        helpers::convert_json_to,
        issuer::Issuer,
        jwks::Jwks,
        tests::test_interceptors::get_default_test_interceptor,
        types::{ClientMetadata, ClientRegistrationOptions, IssuerMetadata},
    };

    fn get_default_jwks_string() -> String {
        "{\"keys\":[{\"kty\":\"EC\",\"d\":\"okqKR79UYsyRRIVT1cQU8vyJxa4HF14Ig9BaXioH1co\",\"use\":\"sig\",\"crv\":\"P-256\",\"kid\":\"E5e5oAXKlVe1Pp1uYlorEE2XEDzZ-5sTNDuS4RcU_VA\",\"x\":\"hBWMzCM4tmlWWK0ovPlg2oCnpcdWAcVvtr9M5bichiA\",\"y\":\"yP7NOAHMReiT1PG-Nxl4MbegpvwJnUGfLCI_llPQIg4\",\"alg\":\"ES256\"}]}".to_string()
    }

    pub fn get_default_expected_client_register_response() -> String {
        "{\"client_id\":\"identifier\",\"client_secret\":\"secure\"}".to_string()
    }

    #[tokio::test]
    async fn enriches_the_registration_with_jwks_if_not_provided_or_jwks_uri() {
        let mock_http_server = MockServer::start();

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

        let registration_endpoint = "https://op.example.com/client/registration".to_string();

        let issuer_metadata = IssuerMetadata {
            registration_endpoint: Some(registration_endpoint),
            ..IssuerMetadata::default()
        };

        let issuer = Issuer::new(
            issuer_metadata,
            get_default_test_interceptor(Some(mock_http_server.port())),
        );

        let register_options = ClientRegistrationOptions {
            jwks: Some(convert_json_to::<Jwks>(&get_default_jwks_string()).unwrap()),
            ..Default::default()
        };

        let _ = Client::register_async(
            &issuer,
            ClientMetadata::default(),
            Some(register_options.clone()),
            get_default_test_interceptor(Some(mock_http_server.port())),
        )
        .await
        .unwrap();

        auth_mock_server.assert_hits(1);
    }

    #[tokio::test]
    async fn ignores_the_keystore_during_registration_if_jwks_is_provided() {
        let mock_http_server = MockServer::start();

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

        let registration_endpoint = "https://op.example.com/client/registration".to_string();

        let issuer_metadata = IssuerMetadata {
            registration_endpoint: Some(registration_endpoint),
            ..IssuerMetadata::default()
        };

        let issuer = Issuer::new(
            issuer_metadata,
            get_default_test_interceptor(Some(mock_http_server.port())),
        );

        let register_options = ClientRegistrationOptions {
            jwks: Some(convert_json_to::<Jwks>(&get_default_jwks_string()).unwrap()),
            ..Default::default()
        };

        let client_metadata = ClientMetadata {
            jwks: Some(Jwks::default()),
            ..Default::default()
        };

        let _ = Client::register_async(
            &issuer,
            client_metadata.clone(),
            Some(register_options.clone()),
            get_default_test_interceptor(Some(mock_http_server.port())),
        )
        .await
        .unwrap();

        auth_mock_server.assert_hits(1);
    }

    #[tokio::test]
    async fn ignores_the_keystore_during_registration_if_jwks_uri_is_provided() {
        let mock_http_server = MockServer::start();

        let auth_mock_server = mock_http_server.mock(|when, then| {
            when.matches(|req: &HttpMockRequest| {
                if let Some(body) = req.body.clone() {
                    let body_string = String::from_utf8(body);
                    if let Ok(body_str) = body_string {
                        if let Ok(metadata) = convert_json_to::<ClientMetadata>(&body_str) {
                            return metadata
                                == ClientMetadata {
                                    jwks_uri: Some("https://rp.example.com/certs".to_string()),
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

        let registration_endpoint = "https://op.example.com/client/registration".to_string();

        let issuer_metadata = IssuerMetadata {
            registration_endpoint: Some(registration_endpoint),
            ..IssuerMetadata::default()
        };

        let issuer = Issuer::new(
            issuer_metadata,
            get_default_test_interceptor(Some(mock_http_server.port())),
        );

        let register_options = ClientRegistrationOptions {
            jwks: Some(convert_json_to::<Jwks>(&get_default_jwks_string()).unwrap()),
            ..Default::default()
        };

        let client_metadata = ClientMetadata {
            jwks_uri: Some("https://rp.example.com/certs".to_string()),
            ..Default::default()
        };

        let _ = Client::register_async(
            &issuer,
            client_metadata.clone(),
            Some(register_options.clone()),
            get_default_test_interceptor(Some(mock_http_server.port())),
        )
        .await
        .unwrap();

        auth_mock_server.assert_hits(1);
    }

    #[tokio::test]
    async fn does_not_accept_oct_keys() {
        let registration_endpoint = "https://op.example.com/client/registration".to_string();

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

        let client_error = Client::register_async(
            &issuer,
            client_metadata.clone(),
            Some(register_options.clone()),
            None,
        )
        .await
        .unwrap_err();

        assert_eq!(
            "jwks must only contain private keys",
            client_error.error().error.message
        );
    }

    #[tokio::test]
    async fn does_not_accept_public_keys() {
        let registration_endpoint = "https://op.example.com/client/registration".to_string();

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

        let client_error = Client::register_async(
            &issuer,
            client_metadata.clone(),
            Some(register_options.clone()),
            None,
        )
        .await
        .unwrap_err();

        assert_eq!(
            "jwks must only contain private keys",
            client_error.error().error.message
        );
    }
}

#[cfg(test)]
mod with_initial_access_token {
    use httpmock::{Method::POST, MockServer};

    use crate::{
        client::Client,
        issuer::Issuer,
        tests::test_interceptors::get_default_test_interceptor,
        types::{ClientMetadata, ClientRegistrationOptions, IssuerMetadata},
    };

    pub fn get_default_expected_client_register_response() -> String {
        "{\"client_id\":\"identifier\",\"client_secret\":\"secure\"}".to_string()
    }

    #[tokio::test]
    async fn uses_the_initial_access_token_in_a_bearer_authorization_scheme() {
        let mock_http_server = MockServer::start();

        let auth_mock_server = mock_http_server.mock(|when, then| {
            when.method(POST)
                .path("/client/registration")
                .header("authorization", "Bearer foobar");
            then.status(201)
                .body(get_default_expected_client_register_response());
        });

        let registration_endpoint = "https://op.example.com/client/registration".to_string();

        let issuer_metadata = IssuerMetadata {
            registration_endpoint: Some(registration_endpoint),
            ..IssuerMetadata::default()
        };

        let issuer = Issuer::new(
            issuer_metadata,
            get_default_test_interceptor(Some(mock_http_server.port())),
        );

        let register_options = ClientRegistrationOptions {
            initial_access_token: Some("foobar".to_string()),
            ..Default::default()
        };

        let _ = Client::register_async(
            &issuer,
            ClientMetadata::default(),
            Some(register_options.clone()),
            get_default_test_interceptor(Some(mock_http_server.port())),
        )
        .await
        .unwrap();

        auth_mock_server.assert_hits(1);
    }
}

#[cfg(test)]
mod http_options {

    use crate::{tests::test_interceptors::TestInterceptor, types::ClientRegistrationOptions};

    use super::*;

    pub fn get_default_expected_client_register_response() -> String {
        "{\"client_id\":\"identifier\",\"client_secret\":\"secure\"}".to_string()
    }

    #[tokio::test]
    async fn allows_for_http_options_to_be_defined_for_issuer_discover_calls() {
        let mock_http_server = MockServer::start();

        let auth_mock_server = mock_http_server.mock(|when, then| {
            when.method(POST)
                .header("testHeader", "testHeaderValue")
                .path("/client/registration");
            then.status(201)
                .body(get_default_expected_client_register_response());
        });

        let registration_endpoint = "https://op.example.com/client/registration".to_string();

        let issuer_metadata = IssuerMetadata {
            registration_endpoint: Some(registration_endpoint),
            ..IssuerMetadata::default()
        };

        let issuer = Issuer::new(
            issuer_metadata,
            get_default_test_interceptor(Some(mock_http_server.port())),
        );

        let register_options = ClientRegistrationOptions {
            initial_access_token: Some("foobar".to_string()),
            ..Default::default()
        };

        let _ = Client::register_async(
            &issuer,
            ClientMetadata::default(),
            Some(register_options),
            Some(Box::new(TestInterceptor {
                test_header: Some("testHeader".to_string()),
                test_header_value: Some("testHeaderValue".to_string()),
                test_server_port: Some(mock_http_server.port()),
            })),
        )
        .await
        .unwrap();

        auth_mock_server.assert_hits(1);
    }
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
