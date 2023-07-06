use httpmock::{Method::GET, MockServer};

use crate::{
    client::Client, helpers::convert_json_to, jwks::Jwks,
    tests::test_interceptors::get_default_test_interceptor, types::OidcClientError,
};

pub fn get_default_expected_client_read_response() -> String {
    "{\"client_id\":\"identifier\",\"client_secret\":\"secure\"}".to_string()
}

pub fn get_async_client_discovery(
    client_registration_uri: &str,
    port: u16,
) -> Result<Client, OidcClientError> {
    let async_runtime = tokio::runtime::Runtime::new().unwrap();

    let result: Result<Client, OidcClientError> = async_runtime.block_on(async {
        Client::from_uri_async(
            client_registration_uri,
            None,
            None,
            None,
            None,
            get_default_test_interceptor(port),
        )
        .await
    });
    result
}

#[test]
fn accepts_and_assigns_discovered_metadata() {
    let mock_http_server = MockServer::start();

    let _auth_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET).path("/client/identifier");
        then.status(200)
            .header("content-type", "application/json")
            .body(get_default_expected_client_read_response());
    });

    let client_registration_uri = "https://op.example.com/client/identifier";

    let client = Client::from_uri(
        &client_registration_uri,
        None,
        None,
        None,
        None,
        get_default_test_interceptor(mock_http_server.port()),
    )
    .unwrap();

    let client_async =
        get_async_client_discovery(&client_registration_uri, mock_http_server.port()).unwrap();

    assert_eq!("identifier", client.get_client_id());
    assert_eq!("identifier", client_async.get_client_id());

    assert_eq!("secure", client.get_client_secret().unwrap());
    assert_eq!("secure", client_async.get_client_secret().unwrap());
}

#[test]
fn is_rejected_with_op_error_upon_oidc_error() {
    let mock_http_server = MockServer::start();

    let _auth_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET).path("/client/identifier");
        then.status(500).body(
            "{\"error\":\"server_error\",\"error_description\":\"bad things are happening\"}",
        );
    });

    let client_registration_uri = "https://op.example.com/client/identifier";

    let client_error = Client::from_uri(
        &client_registration_uri,
        None,
        None,
        None,
        None,
        get_default_test_interceptor(mock_http_server.port()),
    )
    .unwrap_err();

    let client_error_async =
        get_async_client_discovery(&client_registration_uri, mock_http_server.port()).unwrap_err();

    assert!(client_error.is_op_error());
    assert!(client_error_async.is_op_error());

    let err = client_error.op_error().error;
    let err_async = client_error_async.op_error().error;

    assert_eq!("server_error", err.error);
    assert_eq!("server_error", err_async.error);

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
fn is_rejected_with_op_error_upon_oidc_error_in_www_authenticate_header() {
    let mock_http_server = MockServer::start();

    let _auth_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET).path("/client/identifier");
        then.status(401).body("Unauthorized").header(
            "WWW-Authenticate",
            "Bearer error=\"invalid_token\", error_description=\"bad things are happening\"",
        );
    });

    let client_registration_uri = "https://op.example.com/client/identifier";

    let client_error = Client::from_uri(
        &client_registration_uri,
        None,
        None,
        None,
        None,
        get_default_test_interceptor(mock_http_server.port()),
    )
    .unwrap_err();

    let client_error_async =
        get_async_client_discovery(&client_registration_uri, mock_http_server.port()).unwrap_err();

    assert!(client_error.is_op_error());
    assert!(client_error_async.is_op_error());

    let err = client_error.op_error().error;
    let err_async = client_error_async.op_error().error;

    assert_eq!("invalid_token", err.error);
    assert_eq!("invalid_token", err_async.error);

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
fn is_rejected_with_when_non_200_is_returned() {
    let mock_http_server = MockServer::start();

    let _auth_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET).path("/client/identifier");
        then.status(500).body("Internal Server Error");
    });

    let client_registration_uri = "https://op.example.com/client/identifier";

    let client_error = Client::from_uri(
        &client_registration_uri,
        None,
        None,
        None,
        None,
        get_default_test_interceptor(mock_http_server.port()),
    )
    .unwrap_err();

    let client_error_async =
        get_async_client_discovery(&client_registration_uri, mock_http_server.port()).unwrap_err();

    assert!(client_error.is_op_error());
    assert!(client_error_async.is_op_error());

    let err = client_error.op_error();
    let err_async = client_error_async.op_error();

    assert!(err.response.is_some());
    assert!(err_async.response.is_some());

    assert_eq!(
        Some("expected 200 OK, got: 500 Internal Server Error".to_string()),
        err.error.error_description
    );
    assert_eq!(
        Some("expected 200 OK, got: 500 Internal Server Error".to_string()),
        err_async.error.error_description
    );
}

#[test]
fn is_rejected_with_json_parse_error_upon_invalid_response() {
    let mock_http_server = MockServer::start();

    let _auth_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET).path("/client/identifier");
        then.status(200).body("{\"notavalid\"}");
    });

    let client_registration_uri = "https://op.example.com/client/identifier";

    let client_error = Client::from_uri(
        &client_registration_uri,
        None,
        None,
        None,
        None,
        get_default_test_interceptor(mock_http_server.port()),
    )
    .unwrap_err();

    let client_error_async =
        get_async_client_discovery(&client_registration_uri, mock_http_server.port()).unwrap_err();

    assert!(client_error.is_type_error());
    assert!(client_error_async.is_type_error());

    let err = client_error.type_error().error;
    let err_async = client_error_async.type_error().error;

    assert_eq!("unexpected body type", err.message);
    assert_eq!("unexpected body type", err_async.message);
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
            client_error_async.error().error.message
        );
    });

    assert_eq!(
        "jwks must only contain private keys",
        client_error.error().error.message
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
            client_error_async.error().error.message
        );
    });

    assert_eq!(
        "jwks must only contain private keys",
        client_error.error().error.message
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
                .path("/client/identifier");
            then.status(200)
                .header("content-type", "application/json")
                .body(get_default_expected_client_read_response());
        });

        let client_registration_uri = "https://op.example.com/client/identifier";

        let _ = Client::from_uri(
            &client_registration_uri,
            None,
            None,
            None,
            None,
            Some(Box::new(TestInterceptor {
                test_header: Some("testHeader".to_string()),
                test_header_value: Some("testHeaderValue".to_string()),
                test_server_port: Some(mock_http_server.port()),
            })),
        )
        .unwrap();

        auth_mock_server.assert_hits(1);
    }

    #[test]
    fn allows_for_http_options_to_be_defined_for_issuer_discover_calls_async() {
        let mock_http_server = MockServer::start();

        let auth_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .header("testHeader", "testHeaderValue")
                .path("/client/identifier");
            then.status(200)
                .header("content-type", "application/json")
                .body(get_default_expected_client_read_response());
        });

        let client_registration_uri = "https://op.example.com/client/identifier";

        let async_runtime = tokio::runtime::Runtime::new().unwrap();

        let _ = async_runtime.block_on(async {
            let _ = Client::from_uri_async(
                &client_registration_uri,
                None,
                None,
                None,
                None,
                Some(Box::new(TestInterceptor {
                    test_header: Some("testHeader".to_string()),
                    test_header_value: Some("testHeaderValue".to_string()),
                    test_server_port: Some(mock_http_server.port()),
                })),
            )
            .await
            .unwrap();
            auth_mock_server.assert_hits(1);
        });
    }
}
