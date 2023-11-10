use httpmock::{Method::POST, MockServer};

use crate::{
    issuer::Issuer,
    tests::test_interceptors::get_default_test_interceptor,
    types::{ClientMetadata, IssuerMetadata},
};

#[tokio::test]
async fn posts_the_token_in_a_body_and_returns_the_parsed_response() {
    let mock_http_server = MockServer::start();

    let _introspection_server = mock_http_server.mock(|when, then| {
        when.method(POST)
            .header("Accept", "application/json")
            .matches(|req| {
                let decoded =
                    urlencoding::decode(std::str::from_utf8(&req.body.as_ref().unwrap()).unwrap())
                        .unwrap();

                let kvp = querystring::querify(&decoded);

                let token = kvp
                    .iter()
                    .find(|(k, v)| k == &"token" && v == &"tokenValue");
                let client_id = kvp
                    .iter()
                    .find(|(k, v)| k == &"client_id" && v == &"identifier");

                token.is_some() && client_id.is_some()
            })
            .path("/token/introspect");
        then.status(200).body(r#"{"endpoint":"response"}"#);
    });

    let issuer_metadata = IssuerMetadata {
        introspection_endpoint: Some("https://op.example.com/token/introspect".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(
        issuer_metadata,
        get_default_test_interceptor(Some(mock_http_server.port())),
    );

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        token_endpoint_auth_method: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let response = client
        .introspect_async("tokenValue", None, None)
        .await
        .unwrap();

    assert_eq!(r#"{"endpoint":"response"}"#, response.body.unwrap());
}

#[tokio::test]
async fn posts_the_token_and_a_hint_in_a_body() {
    let mock_http_server = MockServer::start();

    let introspection_server = mock_http_server.mock(|when, then| {
        when.method(POST)
            .header("Accept", "application/json")
            .matches(|req| {
                let decoded =
                    urlencoding::decode(std::str::from_utf8(&req.body.as_ref().unwrap()).unwrap())
                        .unwrap();

                let kvp = querystring::querify(&decoded);

                let token = kvp
                    .iter()
                    .find(|(k, v)| k == &"token" && v == &"tokenValue");

                let token_type_hint = kvp
                    .iter()
                    .find(|(k, v)| k == &"token_type_hint" && v == &"access_token");

                let client_id = kvp
                    .iter()
                    .find(|(k, v)| k == &"client_id" && v == &"identifier");

                token.is_some() && client_id.is_some() && token_type_hint.is_some()
            })
            .path("/token/introspect");
        then.status(200).body(r#"{"endpoint":"response"}"#);
    });

    let issuer_metadata = IssuerMetadata {
        introspection_endpoint: Some("https://op.example.com/token/introspect".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(
        issuer_metadata,
        get_default_test_interceptor(Some(mock_http_server.port())),
    );

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        token_endpoint_auth_method: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let _ = client
        .introspect_async("tokenValue", Some("access_token"), None)
        .await
        .unwrap();

    introspection_server.assert_async().await;
}

#[tokio::test]
async fn is_rejected_with_op_error_upon_oidc_error() {
    let mock_http_server = MockServer::start();

    let _introspection_server = mock_http_server.mock(|when, then| {
        when.method(POST)
            .header("Accept", "application/json")
            .path("/token/introspect");
        then.status(500)
            .body(r#"{"error":"server_error","error_description":"bad things are happening"}"#);
    });

    let issuer_metadata = IssuerMetadata {
        introspection_endpoint: Some("https://op.example.com/token/introspect".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(
        issuer_metadata,
        get_default_test_interceptor(Some(mock_http_server.port())),
    );

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        token_endpoint_auth_method: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let err = client
        .introspect_async("tokenValue", None, None)
        .await
        .unwrap_err();

    assert!(err.is_op_error());

    let op_error = err.op_error().error;

    assert_eq!("server_error", op_error.error);
    assert_eq!(
        "bad things are happening",
        op_error.error_description.unwrap()
    );
}

#[tokio::test]
async fn is_rejected_with_when_non_200_is_returned() {
    let mock_http_server = MockServer::start();

    let _introspection_server = mock_http_server.mock(|when, then| {
        when.method(POST)
            .header("Accept", "application/json")
            .path("/token/introspect");
        then.status(500).body("Internal Server Error");
    });

    let issuer_metadata = IssuerMetadata {
        introspection_endpoint: Some("https://op.example.com/token/introspect".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(
        issuer_metadata,
        get_default_test_interceptor(Some(mock_http_server.port())),
    );

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        token_endpoint_auth_method: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let err = client
        .introspect_async("tokenValue", None, None)
        .await
        .unwrap_err();

    assert!(err.is_op_error());

    let op_error = err.op_error();

    assert!(op_error.response.is_some());
    assert_eq!("server_error", op_error.error.error);
    assert_eq!(
        "expected 200 OK, got: 500 Internal Server Error",
        op_error.error.error_description.unwrap()
    );
}

#[tokio::test]
async fn is_rejected_with_error_upon_invalid_response() {
    let mock_http_server = MockServer::start();

    let _introspection_server = mock_http_server.mock(|when, then| {
        when.method(POST)
            .header("Accept", "application/json")
            .path("/token/introspect");
        then.status(200).body("{\"notavalid\"}");
    });

    let issuer_metadata = IssuerMetadata {
        introspection_endpoint: Some("https://op.example.com/token/introspect".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(
        issuer_metadata,
        get_default_test_interceptor(Some(mock_http_server.port())),
    );

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        token_endpoint_auth_method: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let err = client
        .introspect_async("tokenValue", None, None)
        .await
        .unwrap_err();

    assert!(err.is_type_error());

    let error = err.type_error().error;

    assert_eq!("unexpected body type", error.message);
}
