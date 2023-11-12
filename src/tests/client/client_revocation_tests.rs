use httpmock::{Method::POST, MockServer};

use crate::{
    issuer::Issuer,
    tests::test_interceptors::get_default_test_interceptor,
    types::{ClientMetadata, IssuerMetadata},
};

#[tokio::test]
async fn posts_the_token_in_a_body_and_returns_none() {
    let mock_http_server = MockServer::start();

    let _revocation_server = mock_http_server.mock(|when, then| {
        when.method(POST)
            .matches(|req| {
                let decoded =
                    urlencoding::decode(std::str::from_utf8(&req.body.as_ref().unwrap()).unwrap())
                        .unwrap();

                let kvp = querystring::querify(&decoded);

                let client_id = kvp
                    .iter()
                    .find(|(k, v)| k == &"client_id" && v == &"identifier");
                let token = kvp
                    .iter()
                    .find(|(k, v)| k == &"token" && v == &"tokenValue");

                client_id.is_some() && token.is_some()
            })
            .path("/token/revoke");
        then.status(200).body(r#"{"endpoint":"response"}"#);
    });

    let issuer_metadata = IssuerMetadata {
        revocation_endpoint: Some("https://op.example.com/token/revoke".to_string()),
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
        .client(client_metadata, None, None, None, None)
        .unwrap();

    let res = client.revoke_async("tokenValue", None, None).await.unwrap();

    assert!(res.body.is_none());
}

#[tokio::test]
async fn posts_the_token_and_a_hint_in_a_body() {
    let mock_http_server = MockServer::start();

    let _revocation_server = mock_http_server.mock(|when, then| {
        when.method(POST)
            .matches(|req| {
                let decoded =
                    urlencoding::decode(std::str::from_utf8(&req.body.as_ref().unwrap()).unwrap())
                        .unwrap();

                let kvp = querystring::querify(&decoded);

                let client_id = kvp
                    .iter()
                    .find(|(k, v)| k == &"client_id" && v == &"identifier");
                let token = kvp
                    .iter()
                    .find(|(k, v)| k == &"token" && v == &"tokenValue");
                let token_type_hint = kvp
                    .iter()
                    .find(|(k, v)| k == &"token_type_hint" && v == &"access_token");

                client_id.is_some() && token.is_some() && token_type_hint.is_some()
            })
            .path("/token/revoke");
        then.status(200).body(r#"{"endpoint":"response"}"#);
    });

    let issuer_metadata = IssuerMetadata {
        revocation_endpoint: Some("https://op.example.com/token/revoke".to_string()),
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
        .client(client_metadata, None, None, None, None)
        .unwrap();

    let result = client
        .revoke_async("tokenValue", Some("access_token"), None)
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn is_rejected_with_op_error_upon_oidc_error() {
    let mock_http_server = MockServer::start();

    let _revocation_server = mock_http_server.mock(|when, then| {
        when.method(POST).path("/token/revoke");
        then.status(500)
            .body(r#"{"error":"server_error","error_description":"bad things are happening"}"#);
    });

    let issuer_metadata = IssuerMetadata {
        revocation_endpoint: Some("https://op.example.com/token/revoke".to_string()),
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
        .client(client_metadata, None, None, None, None)
        .unwrap();

    let err = client
        .revoke_async("tokenValue", None, None)
        .await
        .unwrap_err();

    assert!(err.is_op_error());

    let op_error = err.op_error();

    assert_eq!("server_error", op_error.error.error);
    assert_eq!(
        "bad things are happening",
        op_error.error.error_description.unwrap()
    );
}

#[tokio::test]
async fn is_rejected_with_when_non_200_is_returned() {
    let mock_http_server = MockServer::start();

    let _revocation_server = mock_http_server.mock(|when, then| {
        when.method(POST).path("/token/revoke");
        then.status(500).body("Internal Server Error");
    });

    let issuer_metadata = IssuerMetadata {
        revocation_endpoint: Some("https://op.example.com/token/revoke".to_string()),
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
        .client(client_metadata, None, None, None, None)
        .unwrap();

    let err = client
        .revoke_async("tokenValue", None, None)
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
async fn completely_ignores_the_response_even_invalid_or_html_one() {
    let mock_http_server = MockServer::start();

    let _revocation_server = mock_http_server.mock(|when, then| {
        when.method(POST).path("/token/revoke");
        then.status(200).body("{\"notvalid\"}");
    });

    let issuer_metadata = IssuerMetadata {
        revocation_endpoint: Some("https://op.example.com/token/revoke".to_string()),
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
        .client(client_metadata, None, None, None, None)
        .unwrap();

    let result = client.revoke_async("tokenValue", None, None).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn handles_empty_bodies() {
    let mock_http_server = MockServer::start();

    let _revocation_server = mock_http_server.mock(|when, then| {
        when.method(POST).path("/token/revoke");
        then.status(200);
    });

    let issuer_metadata = IssuerMetadata {
        revocation_endpoint: Some("https://op.example.com/token/revoke".to_string()),
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
        .client(client_metadata, None, None, None, None)
        .unwrap();

    let result = client.revoke_async("tokenValue", None, None).await;

    assert!(result.is_ok());
}
