use crate::{
    issuer::Issuer,
    types::{ClientMetadata, HttpMethod, IssuerMetadata},
};

use crate::tests::test_http_client::TestHttpReqRes;

#[tokio::test]
async fn posts_the_token_in_a_body_and_returns_the_parsed_response() {
    let http_client = TestHttpReqRes::new("https://op.example.com/token/introspect")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header("content-length", vec!["37".to_string()])
        .assert_request_header(
            "content-type",
            vec!["application/x-www-form-urlencoded".to_string()],
        )
        .assert_request_body("token=tokenValue&client_id=identifier")
        .set_response_body(r#"{"endpoint":"response"}"#)
        .build();

    let issuer_metadata = IssuerMetadata {
        introspection_endpoint: Some("https://op.example.com/token/introspect".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        token_endpoint_auth_method: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let response = client
        .introspect_async(&http_client, "tokenValue".to_owned(), None, None)
        .await
        .unwrap();

    assert_eq!(r#"{"endpoint":"response"}"#, response.body.unwrap());
}

#[tokio::test]
async fn posts_the_token_and_a_hint_in_a_body() {
    let http_client = TestHttpReqRes::new("https://op.example.com/token/introspect")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header("content-length", vec!["66".to_string()])
        .assert_request_header(
            "content-type",
            vec!["application/x-www-form-urlencoded".to_string()],
        )
        .assert_request_body("token=tokenValue&client_id=identifier&token_type_hint=access_token")
        .set_response_body(r#"{"endpoint":"response"}"#)
        .build();

    let issuer_metadata = IssuerMetadata {
        introspection_endpoint: Some("https://op.example.com/token/introspect".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        token_endpoint_auth_method: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let _ = client
        .introspect_async(
            &http_client,
            "tokenValue".to_owned(),
            Some("access_token".to_owned()),
            None,
        )
        .await
        .unwrap();

    http_client.assert();
}

#[tokio::test]
async fn is_rejected_with_op_error_upon_oidc_error() {
    let http_client = TestHttpReqRes::new("https://op.example.com/token/introspect")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header("content-length", vec!["37".to_string()])
        .assert_request_header(
            "content-type",
            vec!["application/x-www-form-urlencoded".to_string()],
        )
        .assert_request_body("token=tokenValue&client_id=identifier")
        .set_response_body(
            r#"{"error":"server_error","error_description":"bad things are happening"}"#,
        )
        .set_response_status_code(500)
        .build();

    let issuer_metadata = IssuerMetadata {
        introspection_endpoint: Some("https://op.example.com/token/introspect".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        token_endpoint_auth_method: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let err = client
        .introspect_async(&http_client, "tokenValue".to_owned(), None, None)
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
    let http_client = TestHttpReqRes::new("https://op.example.com/token/introspect")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header("content-length", vec!["37".to_string()])
        .assert_request_header(
            "content-type",
            vec!["application/x-www-form-urlencoded".to_string()],
        )
        .assert_request_body("token=tokenValue&client_id=identifier")
        .set_response_body("Internal Server Error")
        .set_response_status_code(500)
        .build();

    let issuer_metadata = IssuerMetadata {
        introspection_endpoint: Some("https://op.example.com/token/introspect".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        token_endpoint_auth_method: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let err = client
        .introspect_async(&http_client, "tokenValue".to_owned(), None, None)
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
    let http_client = TestHttpReqRes::new("https://op.example.com/token/introspect")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header("content-length", vec!["37".to_string()])
        .assert_request_header(
            "content-type",
            vec!["application/x-www-form-urlencoded".to_string()],
        )
        .assert_request_body("token=tokenValue&client_id=identifier")
        .set_response_body(r#"{"notavalid"}"#)
        .build();

    let issuer_metadata = IssuerMetadata {
        introspection_endpoint: Some("https://op.example.com/token/introspect".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        token_endpoint_auth_method: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let err = client
        .introspect_async(&http_client, "tokenValue".to_owned(), None, None)
        .await
        .unwrap_err();

    assert!(err.is_type_error());

    let error = err.type_error().error;

    assert_eq!("unexpected body type", error.message);
}
