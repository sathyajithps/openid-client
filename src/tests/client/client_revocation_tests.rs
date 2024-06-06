use crate::{
    issuer::Issuer,
    types::{ClientMetadata, HttpMethod, IssuerMetadata},
};

use crate::tests::test_http_client::TestHttpReqRes;

#[tokio::test]
async fn posts_the_token_in_a_body_and_returns_none() {
    let http_client = TestHttpReqRes::new("https://op.example.com/token/revoke")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header("content-length", vec!["37".to_string()])
        .assert_request_header(
            "content-type",
            vec!["application/x-www-form-urlencoded".to_string()],
        )
        .assert_request_body("client_id=identifier&token=tokenValue")
        .set_response_content_type_header("application/json")
        .set_response_body(r#"{"endpoint":"response"}"#)
        .build();

    let issuer_metadata = IssuerMetadata {
        revocation_endpoint: Some("https://op.example.com/token/revoke".to_string()),
        ..Default::default()
    };
    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        token_endpoint_auth_method: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let res = client
        .revoke_async("tokenValue", None, None, &http_client)
        .await
        .unwrap();

    assert!(res.body.is_none());
}

#[tokio::test]
async fn posts_the_token_and_a_hint_in_a_body() {
    let http_client = TestHttpReqRes::new("https://op.example.com/token/revoke")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header("content-length", vec!["66".to_string()])
        .assert_request_header(
            "content-type",
            vec!["application/x-www-form-urlencoded".to_string()],
        )
        .assert_request_body("client_id=identifier&token=tokenValue&token_type_hint=access_token")
        .set_response_content_type_header("application/json")
        .set_response_body(r#"{"endpoint":"response"}"#)
        .build();

    let issuer_metadata = IssuerMetadata {
        revocation_endpoint: Some("https://op.example.com/token/revoke".to_string()),
        ..Default::default()
    };
    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        token_endpoint_auth_method: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let result = client
        .revoke_async("tokenValue", Some("access_token"), None, &http_client)
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn is_rejected_with_op_error_upon_oidc_error() {
    let http_client = TestHttpReqRes::new("https://op.example.com/token/revoke")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header("content-length", vec!["37".to_string()])
        .assert_request_header(
            "content-type",
            vec!["application/x-www-form-urlencoded".to_string()],
        )
        .assert_request_body("client_id=identifier&token=tokenValue")
        .set_response_content_type_header("application/json")
        .set_response_body(
            r#"{"error":"server_error","error_description":"bad things are happening"}"#,
        )
        .set_response_status_code(500)
        .build();

    let issuer_metadata = IssuerMetadata {
        revocation_endpoint: Some("https://op.example.com/token/revoke".to_string()),
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
        .revoke_async("tokenValue", None, None, &http_client)
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
    let http_client = TestHttpReqRes::new("https://op.example.com/token/revoke")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header("content-length", vec!["37".to_string()])
        .assert_request_header(
            "content-type",
            vec!["application/x-www-form-urlencoded".to_string()],
        )
        .assert_request_body("client_id=identifier&token=tokenValue")
        .set_response_content_type_header("application/json")
        .set_response_body("Internal Server Error")
        .set_response_status_code(500)
        .build();

    let issuer_metadata = IssuerMetadata {
        revocation_endpoint: Some("https://op.example.com/token/revoke".to_string()),
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
        .revoke_async("tokenValue", None, None, &http_client)
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
    let http_client = TestHttpReqRes::new("https://op.example.com/token/revoke")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header("content-length", vec!["37".to_string()])
        .assert_request_header(
            "content-type",
            vec!["application/x-www-form-urlencoded".to_string()],
        )
        .assert_request_body("client_id=identifier&token=tokenValue")
        .set_response_content_type_header("application/json")
        .set_response_body(r#"{"notvalid"}"#)
        .build();

    let issuer_metadata = IssuerMetadata {
        revocation_endpoint: Some("https://op.example.com/token/revoke".to_string()),
        ..Default::default()
    };
    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        token_endpoint_auth_method: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let result = client
        .revoke_async("tokenValue", None, None, &http_client)
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn handles_empty_bodies() {
    let http_client = TestHttpReqRes::new("https://op.example.com/token/revoke")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header("content-length", vec!["37".to_string()])
        .assert_request_header(
            "content-type",
            vec!["application/x-www-form-urlencoded".to_string()],
        )
        .assert_request_body("client_id=identifier&token=tokenValue")
        .set_response_content_type_header("application/json")
        .build();

    let issuer_metadata = IssuerMetadata {
        revocation_endpoint: Some("https://op.example.com/token/revoke".to_string()),
        ..Default::default()
    };
    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        token_endpoint_auth_method: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let result = client
        .revoke_async("tokenValue", None, None, &http_client)
        .await;

    assert!(result.is_ok());
}
