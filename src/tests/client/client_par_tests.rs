use assert_json_diff::assert_json_include;
use serde_json::json;

use crate::{
    client::Client,
    http_client::DefaultHttpClient,
    issuer::Issuer,
    types::{AuthorizationParameters, ClientMetadata, HttpMethod, IssuerMetadata},
};

use crate::tests::test_http_client::TestHttpReqRes;

fn get_test_data() -> (Issuer, Client) {
    let issuer_metadata = IssuerMetadata {
        issuer: "https://op.example.com".to_string(),
        pushed_authorization_request_endpoint: Some("https://op.example.com/par".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        client_secret: Some("secure".to_string()),
        response_type: Some("code".to_string()),
        grant_types: Some(vec!["authrorization_code".to_string()]),
        redirect_uri: Some("https://rp.example.com/cb".to_string()),
        ..Default::default()
    };

    let client = issuer.client(client_metadata, None, None, None).unwrap();

    (issuer, client)
}

#[tokio::test]
async fn requires_the_issuer_to_have_pushed_authorization_request_endpoint_declared() {
    let issuer_metadata = IssuerMetadata {
        issuer: "https://op.example.com".to_string(),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        ..Default::default()
    };

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let err = client
        .pushed_authorization_request_async(None, None, &DefaultHttpClient)
        .await
        .unwrap_err();

    assert!(err.is_type_error());

    assert_eq!(
        "pushed_authorization_request_endpoint must be configured on the issuer",
        err.type_error().error.message
    );
}

#[tokio::test]
async fn performs_an_authenticated_post_and_returns_the_response() {
    let http_client = TestHttpReqRes::new("https://op.example.com/par")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header(
            "content-type",
            vec!["application/x-www-form-urlencoded".to_string()],
        )
        .assert_request_header("content-length", vec!["99".to_string()])
        .assert_request_header("authorization", vec!["Basic aWRlbnRpZmllcjpzZWN1cmU=".to_string()])
        .assert_request_body("client_id=identifier&redirect_uri=https%3A%2F%2Frp.example.com%2Fcb&response_type=code&scope=openid")
        .set_response_status_code(201)
        .set_response_body(r#"{"expires_in":60,"request_uri":"urn:ietf:params:oauth:request_uri:random"}"#)
        .build();

    let (_, mut client) = get_test_data();

    let res = client
        .pushed_authorization_request_async(None, None, &http_client)
        .await
        .unwrap();

    assert_json_include!(
        expected: json!({
            "expires_in": 60,
            "request_uri": "urn:ietf:params:oauth:request_uri:random"
        }),
        actual: res
    );
}

#[tokio::test]
async fn handles_incorrect_status_code() {
    let http_client = TestHttpReqRes::new("https://op.example.com/par")
    .assert_request_method(HttpMethod::POST)
    .assert_request_header("accept", vec!["application/json".to_string()])
    .assert_request_header(
        "content-type",
        vec!["application/x-www-form-urlencoded".to_string()],
    )
    .assert_request_header("content-length", vec!["99".to_string()])
    .assert_request_header("authorization", vec!["Basic aWRlbnRpZmllcjpzZWN1cmU=".to_string()])
    .assert_request_body("client_id=identifier&redirect_uri=https%3A%2F%2Frp.example.com%2Fcb&response_type=code&scope=openid")
    .set_response_status_code(200)
    .set_response_body(r#"{"expires_in":60,"request_uri":"urn:ietf:params:oauth:request_uri:random"}"#)
    .build();

    let (_, mut client) = get_test_data();

    let err = client
        .pushed_authorization_request_async(None, None, &http_client)
        .await
        .unwrap_err();

    assert!(err.is_op_error());
    assert_eq!(
        "expected 201 Created, got: 200 OK",
        err.op_error().error.error_description.unwrap()
    )
}

#[tokio::test]
async fn handles_request_being_part_of_the_params() {
    let http_client = TestHttpReqRes::new("https://op.example.com/par")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header(
            "content-type",
            vec!["application/x-www-form-urlencoded".to_string()],
        )
        .assert_request_header("content-length", vec!["32".to_string()])
        .assert_request_header(
            "authorization",
            vec!["Basic aWRlbnRpZmllcjpzZWN1cmU=".to_string()],
        )
        .assert_request_body("client_id=identifier&request=jwt")
        .set_response_status_code(201)
        .set_response_body(
            r#"{"expires_in":60,"request_uri":"urn:ietf:params:oauth:request_uri:random"}"#,
        )
        .build();

    let (_, mut client) = get_test_data();

    let mut params = AuthorizationParameters::default();

    params.request = Some("jwt".to_string());

    let res = client
        .pushed_authorization_request_async(Some(params), None, &http_client)
        .await
        .unwrap();

    assert_json_include!(
        expected: json!({
            "expires_in": 60,
            "request_uri": "urn:ietf:params:oauth:request_uri:random"
        }),
        actual: res
    );
}

#[tokio::test]
async fn rejects_with_op_error_when_part_of_the_response() {
    let http_client = TestHttpReqRes::new("https://op.example.com/par")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header(
            "content-type",
            vec!["application/x-www-form-urlencoded".to_string()],
        )
        .assert_request_header("content-length", vec!["99".to_string()])
        .assert_request_header(
            "authorization",
            vec!["Basic aWRlbnRpZmllcjpzZWN1cmU=".to_string()],
        )
        .assert_request_body("client_id=identifier&redirect_uri=https%3A%2F%2Frp.example.com%2Fcb&response_type=code&scope=openid")
        .set_response_status_code(400)
        .set_response_body(r#"{"error":"invalid_request","error_description":"description"}"#)
        .build();

    let (_, mut client) = get_test_data();

    let err = client
        .pushed_authorization_request_async(None, None, &http_client)
        .await
        .unwrap_err();

    assert!(err.is_op_error());

    let op_error = err.op_error();

    assert_eq!("invalid_request", op_error.error.error);
    assert_eq!("description", op_error.error.error_description.unwrap());
}

#[tokio::test]
async fn rejects_with_rp_error_when_request_uri_is_missing_from_the_response() {
    let http_client = TestHttpReqRes::new("https://op.example.com/par")
    .assert_request_method(HttpMethod::POST)
    .assert_request_header("accept", vec!["application/json".to_string()])
    .assert_request_header(
        "content-type",
        vec!["application/x-www-form-urlencoded".to_string()],
    )
    .assert_request_header("content-length", vec!["99".to_string()])
    .assert_request_header(
        "authorization",
        vec!["Basic aWRlbnRpZmllcjpzZWN1cmU=".to_string()],
    )
    .assert_request_body("client_id=identifier&redirect_uri=https%3A%2F%2Frp.example.com%2Fcb&response_type=code&scope=openid")
    .set_response_status_code(201)
    .set_response_body(r#"{"expires_in":60}"#)
    .build();

    let (_, mut client) = get_test_data();

    let err = client
        .pushed_authorization_request_async(None, None, &http_client)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());

    let rp_error = err.rp_error();

    assert!(rp_error.response.is_some());
    assert_eq!(
        "expected request_uri in Pushed Authorization Successful Response",
        rp_error.error.message
    );
}

#[tokio::test]
async fn rejects_with_rp_error_when_request_uri_is_not_a_string() {
    let http_client = TestHttpReqRes::new("https://op.example.com/par")
    .assert_request_method(HttpMethod::POST)
    .assert_request_header("accept", vec!["application/json".to_string()])
    .assert_request_header(
        "content-type",
        vec!["application/x-www-form-urlencoded".to_string()],
    )
    .assert_request_header("content-length", vec!["99".to_string()])
    .assert_request_header(
        "authorization",
        vec!["Basic aWRlbnRpZmllcjpzZWN1cmU=".to_string()],
    )
    .assert_request_body("client_id=identifier&redirect_uri=https%3A%2F%2Frp.example.com%2Fcb&response_type=code&scope=openid")
    .set_response_status_code(201)
    .set_response_body(r#"{"expires_in":60,"request_uri":null}"#)
    .build();

    let (_, mut client) = get_test_data();

    let err = client
        .pushed_authorization_request_async(None, None, &http_client)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());

    let rp_error = err.rp_error();

    assert!(rp_error.response.is_some());
    assert_eq!(
        "invalid request_uri value in Pushed Authorization Successful Response",
        rp_error.error.message
    );
}

#[tokio::test]
async fn rejects_with_rp_error_when_expires_in_is_missing_from_the_response() {
    let http_client = TestHttpReqRes::new("https://op.example.com/par")
    .assert_request_method(HttpMethod::POST)
    .assert_request_header("accept", vec!["application/json".to_string()])
    .assert_request_header(
        "content-type",
        vec!["application/x-www-form-urlencoded".to_string()],
    )
    .assert_request_header("content-length", vec!["99".to_string()])
    .assert_request_header(
        "authorization",
        vec!["Basic aWRlbnRpZmllcjpzZWN1cmU=".to_string()],
    )
    .assert_request_body("client_id=identifier&redirect_uri=https%3A%2F%2Frp.example.com%2Fcb&response_type=code&scope=openid")
    .set_response_status_code(201)
    .set_response_body(r#"{"request_uri":"urn:ietf:params:oauth:request_uri:random"}"#)
    .build();

    let (_, mut client) = get_test_data();

    let err = client
        .pushed_authorization_request_async(None, None, &http_client)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());

    let rp_error = err.rp_error();

    assert!(rp_error.response.is_some());
    assert_eq!(
        "expected expires_in in Pushed Authorization Successful Response",
        rp_error.error.message
    );
}

#[tokio::test]
async fn rejects_with_rp_error_when_expires_in_is_not_a_string() {
    let http_client = TestHttpReqRes::new("https://op.example.com/par")
    .assert_request_method(HttpMethod::POST)
    .assert_request_header("accept", vec!["application/json".to_string()])
    .assert_request_header(
        "content-type",
        vec!["application/x-www-form-urlencoded".to_string()],
    )
    .assert_request_header("content-length", vec!["99".to_string()])
    .assert_request_header(
        "authorization",
        vec!["Basic aWRlbnRpZmllcjpzZWN1cmU=".to_string()],
    )
    .assert_request_body("client_id=identifier&redirect_uri=https%3A%2F%2Frp.example.com%2Fcb&response_type=code&scope=openid")
    .set_response_status_code(201)
    .set_response_body( r#"{"request_uri":"urn:ietf:params:oauth:request_uri:random","expires_in":null}"#)
    .build();

    let (_, mut client) = get_test_data();

    let err = client
        .pushed_authorization_request_async(None, None, &http_client)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());

    let rp_error = err.rp_error();

    assert!(rp_error.response.is_some());
    assert_eq!(
        "invalid expires_in value in Pushed Authorization Successful Response",
        rp_error.error.message
    );
}
