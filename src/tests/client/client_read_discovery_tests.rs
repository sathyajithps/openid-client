use crate::{
    client::Client,
    helpers::convert_json_to,
    http_client::DefaultHttpClient,
    issuer::Issuer,
    jwks::Jwks,
    types::{HttpMethod, IssuerMetadata},
};

use crate::tests::test_http_client::TestHttpReqRes;

static DEFAULT_CLIENT_READ: &str = r#"{"client_id":"identifier","client_secret":"secure"}"#;

#[tokio::test]
async fn accepts_and_assigns_discovered_metadata() {
    let http_client = TestHttpReqRes::new("https://op.example.com/client/identifier")
        .assert_request_method(HttpMethod::GET)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .set_response_body(DEFAULT_CLIENT_READ)
        .set_response_content_type_header("application/json")
        .build();

    let client_registration_uri = "https://op.example.com/client/identifier";

    let client = Client::from_uri_async(
        &http_client,
        &client_registration_uri,
        &Issuer::new(IssuerMetadata::default()),
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();

    assert_eq!("identifier", client.client_id);

    assert_eq!("secure", client.client_secret.unwrap());
}

#[tokio::test]
async fn is_rejected_with_op_error_upon_oidc_error() {
    let http_client = TestHttpReqRes::new("https://op.example.com/client/identifier")
        .assert_request_method(HttpMethod::GET)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .set_response_body(
            r#"{"error":"server_error","error_description":"bad things are happening"}"#,
        )
        .set_response_status_code(500)
        .build();

    let client_registration_uri = "https://op.example.com/client/identifier";

    let client_error = Client::from_uri_async(
        &http_client,
        &client_registration_uri,
        &Issuer::new(IssuerMetadata::default()),
        None,
        None,
        None,
        None,
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
    let http_client = TestHttpReqRes::new("https://op.example.com/client/identifier")
        .assert_request_method(HttpMethod::GET)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .set_response_body("Unauthorized")
        .set_response_www_authenticate_header(
            r#"Bearer error="invalid_token", error_description="bad things are happening""#,
        )
        .set_response_status_code(401)
        .build();

    let client_registration_uri = "https://op.example.com/client/identifier";

    let client_error = Client::from_uri_async(
        &http_client,
        &client_registration_uri,
        &Issuer::new(IssuerMetadata::default()),
        None,
        None,
        None,
        None,
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
    let http_client = TestHttpReqRes::new("https://op.example.com/client/identifier")
        .assert_request_method(HttpMethod::GET)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .set_response_body("Internal Server Error")
        .set_response_status_code(500)
        .build();

    let client_registration_uri = "https://op.example.com/client/identifier";

    let client_error = Client::from_uri_async(
        &http_client,
        &client_registration_uri,
        &Issuer::new(IssuerMetadata::default()),
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap_err();

    assert!(client_error.is_op_error());

    let err = client_error.op_error();

    assert!(err.response.is_some());

    assert_eq!(
        Some("expected 200 OK, got: 500 Internal Server Error".to_string()),
        err.error.error_description
    );
}

#[tokio::test]
async fn is_rejected_with_json_parse_error_upon_invalid_response() {
    let http_client = TestHttpReqRes::new("https://op.example.com/client/identifier")
        .assert_request_method(HttpMethod::GET)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .set_response_body(r#"{"notavalid"}"#)
        .build();

    let client_registration_uri = "https://op.example.com/client/identifier";

    let client_error = Client::from_uri_async(
        &http_client,
        &client_registration_uri,
        &Issuer::new(IssuerMetadata::default()),
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap_err();

    assert!(client_error.is_type_error());

    let err = client_error.type_error().error;

    assert_eq!("unexpected body type", err.message);
}

#[tokio::test]
async fn does_not_accept_oct_keys() {
    let client_registration_uri = "https://op.example.com/client/registration";

    let jwks = Some(convert_json_to::<Jwks>(r#"{"keys":[{"k":"qHedLw","kty":"oct","kid":"R5OsS5S7xvrW7E0k0t0PwRsskJpdOkyfnAZi8S806Bg"}]}"#).unwrap());

    let client_error = Client::from_uri_async(
        &DefaultHttpClient,
        &client_registration_uri,
        &Issuer::new(IssuerMetadata::default()),
        None,
        jwks,
        None,
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
    let client_registration_uri = "https://op.example.com/client/registration";

    let jwks = Some(convert_json_to::<Jwks>(r#"{"keys":[{"kty":"EC","kid":"MFZeG102dQiqbANoaMlW_Jmf7fOZmtRsHt77JFhTpF0","crv":"P-256","x":"FWZ9rSkLt6Dx9E3pxLybhdM6xgR5obGsj5_pqmnz5J4","y":"_n8G69C-A2Xl4xUW2lF0i8ZGZnk_KPYrhv4GbTGu5G4"}]}"#).unwrap());
    let client_error = Client::from_uri_async(
        &DefaultHttpClient,
        &client_registration_uri,
        &Issuer::new(IssuerMetadata::default()),
        None,
        jwks.clone(),
        None,
        None,
    )
    .await
    .unwrap_err();

    assert_eq!(
        "jwks must only contain private keys",
        client_error.error().error.message
    );
}
