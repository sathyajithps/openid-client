use assert_json_diff::assert_json_include;
use serde_json::json;

use crate::{
    client::Client,
    helpers::{decode_jwt, form_url_encoded_to_string_map},
    issuer::Issuer,
    tokenset::{TokenSet, TokenSetParams},
    types::{ClientMetadata, HttpMethod, IssuerMetadata, MtlsEndpoints, UserinfoOptions},
};

use crate::tests::test_http_client::TestHttpReqRes;

fn get_clients() -> (Client, Client) {
    let issuer_metadata = IssuerMetadata {
        issuer: "https://op.example.com".to_string(),
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        token_endpoint: Some("https://op.example.com/token".to_string()),
        introspection_endpoint: Some("https://op.example.com/token/introspect".to_string()),
        revocation_endpoint: Some("https://op.example.com/token/revoke".to_string()),
        mtls_endpoint_aliases: Some(MtlsEndpoints {
            userinfo_endpoint: Some("https://mtls.op.example.com/me".to_string()),
            token_endpoint: Some("https://mtls.op.example.com/token".to_string()),
            introspection_endpoint: Some(
                "https://mtls.op.example.com/token/introspect".to_string(),
            ),
            revocation_endpoint: Some("https://mtls.op.example.com/token/revoke".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("client".to_string()),
        token_endpoint_auth_method: Some("self_signed_tls_client_auth".to_string()),
        tls_client_certificate_bound_access_tokens: Some(true),
        ..Default::default()
    };

    let client = issuer.client(client_metadata, None, None, None).unwrap();

    let jwt_client_metadata = ClientMetadata {
        client_id: Some("client".to_string()),
        client_secret: Some("abcdefghijklmnopqrstuvwxyz123456".to_string()),
        token_endpoint_auth_method: Some("client_secret_jwt".to_string()),
        token_endpoint_auth_signing_alg: Some("HS256".to_string()),
        tls_client_certificate_bound_access_tokens: Some(true),
        ..Default::default()
    };

    let jwt_auth_client = issuer
        .client(jwt_client_metadata, None, None, None)
        .unwrap();

    (client, jwt_auth_client)
}

#[tokio::test]
async fn uses_the_issuer_identifier_and_token_endpoint_as_private_key_jwt_audiences() {
    let (_, client) = get_clients();

    let req_token = client.auth_for("token", None).unwrap();
    let form_token = req_token
        .body
        .map(|b| form_url_encoded_to_string_map(&b))
        .unwrap();

    let decoded_token = decode_jwt(&form_token.get("client_assertion").unwrap()).unwrap();

    let aud_token = decoded_token.payload.claim("aud").unwrap();

    assert_json_include!(
        expected: json!(["https://op.example.com", "https://op.example.com/token"]),
        actual: aud_token
    );

    let req_introspection = client.auth_for("introspection", None).unwrap();
    let form_introspection = req_introspection
        .body
        .map(|b| form_url_encoded_to_string_map(&b))
        .unwrap();

    let decoded_introspection =
        decode_jwt(&form_introspection.get("client_assertion").unwrap()).unwrap();

    let aud_introspection = decoded_introspection.payload.claim("aud").unwrap();

    assert_json_include!(
        expected: json!(["https://op.example.com", "https://op.example.com/token"]),
        actual: aud_introspection
    );

    let req_revocation = client.auth_for("introspection", None).unwrap();
    let form_revocation = req_revocation
        .body
        .map(|b| form_url_encoded_to_string_map(&b))
        .unwrap();

    let decoded_revocation = decode_jwt(&form_revocation.get("client_assertion").unwrap()).unwrap();

    let aud_revocation = decoded_revocation.payload.claim("aud").unwrap();

    assert_json_include!(
        expected: json!(["https://op.example.com", "https://op.example.com/token"]),
        actual: aud_revocation
    );
}

#[tokio::test]
async fn requires_mtls_for_userinfo_when_tls_client_certificate_bound_access_tokens_is_true() {
    let mut http_client = TestHttpReqRes::new("https://mtls.op.example.com/me")
        .assert_request_method(HttpMethod::GET)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header("authorization", vec!["Bearer foo".to_string()])
        .assert_request_mtls(true)
        .set_response_body(r#"{"sub":"foo"}"#)
        .set_response_status_code(200)
        .build();

    let (mut client, _) = get_clients();

    let token_params = TokenSetParams {
        access_token: Some("foo".to_string()),
        ..Default::default()
    };

    let token = TokenSet::new(token_params);

    http_client.return_client_cert(true);

    client
        .userinfo_async(&token, UserinfoOptions::default(), &http_client)
        .await
        .unwrap();

    http_client.return_client_cert(false);

    let err = client
        .userinfo_async(&token, UserinfoOptions::default(), &http_client)
        .await
        .unwrap_err();

    assert!(err.is_type_error());
    assert_eq!(
        "mutual-TLS certificate and key not set",
        err.type_error().error.message
    );
}

#[tokio::test]
async fn requires_mtls_for_introspection_authentication_when_introspection_endpoint_auth_method_is_tls_client_auth(
) {
    let mut http_client = TestHttpReqRes::new("https://mtls.op.example.com/token/introspect")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header(
            "content-type",
            vec!["application/x-www-form-urlencoded".to_string()],
        )
        .assert_request_header("content-length", vec!["26".to_string()])
        .assert_request_mtls(true)
        .assert_request_body("token=foo&client_id=client")
        .set_response_body("{}")
        .set_response_status_code(200)
        .build();

    let (mut client, _) = get_clients();

    http_client.return_client_cert(true);

    client
        .introspect_async("foo".to_owned(), &http_client, None, None)
        .await
        .unwrap();

    http_client.return_client_cert(false);

    let err = client
        .introspect_async("foo".to_owned(), &http_client, None, None)
        .await
        .unwrap_err();

    assert!(err.is_type_error());
    assert_eq!(
        "mutual-TLS certificate and key not set",
        err.type_error().error.message
    );
}

#[tokio::test]
async fn requires_mtls_for_revocation_authentication_when_revocation_endpoint_auth_method_is_tls_client_auth(
) {
    let mut http_client = TestHttpReqRes::new("https://mtls.op.example.com/token/revoke")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header(
            "content-type",
            vec!["application/x-www-form-urlencoded".to_string()],
        )
        .assert_request_header("content-length", vec!["26".to_string()])
        .assert_request_mtls(true)
        .assert_request_body("token=foo&client_id=client")
        .set_response_body("{}")
        .set_response_status_code(200)
        .build();

    let (mut client, _) = get_clients();

    http_client.return_client_cert(true);

    client
        .revoke_async("foo", None, None, &http_client)
        .await
        .unwrap();

    http_client.return_client_cert(false);

    let err = client
        .revoke_async("foo", None, None, &http_client)
        .await
        .unwrap_err();

    assert!(err.is_type_error());
    assert_eq!(
        "mutual-TLS certificate and key not set",
        err.type_error().error.message
    );
}
