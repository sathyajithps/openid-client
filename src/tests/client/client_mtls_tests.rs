use assert_json_diff::assert_json_include;
use httpmock::{
    Method::{GET, POST},
    MockServer,
};
use serde_json::json;

use crate::{
    client::Client,
    helpers::decode_jwt,
    issuer::Issuer,
    tests::test_interceptors::{
        get_default_test_interceptor, get_default_test_interceptor_with_crt_key,
        get_default_test_interceptor_with_pfx,
    },
    tokenset::{TokenSet, TokenSetParams},
    types::{ClientMetadata, IssuerMetadata, MtlsEndpoints, UserinfoRequestParams},
};

fn get_clients(port: Option<u16>) -> (Client, Client) {
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

    let issuer = Issuer::new(issuer_metadata, None);

    let client_metadata = ClientMetadata {
        client_id: Some("client".to_string()),
        token_endpoint_auth_method: Some("self_signed_tls_client_auth".to_string()),
        tls_client_certificate_bound_access_tokens: Some(true),
        ..Default::default()
    };

    let client = issuer
        .client(
            client_metadata,
            get_default_test_interceptor_with_crt_key(port),
            None,
            None,
            false,
        )
        .unwrap();

    let jwt_client_metadata = ClientMetadata {
        client_id: Some("client".to_string()),
        client_secret: Some("abcdefghijklmnopqrstuvwxyz123456".to_string()),
        token_endpoint_auth_method: Some("client_secret_jwt".to_string()),
        token_endpoint_auth_signing_alg: Some("HS256".to_string()),
        tls_client_certificate_bound_access_tokens: Some(true),
        ..Default::default()
    };

    let jwt_auth_client = issuer
        .client(jwt_client_metadata, None, None, None, false)
        .unwrap();

    (client, jwt_auth_client)
}

#[tokio::test]
async fn uses_the_issuer_identifier_and_token_endpoint_as_private_key_jwt_audiences() {
    let (_, client) = get_clients(None);

    let req_token = client.auth_for("token", None).unwrap();
    let form_token = req_token.form.unwrap();

    let decoded_token = decode_jwt(
        &form_token
            .get("client_assertion")
            .unwrap()
            .as_str()
            .unwrap(),
    )
    .unwrap();

    let aud_token = decoded_token.payload.claim("aud").unwrap();

    assert_json_include!(
        expected: json!(["https://op.example.com", "https://op.example.com/token"]),
        actual: aud_token
    );

    let req_introspection = client.auth_for("introspection", None).unwrap();
    let form_introspection = req_introspection.form.unwrap();

    let decoded_introspection = decode_jwt(
        &form_introspection
            .get("client_assertion")
            .unwrap()
            .as_str()
            .unwrap(),
    )
    .unwrap();

    let aud_introspection = decoded_introspection.payload.claim("aud").unwrap();

    assert_json_include!(
        expected: json!(["https://op.example.com", "https://op.example.com/token"]),
        actual: aud_introspection
    );

    let req_revocation = client.auth_for("introspection", None).unwrap();
    let form_revocation = req_revocation.form.unwrap();

    let decoded_revocation = decode_jwt(
        &form_revocation
            .get("client_assertion")
            .unwrap()
            .as_str()
            .unwrap(),
    )
    .unwrap();

    let aud_revocation = decoded_revocation.payload.claim("aud").unwrap();

    assert_json_include!(
        expected: json!(["https://op.example.com", "https://op.example.com/token"]),
        actual: aud_revocation
    );
}

#[tokio::test]
async fn requires_mtls_for_userinfo_when_tls_client_certificate_bound_access_tokens_is_true() {
    let mock_http_server = MockServer::start();

    let _server = mock_http_server.mock(|when, then| {
        when.method(GET).path("/me");
        then.status(200).body(r#"{"sub":"foo"}"#);
    });

    let (mut client, _) = get_clients(Some(mock_http_server.port()));

    let token_params = TokenSetParams {
        access_token: Some("foo".to_string()),
        ..Default::default()
    };

    let token = TokenSet::new(token_params);

    client
        .userinfo_async(&token, UserinfoRequestParams::default())
        .await
        .unwrap();

    client.request_interceptor = get_default_test_interceptor(Some(mock_http_server.port()));

    let err = client
        .userinfo_async(&token, UserinfoRequestParams::default())
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
    let mock_http_server = MockServer::start();

    let _server = mock_http_server.mock(|when, then| {
        when.method(POST).path("/token/introspect");
        then.status(200).body("{}");
    });

    let (mut client, _) = get_clients(Some(mock_http_server.port()));

    client.introspect_async("foo", None, None).await.unwrap();

    client.request_interceptor = get_default_test_interceptor(Some(mock_http_server.port()));

    let err = client
        .introspect_async("foo", None, None)
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
    let mock_http_server = MockServer::start();

    let _server = mock_http_server.mock(|when, then| {
        when.method(POST).path("/token/revoke");
        then.status(200).body("{}");
    });

    let (mut client, _) = get_clients(Some(mock_http_server.port()));

    client
        .revoke_async("foo".to_string(), None, None)
        .await
        .unwrap();

    client.request_interceptor = get_default_test_interceptor(Some(mock_http_server.port()));

    let err = client
        .revoke_async("foo".to_string(), None, None)
        .await
        .unwrap_err();

    assert!(err.is_type_error());
    assert_eq!(
        "mutual-TLS certificate and key not set",
        err.type_error().error.message
    );
}

#[tokio::test]
async fn works_with_a_pkcs_12_file_and_a_passphrase() {
    let mock_http_server = MockServer::start();

    let _server = mock_http_server.mock(|when, then| {
        when.method(GET).path("/me");
        then.status(200).body(r#"{"sub":"foo"}"#);
    });

    let (mut client, _) = get_clients(Some(mock_http_server.port()));

    client.request_interceptor =
        get_default_test_interceptor_with_pfx(Some(mock_http_server.port()));

    let token_params = TokenSetParams {
        access_token: Some("foo".to_string()),
        ..Default::default()
    };

    let token = TokenSet::new(token_params);

    client
        .userinfo_async(&token, UserinfoRequestParams::default())
        .await
        .unwrap();

    client.request_interceptor = get_default_test_interceptor(Some(mock_http_server.port()));

    let err = client
        .userinfo_async(&token, UserinfoRequestParams::default())
        .await
        .unwrap_err();

    assert!(err.is_type_error());
    assert_eq!(
        "mutual-TLS certificate and key not set",
        err.type_error().error.message
    );
}
