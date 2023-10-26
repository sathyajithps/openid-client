use httpmock::{Method::POST, MockServer};
use josekit::{jws::JwsHeader, jwt::JwtPayload};
use serde_json::json;

use crate::{
    client::Client,
    helpers::now,
    issuer::Issuer,
    tests::test_interceptors::get_default_test_interceptor,
    tokenset::{TokenSet, TokenSetParams},
    types::{ClientMetadata, IssuerMetadata},
};

fn get_client(port: Option<u16>) -> Client {
    let issuer_metadata = IssuerMetadata {
        issuer: "https://op.example.com".to_string(),
        token_endpoint: Some("https://op.example.com/token".to_string()),
        ..Default::default()
    };
    let issuer = Issuer::new(issuer_metadata, get_default_test_interceptor(port));

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        client_secret: Some("larger_than_32_char_client_secret".to_string()),
        id_token_signed_response_alg: Some("HS256".to_string()),
        ..Default::default()
    };

    issuer
        .client(client_metadata, None, None, None, false)
        .unwrap()
}

#[tokio::test]
async fn rejects_when_passed_a_token_set_not_containing_refresh_token() {
    let err = get_client(None)
        .refresh_async(TokenSet::default(), None)
        .await
        .unwrap_err();

    assert!(err.is_type_error());
    assert_eq!(
        "refresh_token not present in TokenSet",
        err.type_error().error.message
    );
}

#[tokio::test]
async fn does_a_refresh_token_grant_with_refresh_token() {
    let mock_http_server = MockServer::start();

    let refresh_server = mock_http_server.mock(|when, then| {
        when.method(POST)
            .header("Accept", "application/json")
            .matches(|req| {
                let decoded =
                    urlencoding::decode(std::str::from_utf8(&req.body.as_ref().unwrap()).unwrap())
                        .unwrap();

                let kvp = querystring::querify(&decoded);

                let refresh_token = kvp
                    .iter()
                    .find(|(k, v)| k == &"refresh_token" && v == &"refreshValue");
                let grant_type = kvp
                    .iter()
                    .find(|(k, v)| k == &"grant_type" && v == &"refresh_token");

                refresh_token.is_some() && grant_type.is_some()
            })
            .path("/token");
        then.status(200).body("{}");
    });

    let token_set_params = TokenSetParams {
        refresh_token: Some("refreshValue".to_string()),
        ..Default::default()
    };

    let _ = get_client(Some(mock_http_server.port()))
        .refresh_async(TokenSet::new(token_set_params), None)
        .await;

    refresh_server.assert();
}

#[tokio::test]
async fn returns_a_token_set() {
    let mock_http_server = MockServer::start();

    let _refresh_server = mock_http_server.mock(|when, then| {
        when.method(POST)
            .header("Accept", "application/json")
            .matches(|req| {
                let decoded =
                    urlencoding::decode(std::str::from_utf8(&req.body.as_ref().unwrap()).unwrap())
                        .unwrap();

                let kvp = querystring::querify(&decoded);

                let refresh_token = kvp
                    .iter()
                    .find(|(k, v)| k == &"refresh_token" && v == &"refreshValue");
                let grant_type = kvp
                    .iter()
                    .find(|(k, v)| k == &"grant_type" && v == &"refresh_token");

                refresh_token.is_some() && grant_type.is_some()
            })
            .path("/token");
        then.status(200).body(r#"{"access_token":"tokenValue"}"#);
    });

    let token_set_params = TokenSetParams {
        refresh_token: Some("refreshValue".to_string()),
        ..Default::default()
    };

    let token_set = get_client(Some(mock_http_server.port()))
        .refresh_async(TokenSet::new(token_set_params), None)
        .await
        .unwrap();

    assert_eq!("tokenValue", token_set.get_access_token().unwrap());
}

#[tokio::test]
async fn passes_id_token_validations_when_id_token_is_returned() {
    let mock_http_server = MockServer::start();

    let mut client = get_client(Some(mock_http_server.port()));

    let mut payload = JwtPayload::new();
    payload
        .set_claim(
            "iss",
            Some(json!(client.issuer.as_ref().unwrap().issuer.clone())),
        )
        .unwrap();
    let iat = now();
    let exp = iat + 300;

    payload.set_claim("iat", Some(json!(iat))).unwrap();
    payload.set_claim("exp", Some(json!(exp))).unwrap();
    payload.set_claim("aud", Some(json!("identifier"))).unwrap();
    payload.set_claim("sub", Some(json!("foo"))).unwrap();

    let mut header = JwsHeader::new();
    header.set_claim("alg", Some(json!("HS256"))).unwrap();

    let signer = josekit::jws::HS256
        .signer_from_bytes("larger_than_32_char_client_secret")
        .unwrap();

    let id_token = josekit::jwt::encode_with_signer(&payload, &header, &signer).unwrap();

    let _refresh_server = mock_http_server.mock(|when, then| {
        when.method(POST)
            .header("Accept", "application/json")
            .matches(|req| {
                let decoded =
                    urlencoding::decode(std::str::from_utf8(&req.body.as_ref().unwrap()).unwrap())
                        .unwrap();

                let kvp = querystring::querify(&decoded);

                let refresh_token = kvp
                    .iter()
                    .find(|(k, v)| k == &"refresh_token" && v == &"refreshValue");
                let grant_type = kvp
                    .iter()
                    .find(|(k, v)| k == &"grant_type" && v == &"refresh_token");

                refresh_token.is_some() && grant_type.is_some()
            })
            .path("/token");
        then.status(200).body(format!(
            r#"{{"access_token":"present","refresh_token":"refreshValue","id_token":"{}"}}"#,
            &id_token
        ));
    });

    payload.set_claim("exp", Some(json!(exp + 60))).unwrap();

    let id_token_old = josekit::jwt::encode_with_signer(&payload, &header, &signer).unwrap();

    let token_set_params = TokenSetParams {
        refresh_token: Some("refreshValue".to_string()),
        access_token: Some("present".to_string()),
        id_token: Some(id_token_old),
        ..Default::default()
    };

    let token_set = client
        .refresh_async(TokenSet::new(token_set_params), None)
        .await
        .unwrap();

    assert_eq!(id_token, token_set.get_id_token().unwrap());
}

#[tokio::test]
async fn rejects_when_returned_id_token_sub_does_not_match_the_one_passed_in() {
    let mock_http_server = MockServer::start();

    let mut client = get_client(Some(mock_http_server.port()));

    let mut payload = JwtPayload::new();
    payload
        .set_claim(
            "iss",
            Some(json!(client.issuer.as_ref().unwrap().issuer.clone())),
        )
        .unwrap();
    let iat = now();
    let exp = iat + 300;

    payload.set_claim("iat", Some(json!(iat))).unwrap();
    payload.set_claim("exp", Some(json!(exp))).unwrap();
    payload.set_claim("aud", Some(json!("identifier"))).unwrap();
    payload.set_claim("sub", Some(json!("bar"))).unwrap();

    let mut header = JwsHeader::new();
    header.set_claim("alg", Some(json!("HS256"))).unwrap();

    let signer = josekit::jws::HS256
        .signer_from_bytes("larger_than_32_char_client_secret")
        .unwrap();

    let id_token = josekit::jwt::encode_with_signer(&payload, &header, &signer).unwrap();

    let _refresh_server = mock_http_server.mock(|when, then| {
        when.method(POST)
            .header("Accept", "application/json")
            .matches(|req| {
                let decoded =
                    urlencoding::decode(std::str::from_utf8(&req.body.as_ref().unwrap()).unwrap())
                        .unwrap();

                let kvp = querystring::querify(&decoded);

                let refresh_token = kvp
                    .iter()
                    .find(|(k, v)| k == &"refresh_token" && v == &"refreshValue");
                let grant_type = kvp
                    .iter()
                    .find(|(k, v)| k == &"grant_type" && v == &"refresh_token");

                refresh_token.is_some() && grant_type.is_some()
            })
            .path("/token");
        then.status(200).body(format!(
            r#"{{"access_token":"present","refresh_token":"refreshValue","id_token":"{}"}}"#,
            &id_token
        ));
    });

    payload.set_claim("sub", Some(json!("foo"))).unwrap();

    let id_token_old = josekit::jwt::encode_with_signer(&payload, &header, &signer).unwrap();

    let token_set_params = TokenSetParams {
        refresh_token: Some("refreshValue".to_string()),
        access_token: Some("present".to_string()),
        id_token: Some(id_token_old),
        ..Default::default()
    };

    let err = client
        .refresh_async(TokenSet::new(token_set_params), None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(
        "sub mismatch, expected foo, got: bar",
        err.rp_error().error.message
    );
}
