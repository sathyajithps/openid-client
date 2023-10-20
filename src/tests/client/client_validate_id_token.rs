use std::{collections::HashMap, time::Duration};

use httpmock::{Method::GET, MockServer};
use josekit::{jwk::Jwk, jws::JwsHeader, jwt::JwtPayload};
use serde_json::{json, Value};

use crate::{
    client::Client,
    helpers::{generate_hash, now},
    issuer::Issuer,
    jwks::{jwks::CustomJwk, Jwks},
    tests::test_interceptors::get_default_test_interceptor,
    tokenset::{TokenSet, TokenSetParams},
    types::{
        CallbackParams, ClientMetadata, ClientOptions, IssuerMetadata, OAuthCallbackChecks,
        OpenIDCallbackChecks,
    },
};

struct TestData {
    pub jwk: Jwk,
    pub issuer: Issuer,
    pub client: Client,
    pub client_with_3rd_party: Client,
    pub client_with_3rd_parties: Client,
    pub fapi_client: Client,
}

fn get_token_set(id_token: String, access_token: Option<String>, code: Option<String>) -> TokenSet {
    let mut other = HashMap::new();

    if let Some(c) = code {
        other.insert("code".to_string(), json!(c));
    }

    let token_set_params = TokenSetParams {
        id_token: Some(id_token),
        access_token,
        other: Some(other),
        ..Default::default()
    };

    TokenSet::new(token_set_params)
}

fn get_id_token(key: &Jwk, alg: &str, payload: Vec<(String, Value)>) -> String {
    let mut p = JwtPayload::new();

    for (c, v) in payload {
        p.set_claim(&c, Some(v)).unwrap();
    }

    let mut header = JwsHeader::new();
    header.set_claim("alg", Some(json!(alg))).unwrap();
    header
        .set_claim("typ", Some(json!("oauth-authz-req+jwt")))
        .unwrap();

    if !alg.starts_with("HS") {
        if let Some(id) = key.key_id() {
            header.set_claim("kid", Some(json!(id))).unwrap();
        }
    }

    let signer = key.to_signer().unwrap();

    josekit::jwt::encode_with_signer(&p, &header, &*signer).unwrap()
}

fn get_test_data(mock_server: &MockServer) -> TestData {
    let mut jwk = Jwk::generate_rsa_key(2048).unwrap();

    jwk.set_algorithm("RS256");

    let jwks = Jwks::from(vec![jwk.clone()]);

    let _ = mock_server.mock(|when, then| {
        when.method(GET)
            .header("Accept", "application/json,application/jwk-set+json")
            .path("/certs");
        then.status(200)
            .body(serde_json::to_string(&jwks.get_public_jwks()).unwrap());
    });

    let issuer_metadata = IssuerMetadata {
        issuer: "https://op.example.com".to_string(),
        jwks_uri: Some("https://op.example.com/certs".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(
        issuer_metadata,
        get_default_test_interceptor(Some(mock_server.port())),
    );

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        client_secret: Some("larger_than_32_characters_secret_".to_string()),
        ..Default::default()
    };

    let client = issuer
        .client(client_metadata.clone(), None, None, None, false)
        .unwrap();

    let client_3rd_party_options = ClientOptions {
        additional_authorized_parties: Some(vec!["authorized third party".to_string()]),
    };

    let client_with_3rd_party = issuer
        .client(
            client_metadata.clone(),
            None,
            None,
            Some(client_3rd_party_options),
            false,
        )
        .unwrap();

    let client_3rd_parties_options = ClientOptions {
        additional_authorized_parties: Some(vec![
            "authorized third party".to_string(),
            "another third party".to_string(),
        ]),
    };

    let client_with_3rd_parties = issuer
        .client(
            client_metadata,
            None,
            None,
            Some(client_3rd_parties_options),
            false,
        )
        .unwrap();

    let fapi_client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        token_endpoint_auth_method: Some("tls_client_auth".to_string()),
        ..Default::default()
    };

    let fapi_client = issuer
        .client(fapi_client_metadata, None, None, None, true)
        .unwrap();

    TestData {
        jwk,
        issuer,
        client,
        client_with_3rd_party,
        client_with_3rd_parties,
        fapi_client,
    }
}

#[tokio::test]
async fn validates_the_id_token_and_fulfills_with_input_value() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(now() + 3600)),
        ("iat".to_string(), json!(now())),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    let validated_token_set = test_data
        .client
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap();

    assert_eq!(id_token, validated_token_set.get_id_token().unwrap());
}

#[tokio::test]
async fn validates_the_id_token_signature() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(now() + 3600)),
        ("iat".to_string(), json!(now())),
    ];

    let mut id_token = get_id_token(&test_data.jwk, "RS256", payload);

    id_token = id_token[..id_token.len() - 2].to_string();

    let token_set = get_token_set(id_token.clone(), None, None);

    let err = test_data
        .client
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());

    assert_eq!(
        "failed to validate JWT signature",
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn validates_the_id_token_and_fulfills_with_input_value_when_signed_by_secret() {
    let mock_server = MockServer::start();

    let test_data = get_test_data(&mock_server);

    let client_metadata = ClientMetadata {
        client_id: Some("hs256-client".to_string()),
        client_secret: Some("larger_than_32_characters_secret_".to_string()),
        id_token_signed_response_alg: Some("HS256".to_string()),
        ..Default::default()
    };

    let mut client = test_data
        .issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let key = client.secret_for_alg("HS256").unwrap();

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!(client.client_id)),
        ("exp".to_string(), json!(now() + 3600)),
        ("iat".to_string(), json!(now())),
    ];

    let id_token = get_id_token(&key, "HS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    let validated_token_set = client
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap();

    assert_eq!(id_token, validated_token_set.get_id_token().unwrap());
}

#[tokio::test]
async fn validates_the_id_token_signed_response_alg_is_the_one_used() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let key = test_data.client.secret_for_alg("HS256").unwrap();

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(now() + 3600)),
        ("iat".to_string(), json!(now())),
    ];

    let id_token = get_id_token(&key, "HS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    let err = test_data
        .client
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(
        "unexpected JWT alg received, expected RS256, got: HS256",
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn verifies_the_azp() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!(test_data.client.client_id)),
        ("azp".to_string(), json!("not the client")),
        ("exp".to_string(), json!(now() + 3600)),
        ("iat".to_string(), json!(now())),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    let err = test_data
        .client
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(
        "azp mismatch, got: not the client",
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn verifies_azp_is_present_when_more_audiences_are_provided() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        (
            "aud".to_string(),
            json!([test_data.client.client_id, "someone else"]),
        ),
        ("exp".to_string(), json!(now() + 3600)),
        ("iat".to_string(), json!(now())),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    let err = test_data
        .client
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(
        "missing required JWT property azp",
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn verifies_the_audience_when_azp_is_there() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        (
            "aud".to_string(),
            json!([test_data.client.client_id, "someone else"]),
        ),
        ("azp".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(now() + 3600)),
        ("iat".to_string(), json!(now())),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    let validated_token_set = test_data
        .client
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap();

    assert_eq!(id_token, validated_token_set.get_id_token().unwrap());
}

#[tokio::test]
async fn rejects_unknown_additional_party_azp_values_single_additional_value() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        (
            "aud".to_string(),
            json!([test_data.client.client_id, "someone else"]),
        ),
        ("azp".to_string(), json!("some unknown third party")),
        ("exp".to_string(), json!(now() + 3600)),
        ("iat".to_string(), json!(now())),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    let err = test_data
        .client_with_3rd_party
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(
        "azp mismatch, got: some unknown third party",
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn allows_configured_additional_party_azp_value_single_additional_value() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        (
            "aud".to_string(),
            json!([test_data.client.client_id, "someone else"]),
        ),
        ("azp".to_string(), json!("authorized third party")),
        ("exp".to_string(), json!(now() + 3600)),
        ("iat".to_string(), json!(now())),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    let validated_token_set = test_data
        .client_with_3rd_party
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap();

    assert_eq!(id_token, validated_token_set.get_id_token().unwrap());
}

#[tokio::test]
async fn allows_the_default_client_id_additional_party_azp_value_single_additional_value() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        (
            "aud".to_string(),
            json!([test_data.client.client_id, "someone else"]),
        ),
        ("azp".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(now() + 3600)),
        ("iat".to_string(), json!(now())),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    let validated_token_set = test_data
        .client_with_3rd_party
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap();

    assert_eq!(id_token, validated_token_set.get_id_token().unwrap());
}

#[tokio::test]
async fn rejects_unknown_additional_party_azp_values_multiple_additional_values() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        (
            "aud".to_string(),
            json!([test_data.client.client_id, "someone else"]),
        ),
        ("azp".to_string(), json!("some unknown third party")),
        ("exp".to_string(), json!(now() + 3600)),
        ("iat".to_string(), json!(now())),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    let err = test_data
        .client_with_3rd_parties
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(
        "azp mismatch, got: some unknown third party",
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn allows_configured_additional_party_azp_value_multiple_additional_values() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        (
            "aud".to_string(),
            json!([test_data.client.client_id, "someone else"]),
        ),
        ("azp".to_string(), json!("authorized third party")),
        ("exp".to_string(), json!(now() + 3600)),
        ("iat".to_string(), json!(now())),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    let validated_token_set = test_data
        .client_with_3rd_parties
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap();

    assert_eq!(id_token, validated_token_set.get_id_token().unwrap());
}

#[tokio::test]
async fn allows_the_default_client_id_additional_party_azp_value_multiple_additional_value() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        (
            "aud".to_string(),
            json!([test_data.client.client_id, "someone else"]),
        ),
        ("azp".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(now() + 3600)),
        ("iat".to_string(), json!(now())),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    let validated_token_set = test_data
        .client_with_3rd_parties
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap();

    assert_eq!(id_token, validated_token_set.get_id_token().unwrap());
}

#[tokio::test]
async fn verifies_the_audience_when_string() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!("someone else")),
        ("exp".to_string(), json!(now() + 3600)),
        ("iat".to_string(), json!(now())),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    let err = test_data
        .client
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(
        "aud mismatch, expected identifier, got: someone else",
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn verifies_the_audience_when_array() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!(["someone else", "and another"])),
        ("azp".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(now() + 3600)),
        ("iat".to_string(), json!(now())),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    let err = test_data
        .client
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(
        "aud is missing the client_id, expected identifier to be included in [\"someone else\", \"and another\"]",
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn passes_with_nonce_check() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("nonce".to_string(), json!("nonce!!!")),
        (
            "aud".to_string(),
            json!([test_data.client.client_id, "someone else"]),
        ),
        ("azp".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(now() + 3600)),
        ("iat".to_string(), json!(now())),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    let validated_token_set = test_data
        .client
        .validate_id_token_async(token_set, Some("nonce!!!".to_string()), "", None, None)
        .await
        .unwrap();

    assert_eq!(id_token, validated_token_set.get_id_token().unwrap());
}

#[tokio::test]
async fn validates_nonce_when_provided_to_check_for() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        (
            "aud".to_string(),
            json!([test_data.client.client_id, "someone else"]),
        ),
        ("azp".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(now() + 3600)),
        ("iat".to_string(), json!(now())),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    let err = test_data
        .client
        .validate_id_token_async(token_set, Some("nonce!!!".to_string()), "", None, None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(
        "nonce mismatch, expected nonce!!!, got: ",
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn validates_nonce_when_in_token() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("nonce".to_string(), json!("nonce!!!")),
        (
            "aud".to_string(),
            json!([test_data.client.client_id, "someone else"]),
        ),
        ("azp".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(now() + 3600)),
        ("iat".to_string(), json!(now())),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    let err = test_data
        .client
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(
        "nonce mismatch, expected , got: nonce!!!",
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn verifies_presence_of_payload_property_iss() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let mut payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("nonce".to_string(), json!("nonce!!!")),
        ("aud".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(now() + 3600)),
        ("iat".to_string(), json!(now())),
    ];

    payload = payload
        .iter()
        .filter(|x| x.0 != "iss")
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    let err = test_data
        .client
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(
        "missing required JWT property iss",
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn verifies_presence_of_payload_property_sub() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let mut payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("nonce".to_string(), json!("nonce!!!")),
        ("aud".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(now() + 3600)),
        ("iat".to_string(), json!(now())),
    ];

    payload = payload
        .iter()
        .filter(|x| x.0 != "sub")
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    let err = test_data
        .client
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(
        "missing required JWT property sub",
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn verifies_presence_of_payload_property_aud() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let mut payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("nonce".to_string(), json!("nonce!!!")),
        ("aud".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(now() + 3600)),
        ("iat".to_string(), json!(now())),
    ];

    payload = payload
        .iter()
        .filter(|x| x.0 != "aud")
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    let err = test_data
        .client
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(
        "missing required JWT property aud",
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn verifies_presence_of_payload_property_exp() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let mut payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("nonce".to_string(), json!("nonce!!!")),
        ("aud".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(now() + 3600)),
        ("iat".to_string(), json!(now())),
    ];

    payload = payload
        .iter()
        .filter(|x| x.0 != "exp")
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    let err = test_data
        .client
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(
        "missing required JWT property exp",
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn verifies_presence_of_payload_property_iat() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let mut payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(now() + 3600)),
        ("iat".to_string(), json!(now())),
    ];

    payload = payload
        .iter()
        .filter(|x| x.0 != "iat")
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    let err = test_data
        .client
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(
        "missing required JWT property iat",
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn allows_iat_skew() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(now() + 3600)),
        ("iat".to_string(), json!(now() + 5)),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    test_data
        .client
        .set_clock_skew_duration(Duration::from_secs(5));

    let validated_token_set = test_data
        .client
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap();

    assert_eq!(id_token, validated_token_set.get_id_token().unwrap());
}

#[tokio::test]
async fn verifies_exp_is_in_the_future() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let time = now();
    let time_exp = time - 100;

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(time_exp)),
        ("iat".to_string(), json!(time)),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    let err = test_data
        .client
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(
        format!("JWT expired, now {}, exp {}", time, time_exp),
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn allow_exp_skew() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let time = now();
    let time_exp = time - 4;

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(time_exp)),
        ("iat".to_string(), json!(time)),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    test_data
        .client
        .set_clock_skew_duration(Duration::from_secs(6));

    let validated_token_set = test_data
        .client
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap();

    assert_eq!(id_token, validated_token_set.get_id_token().unwrap());
}

#[tokio::test]
async fn verifies_nbf_is_in_the_past() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let time = now();
    let nbf = time + 20;

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(time + 3600)),
        ("iat".to_string(), json!(time)),
        ("nbf".to_string(), json!(nbf)),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    let err = test_data
        .client
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(
        format!("JWT not active yet, now {}, nbf {}", time, nbf),
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn allows_nbf_skew() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let time = now();
    let nbf = time + 5;

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(time + 3600)),
        ("iat".to_string(), json!(time)),
        ("nbf".to_string(), json!(nbf)),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    test_data
        .client
        .set_clock_skew_duration(Duration::from_secs(5));

    let validated_token_set = test_data
        .client
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap();

    assert_eq!(id_token, validated_token_set.get_id_token().unwrap());
}

#[tokio::test]
async fn passes_when_auth_time_is_within_max_age() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let time = now();
    let auth_time = time - 200;

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(time + 3600)),
        ("iat".to_string(), json!(time)),
        ("auth_time".to_string(), json!(auth_time)),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    let validated_token_set = test_data
        .client
        .validate_id_token_async(token_set, None, "", Some(300), None)
        .await
        .unwrap();

    assert_eq!(id_token, validated_token_set.get_id_token().unwrap());
}

#[tokio::test]
async fn verifies_auth_time_did_not_exceed_max_age() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let time = now();
    let auth_time = time - 600;

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(time + 3600)),
        ("iat".to_string(), json!(time)),
        ("auth_time".to_string(), json!(auth_time)),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    test_data
        .client
        .set_clock_skew_duration(Duration::from_secs(5));

    let err = test_data
        .client
        .validate_id_token_async(token_set, None, "", Some(300), None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(format!("too much time has elapsed since the last End-User authentication, max_age 300, auth_time: {}, now {}", auth_time, time), err.rp_error().error.message);
}

#[tokio::test]
async fn allows_auth_time_skew() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let time = now();
    let auth_time = time - 303;

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(time + 3600)),
        ("iat".to_string(), json!(time)),
        ("auth_time".to_string(), json!(auth_time)),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    test_data
        .client
        .set_clock_skew_duration(Duration::from_secs(5));

    let validated_token_set = test_data
        .client
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap();

    assert_eq!(id_token, validated_token_set.get_id_token().unwrap());
}

#[tokio::test]
async fn verifies_auth_time_is_a_number() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let time = now();

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(time + 3600)),
        ("iat".to_string(), json!(time)),
        ("auth_time".to_string(), json!("foobar")),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    let err = test_data
        .client
        .validate_id_token_async(token_set, None, "", Some(300), None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(
        "JWT auth_time claim must be a JSON numeric value",
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn verifies_auth_time_is_present_when_require_auth_time_is_true() {
    let mock_server = MockServer::start();

    let test_data = get_test_data(&mock_server);

    let client_metadata = ClientMetadata {
        client_id: Some("with-require_auth_time".to_string()),
        require_auth_time: Some(true),
        ..Default::default()
    };

    let mut client = test_data
        .issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let time = now();

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!(client.client_id)),
        ("exp".to_string(), json!(time + 3600)),
        ("iat".to_string(), json!(time)),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    let err = client
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(
        "missing required JWT property auth_time",
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn verifies_auth_time_is_present_when_max_age_is_passed() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let time = now();

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(time + 3600)),
        ("iat".to_string(), json!(time)),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, None);

    let err = test_data
        .client
        .validate_id_token_async(token_set, None, "", Some(300), None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(
        "missing required JWT property auth_time",
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn passes_with_the_right_at_hash() {
    let access_token = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";
    let at_hash = "77QmUPtjPfzWtF2AnpK9RQ";

    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let time = now();

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(time + 3600)),
        ("iat".to_string(), json!(time)),
        ("at_hash".to_string(), json!(at_hash)),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), Some(access_token.to_string()), None);

    let validated_token_set = test_data
        .client
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap();

    assert_eq!(id_token, validated_token_set.get_id_token().unwrap());
}

#[tokio::test]
async fn validates_at_hash_presence_for_implicit_flow() {
    let access_token = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";

    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let time = now();

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(time + 3600)),
        ("iat".to_string(), json!(time)),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let params = CallbackParams {
        id_token: Some(id_token.clone()),
        access_token: Some(access_token.to_string()),
        ..Default::default()
    };

    let err = test_data
        .client
        .callback_async(None, params, None, None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(
        "missing required property at_hash",
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn validates_c_hash_presence_for_hybrid_flow() {
    let code = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";

    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let time = now();

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(time + 3600)),
        ("iat".to_string(), json!(time)),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let params = CallbackParams {
        id_token: Some(id_token.clone()),
        code: Some(code.to_string()),
        ..Default::default()
    };

    let err = test_data
        .client
        .callback_async(None, params, None, None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(
        "missing required property c_hash",
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn fapi_client_validates_s_hash_presence() {
    let code = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";
    let c_hash = "77QmUPtjPfzWtF2AnpK9RQ";

    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let time = now();

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!(test_data.fapi_client.client_id)),
        ("exp".to_string(), json!(time + 3600)),
        ("iat".to_string(), json!(time)),
        ("c_hash".to_string(), json!(c_hash)),
    ];

    let id_token = get_id_token(&test_data.jwk, "PS256", payload);

    let params = CallbackParams {
        id_token: Some(id_token.clone()),
        code: Some(code.to_string()),
        state: Some("foo".to_string()),
        ..Default::default()
    };

    let checks = OpenIDCallbackChecks {
        oauth_checks: Some(OAuthCallbackChecks {
            state: Some("foo".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let err = test_data
        .fapi_client
        .callback_async(None, params, Some(checks), None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(
        "missing required property s_hash",
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn fapi_client_checks_iat_is_fresh() {
    let code = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";
    let c_hash = "77QmUPtjPfzWtF2AnpK9RQ";
    let s_hash = "LCa0a2j_xo_5m0U8HTBBNA";

    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let time = now();
    let iat = time - 3601;

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!(test_data.fapi_client.client_id)),
        ("exp".to_string(), json!(time + 3600)),
        ("iat".to_string(), json!(iat)),
        ("c_hash".to_string(), json!(c_hash)),
        ("s_hash".to_string(), json!(s_hash)),
    ];

    let id_token = get_id_token(&test_data.jwk, "PS256", payload);

    let params = CallbackParams {
        id_token: Some(id_token.clone()),
        code: Some(code.to_string()),
        state: Some("foo".to_string()),
        ..Default::default()
    };

    let checks = OpenIDCallbackChecks {
        oauth_checks: Some(OAuthCallbackChecks {
            state: Some("foo".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let err = test_data
        .fapi_client
        .callback_async(None, params, Some(checks), None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(
        format!("JWT issued too far in the past, now {}, iat {}", time, iat),
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn validates_state_presence_when_s_hash_is_returned() {
    let s_hash = "77QmUPtjPfzWtF2AnpK9RQ";

    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let time = now();

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(time + 3600)),
        ("iat".to_string(), json!(time)),
        ("s_hash".to_string(), json!(s_hash)),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let params = CallbackParams {
        id_token: Some(id_token.clone()),
        ..Default::default()
    };

    let err = test_data
        .client
        .callback_async(None, params, None, None)
        .await
        .unwrap_err();

    assert!(err.is_type_error());
    assert_eq!(
        "cannot verify s_hash, \"checks.state\" property not provided",
        err.type_error().error.message
    );
}

#[tokio::test]
async fn validates_s_hash() {
    let state = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";
    let s_hash = "foobar";

    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let time = now();

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(time + 3600)),
        ("iat".to_string(), json!(time)),
        ("s_hash".to_string(), json!(s_hash)),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let params = CallbackParams {
        id_token: Some(id_token.clone()),
        state: Some(state.to_string()),
        ..Default::default()
    };

    let checks = OpenIDCallbackChecks {
        oauth_checks: Some(OAuthCallbackChecks {
            state: Some(state.to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let err = test_data
        .client
        .callback_async(None, params, Some(checks), None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(
        format!(
            "s_hash mismatch, expected {}, got: {}",
            generate_hash("RS256", state, None).unwrap(),
            s_hash
        ),
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn passes_with_the_right_s_hash() {
    let state = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";
    let s_hash = "77QmUPtjPfzWtF2AnpK9RQ";

    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let time = now();

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(time + 3600)),
        ("iat".to_string(), json!(time)),
        ("s_hash".to_string(), json!(s_hash)),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let params = CallbackParams {
        id_token: Some(id_token.clone()),
        state: Some(state.to_string()),
        ..Default::default()
    };

    let checks = OpenIDCallbackChecks {
        oauth_checks: Some(OAuthCallbackChecks {
            state: Some(state.to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let result = test_data
        .client
        .callback_async(None, params, Some(checks), None)
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn fails_with_the_wrong_at_hash() {
    let access_token = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";
    let at_hash = "notvalid77QmUPtjPfzWtF2AnpK9RQ";

    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let time = now();

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(time + 3600)),
        ("iat".to_string(), json!(time)),
        ("at_hash".to_string(), json!(at_hash)),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), Some(access_token.to_string()), None);

    let err = test_data
        .client
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(
        format!(
            "at_hash mismatch, expected {}, got: {}",
            generate_hash("RS256", access_token, None).unwrap(),
            at_hash
        ),
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn passes_with_the_right_c_hash() {
    let code = "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk";
    let c_hash = "LDktKdoQak3Pk0cnXxCltA";

    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let time = now();

    let payload = vec![
        ("iss".to_string(), json!(test_data.issuer.issuer)),
        ("sub".to_string(), json!("userId")),
        ("aud".to_string(), json!(test_data.client.client_id)),
        ("exp".to_string(), json!(time + 3600)),
        ("iat".to_string(), json!(time)),
        ("c_hash".to_string(), json!(c_hash)),
    ];

    let id_token = get_id_token(&test_data.jwk, "RS256", payload);

    let token_set = get_token_set(id_token.clone(), None, Some(code.to_string()));

    let validated_token_set = test_data
        .client
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap();

    assert_eq!(id_token, validated_token_set.get_id_token().unwrap());
}

#[tokio::test]
async fn fails_if_tokenset_without_id_token_is_passed_in() {
    let mock_server = MockServer::start();

    let mut test_data = get_test_data(&mock_server);

    let token_params = TokenSetParams {
        id_token: None,
        access_token: Some("tokenValue".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_params);

    let err = test_data
        .client
        .validate_id_token_async(token_set, None, "", None, None)
        .await
        .unwrap_err();

    assert!(err.is_type_error());
    assert_eq!(
        "id_token not present in TokenSet",
        err.type_error().error.message
    );
}
