use josekit::{
    jwk::{alg::ec::EcCurve, Jwk},
    jws::JwsHeader,
    jwt::JwtPayload,
};
use serde_json::{json, Value};

use crate::{
    client::Client,
    helpers::{get_jwk_thumbprint_s256, now},
    issuer::Issuer,
    jwks::jwks::CustomJwk,
    types::{CallbackParams, ClientMetadata, IssuerMetadata},
};

fn id_token(claims: Option<Vec<(String, Value)>>, exclude: bool) -> String {
    let mut jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();
    jwk.set_algorithm("ES256");
    jwk.set_key_id("someid");

    let signer = jwk.to_signer().unwrap();

    let mut payload = JwtPayload::new();
    payload
        .set_claim(
            "sub",
            Some(json!(get_jwk_thumbprint_s256(
                &serde_json::to_string(&jwk).unwrap()
            )
            .unwrap())),
        )
        .unwrap();

    if !exclude {
        payload
            .set_claim(
                "sub_jwk",
                Some(serde_json::to_value(&jwk.to_public_key().unwrap()).unwrap()),
            )
            .unwrap();
    }
    payload
        .set_claim("iss", Some(json!("https://self-issued.me")))
        .unwrap();
    let iat = now();
    let exp = iat + 7200;

    payload.set_claim("iat", Some(json!(iat))).unwrap();
    payload.set_claim("exp", Some(json!(exp))).unwrap();
    payload
        .set_claim("aud", Some(json!("https://rp.example.com/cb")))
        .unwrap();

    if let Some(c) = claims {
        for (k, v) in c {
            payload.set_claim(&k, Some(v)).unwrap();
        }
    }

    let mut header = JwsHeader::new();
    header.set_claim("alg", Some(json!("ES256"))).unwrap();
    if let Some(kid) = jwk.key_id() {
        header.set_key_id(kid);
    }

    josekit::jwt::encode_with_signer(&payload, &header, &*signer).unwrap()
}

fn get_test_data() -> (Issuer, Client) {
    let issuer_metdata = IssuerMetadata {
        authorization_endpoint: Some("openid:".to_string()),
        issuer: "https://self-issued.me".to_string(),
        registration_endpoint: Some("https://self-issued.me/registration/1.0/".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metdata, None);

    let client_metadata = ClientMetadata {
        client_id: Some("https://rp.example.com/cb".to_string()),
        response_types: Some(vec!["id_token".to_string()]),
        token_endpoint_auth_method: Some("none".to_string()),
        id_token_signed_response_alg: Some("ES256".to_string()),
        ..Default::default()
    };

    let client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    (issuer, client)
}

#[tokio::test]
async fn consumes_a_self_issued_response() {
    let (_, mut client) = get_test_data();

    let params = CallbackParams {
        id_token: Some(id_token(None, false)),
        ..Default::default()
    };

    client
        .callback_async(None, params, None, None)
        .await
        .unwrap();
}

#[tokio::test]
async fn expects_sub_jwk_to_be_in_the_id_token_claims() {
    let (_, mut client) = get_test_data();

    let params = CallbackParams {
        id_token: Some(id_token(None, true)),
        ..Default::default()
    };

    let err = client
        .callback_async(None, params, None, None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());

    let rp_error = err.rp_error();
    assert_eq!(
        "missing required JWT property sub_jwk",
        rp_error.error.message
    );
    assert!(rp_error.error.extra_data.unwrap().contains_key("jwt"));
}

#[tokio::test]
async fn expects_sub_jwk_to_be_a_public_jwk() {
    let (_, mut client) = get_test_data();

    let claims = vec![("sub_jwk".to_string(), json!("foobar"))];

    let params = CallbackParams {
        id_token: Some(id_token(Some(claims), true)),
        ..Default::default()
    };

    let err = client
        .callback_async(None, params, None, None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());

    let rp_error = err.rp_error();
    assert_eq!(
        "failed to use sub_jwk claim as an asymmetric JSON Web Key",
        rp_error.error.message
    );
    assert!(rp_error.error.extra_data.unwrap().contains_key("jwt"));
}

#[tokio::test]
async fn expects_sub_to_be_the_thumbprint_of_the_sub_jwk() {
    let (_, mut client) = get_test_data();

    let claims = vec![("sub".to_string(), json!("foo"))];

    let params = CallbackParams {
        id_token: Some(id_token(Some(claims), false)),
        ..Default::default()
    };

    let err = client
        .callback_async(None, params, None, None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());

    let rp_error = err.rp_error();
    assert_eq!(
        "failed to match the subject with sub_jwk",
        rp_error.error.message
    );
    assert!(rp_error.error.extra_data.unwrap().contains_key("jwt"));
}
