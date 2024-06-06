use std::collections::HashMap;

use josekit::jwk::{
    alg::{ec::EcCurve, ed::EdCurve},
    Jwk,
};
use serde_json::json;

use crate::{
    client::Client,
    http_client::DefaultHttpClient,
    issuer::Issuer,
    tokenset::{TokenSet, TokenSetParams},
    types::{
        grant_params::GrantParams, http_client::HttpMethod, CallbackExtras, CallbackParams,
        ClientMetadata, DeviceAuthorizationExtras, DeviceAuthorizationParams, GrantExtras,
        IssuerMetadata, OAuthCallbackParams, OpenIdCallbackParams,
        PushedAuthorizationRequestExtras, RefreshTokenExtras, RequestResourceOptions,
        RequestResourceParams, UserinfoOptions,
    },
};

use crate::tests::test_http_client::{TestHttpClient, TestHttpReqRes};

fn get_ec_private_key() -> Jwk {
    let mut jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();
    jwk.set_algorithm("ES256");
    jwk.set_key_type("EC");
    jwk
}

fn get_okp_private_key() -> Jwk {
    let mut jwk = Jwk::generate_ed_key(EdCurve::Ed25519).unwrap();
    jwk.set_algorithm("EdDSA");
    jwk.set_key_type("OKP");
    jwk
}

fn get_rsa_private_key() -> Jwk {
    let mut jwk = Jwk::generate_rsa_key(2048).unwrap();
    jwk.set_algorithm("PS256");
    jwk.set_key_type("RSA");
    jwk
}

fn get_client() -> (Issuer, Client) {
    let issuer_metadata = IssuerMetadata {
        issuer: "https://op.example.com".to_string(),
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        token_endpoint: Some("https://op.example.com/token".to_string()),
        introspection_endpoint: Some("https://op.example.com/token/introspect".to_string()),
        revocation_endpoint: Some("https://op.example.com/token/revoke".to_string()),
        device_authorization_endpoint: Some("https://op.example.com/device".to_string()),
        pushed_authorization_request_endpoint: Some("https://op.example.com/par".to_string()),
        dpop_signing_alg_values_supported: Some(vec![
            "PS256".to_string(),
            "PS512".to_string(),
            "PS384".to_string(),
            "EdDSA".to_string(),
            "ES256".to_string(),
        ]),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("client".to_string()),
        token_endpoint_auth_method: Some("none".to_string()),
        redirect_uri: Some("https://rp.example.com/cb".to_string()),
        ..Default::default()
    };

    let client = issuer.client(client_metadata, None, None, None).unwrap();
    (issuer, client)
}

mod dpop_proof_tests {
    use crate::helpers::decode_jwt;

    use super::*;

    #[test]
    fn must_be_passed_a_payload_object() {
        let (_, client) = get_client();
        let err = client
            .dpop_proof(json!("foo"), &get_ec_private_key(), None)
            .unwrap_err();
        assert!(err.is_type_error());
        assert_eq!(
            "payload must be a plain object",
            err.type_error().error.message
        );
    }

    #[test]
    fn dpop_proof_without_ath() {
        let (_, client) = get_client();

        let proof_rsa = client
            .dpop_proof(
                json!({"htu":"foo", "htm": "bar", "baz": true}),
                &get_rsa_private_key(),
                None,
            )
            .unwrap();

        let decoded_rsa = decode_jwt(&proof_rsa).unwrap();

        assert_eq!(
            "dpop+jwt",
            decoded_rsa.header.claim("typ").unwrap().as_str().unwrap()
        );

        let jwk_claim_rsa = decoded_rsa.header.claim("jwk").unwrap();

        assert!(jwk_claim_rsa.get("kty").is_some());
        assert!(jwk_claim_rsa.get("e").is_some());
        assert!(jwk_claim_rsa.get("n").is_some());

        assert!(decoded_rsa.payload.claim("iat").is_some());
        assert!(decoded_rsa.payload.claim("jti").is_some());
        assert_eq!(
            "foo",
            decoded_rsa.payload.claim("htu").unwrap().as_str().unwrap()
        );
        assert_eq!(
            "bar",
            decoded_rsa.payload.claim("htm").unwrap().as_str().unwrap()
        );
        assert_eq!(
            true,
            decoded_rsa.payload.claim("baz").unwrap().as_bool().unwrap()
        );

        let proof_ec = client
            .dpop_proof(json!({}), &get_ec_private_key(), None)
            .unwrap();

        let decoded_ec = decode_jwt(&proof_ec).unwrap();

        let jwk_claim_ec = decoded_ec.header.claim("jwk").unwrap();

        assert!(jwk_claim_ec.get("kty").is_some());
        assert!(jwk_claim_ec.get("x").is_some());
        assert!(jwk_claim_ec.get("y").is_some());
        assert!(jwk_claim_ec.get("crv").is_some());

        let proof_okp = client
            .dpop_proof(json!({}), &get_okp_private_key(), None)
            .unwrap();

        let decoded_okp = decode_jwt(&proof_okp).unwrap();

        let jwk_claim_okp = decoded_okp.header.claim("jwk").unwrap();

        assert!(jwk_claim_okp.get("kty").is_some());
        assert!(jwk_claim_okp.get("x").is_some());
        assert!(jwk_claim_okp.get("crv").is_some());
    }

    #[test]
    fn dpop_proof_with_ath() {
        let (_, client) = get_client();
        let proof = client
            .dpop_proof(json!({}), &get_ec_private_key(), Some(&"foo".to_string()))
            .unwrap();

        let decoded = decode_jwt(&proof).unwrap();

        assert_eq!(
            "LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564",
            decoded.payload.claim("ath").unwrap().as_str().unwrap()
        );
    }

    #[test]
    fn validates_using_dpop_supported_values() {
        let (_, mut client) = get_client();

        if let Some(iss) = &mut client.issuer {
            iss.dpop_signing_alg_values_supported = Some(vec!["EdDSA".to_string()]);
        }

        let err = client
            .dpop_proof(json!({}), &get_ec_private_key(), None)
            .unwrap_err();

        assert!(err.is_type_error());
        assert_eq!(
            "unsupported DPoP signing algorithm",
            err.type_error().error.message
        );
    }
}

#[tokio::test]
async fn is_enabled_for_userinfo() {
    let http_client = TestHttpReqRes::new("https://op.example.com/me")
        .assert_request_method(HttpMethod::GET)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header("authorization", vec!["DPoP foo".to_string()])
        .assert_dpop_ath()
        .set_response_body(r#"{"sub":"foo"}"#)
        .set_response_status_code(200)
        .build();

    let (_, mut client) = get_client();

    let token_params = TokenSetParams {
        access_token: Some("foo".to_string()),
        ..Default::default()
    };
    let token_set = TokenSet::new(token_params);

    let key = get_rsa_private_key();
    let options = UserinfoOptions {
        dpop: Some(&key),
        ..Default::default()
    };

    client
        .userinfo_async(&token_set, options, &http_client)
        .await
        .unwrap();
}

#[tokio::test]
async fn handles_dpop_nonce_in_userinfo() {
    let http_client = TestHttpClient::new()
        .add(
            TestHttpReqRes::new("https://op.example.com/me")
                .assert_request_method(HttpMethod::GET)
                .assert_request_header("accept", vec!["application/json".to_string()])
                .assert_request_header("authorization", vec!["DPoP foo".to_string()])
                .assert_dpop_nonce_not_present()
                .set_response_status_code(401)
                .set_response_www_authenticate_header(r#"DPoP error="use_dpop_nonce""#)
                .set_response_dpop_nonce_header("eyJ7S_zG.eyJH0-Z.HX4w-7v"),
        )
        .add(
            TestHttpReqRes::new("https://op.example.com/me")
                .assert_request_method(HttpMethod::GET)
                .assert_request_header("accept", vec!["application/json".to_string()])
                .assert_request_header("authorization", vec!["DPoP foo".to_string()])
                .assert_dpop_nonce_value("eyJ7S_zG.eyJH0-Z.HX4w-7v")
                .set_response_body(r#"{"sub":"foo"}"#),
        )
        .add(
            TestHttpReqRes::new("https://op.example.com/me")
                .assert_request_method(HttpMethod::GET)
                .assert_request_header("accept", vec!["application/json".to_string()])
                .assert_request_header("authorization", vec!["DPoP foo".to_string()])
                .assert_dpop_nonce_value("eyJ7S_zG.eyJH0-Z.HX4w-7v")
                .set_response_body(r#"{"sub":"foo"}"#),
        )
        .add(
            TestHttpReqRes::new("https://op.example.com/me")
                .assert_request_method(HttpMethod::GET)
                .assert_request_header("accept", vec!["application/json".to_string()])
                .assert_request_header("authorization", vec!["DPoP foo".to_string()])
                .assert_dpop_nonce_value("eyJ7S_zG.eyJH0-Z.HX4w-7v")
                .set_response_www_authenticate_header(r#"DPoP error="invalid_dpop_proof""#)
                .set_response_status_code(400),
        );

    let (_, mut client) = get_client();

    let token_params = TokenSetParams {
        access_token: Some("foo".to_string()),
        ..Default::default()
    };
    let token_set = TokenSet::new(token_params);

    let key = get_rsa_private_key();

    let options = UserinfoOptions {
        dpop: Some(&key),
        ..Default::default()
    };

    let _ = client
        .userinfo_async(&token_set, options, &http_client)
        .await;

    let options2 = UserinfoOptions {
        dpop: Some(&key),
        ..Default::default()
    };

    let _ = client
        .userinfo_async(&token_set, options2, &http_client)
        .await;

    let options3 = UserinfoOptions {
        dpop: Some(&key),
        ..Default::default()
    };

    let _ = client
        .userinfo_async(&token_set, options3, &http_client)
        .await;

    let options4 = UserinfoOptions {
        dpop: Some(&key),
        ..Default::default()
    };

    let err = client
        .userinfo_async(&token_set, options4, &http_client)
        .await
        .unwrap_err();

    assert!(err.is_op_error());
    assert_eq!("invalid_dpop_proof", err.op_error().error.error);
}

#[tokio::test]
async fn handles_dpop_nonce_in_grant() {
    let http_client = TestHttpClient::new()
        .add(
            TestHttpReqRes::new("https://op.example.com/token")
                .assert_request_method(HttpMethod::POST)
                .assert_request_header("accept", vec!["application/json".to_string()])
                .assert_request_header(
                    "content-type",
                    vec!["application/x-www-form-urlencoded".to_string()],
                )
                .assert_request_header("content-length", vec!["46".to_string()])
                .assert_request_body("client_id=client&grant_type=client_credentials")
                .assert_dpop_nonce_not_present()
                .set_response_status_code(400)
                .set_response_content_type_header("application/json")
                .set_response_body(r#"{"error":"use_dpop_nonce"}"#)
                .set_response_dpop_nonce_header("eyJ7S_zG.eyJH0-Z.HX4w-7v"),
        )
        .add(
            TestHttpReqRes::new("https://op.example.com/token")
                .assert_request_method(HttpMethod::POST)
                .assert_request_header("accept", vec!["application/json".to_string()])
                .assert_request_header(
                    "content-type",
                    vec!["application/x-www-form-urlencoded".to_string()],
                )
                .assert_request_header("content-length", vec!["46".to_string()])
                .assert_request_body("client_id=client&grant_type=client_credentials")
                .assert_dpop_nonce_value("eyJ7S_zG.eyJH0-Z.HX4w-7v")
                .set_response_content_type_header("application/json")
                .set_response_body(
                    r#"{
                    "access_token":"foo"
                  }"#,
                ),
        )
        .add(
            TestHttpReqRes::new("https://op.example.com/token")
                .assert_request_method(HttpMethod::POST)
                .assert_request_header("accept", vec!["application/json".to_string()])
                .assert_request_header(
                    "content-type",
                    vec!["application/x-www-form-urlencoded".to_string()],
                )
                .assert_request_header("content-length", vec!["46".to_string()])
                .assert_request_body("client_id=client&grant_type=client_credentials")
                .assert_dpop_nonce_value("eyJ7S_zG.eyJH0-Z.HX4w-7v")
                .set_response_content_type_header("application/json")
                .set_response_body(
                    r#"{
            "sub":"foo"
          }"#,
                ),
        )
        .add(
            TestHttpReqRes::new("https://op.example.com/token")
                .assert_request_method(HttpMethod::POST)
                .assert_request_header("accept", vec!["application/json".to_string()])
                .assert_request_header(
                    "content-type",
                    vec!["application/x-www-form-urlencoded".to_string()],
                )
                .assert_request_header("content-length", vec!["46".to_string()])
                .assert_request_body("client_id=client&grant_type=client_credentials")
                .assert_dpop_nonce_value("eyJ7S_zG.eyJH0-Z.HX4w-7v")
                .set_response_body(r#"{"error":"invalid_dpop_proof"}"#)
                .set_response_status_code(400),
        );

    let (_, mut client) = get_client();

    let key = get_rsa_private_key();

    let extras = GrantExtras {
        dpop: Some(&key),
        ..Default::default()
    };

    let mut body = HashMap::new();

    body.insert("grant_type".to_string(), "client_credentials".to_owned());

    let _ = client
        .grant_async(
            &http_client,
            GrantParams::default()
                .body(body.clone())
                .extras(extras.clone()),
        )
        .await;

    let _ = client
        .grant_async(
            &http_client,
            GrantParams::default()
                .body(body.clone())
                .extras(extras.clone()),
        )
        .await;

    let err = client
        .grant_async(
            &http_client,
            GrantParams::default().body(body).extras(extras),
        )
        .await
        .unwrap_err();

    assert!(err.is_op_error());
    assert_eq!("invalid_dpop_proof", err.op_error().error.error);
}

#[tokio::test]
async fn handles_dpop_nonce_in_request_resource() {
    let http_client = TestHttpClient::new()
        .add(
            TestHttpReqRes::new("https://rs.example.com/resource")
                .assert_request_method(HttpMethod::GET)
                .assert_request_header("authorization", vec!["DPoP foo".to_string()])
                .assert_dpop_nonce_not_present()
                .set_response_status_code(401)
                .set_response_www_authenticate_header(r#"DPoP error="use_dpop_nonce""#)
                .set_response_dpop_nonce_header("eyJ7S_zG.eyJH0-Z.HX4w-7v"),
        )
        .add(
            TestHttpReqRes::new("https://rs.example.com/resource")
                .assert_request_method(HttpMethod::GET)
                .assert_dpop_nonce_value("eyJ7S_zG.eyJH0-Z.HX4w-7v")
                .assert_request_header("authorization", vec!["DPoP foo".to_string()])
                .set_response_content_type_header("application/json")
                .assert_dpop_nonce_value("eyJ7S_zG.eyJH0-Z.HX4w-7v")
                .set_response_body(r#"{"sub":"foo"}"#),
        )
        .add(
            TestHttpReqRes::new("https://rs.example.com/resource")
                .assert_request_method(HttpMethod::GET)
                .assert_request_header("authorization", vec!["DPoP foo".to_string()])
                .assert_dpop_nonce_value("eyJ7S_zG.eyJH0-Z.HX4w-7v")
                .set_response_www_authenticate_header(r#"DPoP error="invalid_dpop_proof""#)
                .set_response_status_code(400),
        );

    let (_, mut client) = get_client();

    let key = get_rsa_private_key();

    let options = RequestResourceOptions {
        dpop: Some(&key),
        ..Default::default()
    };

    let params = RequestResourceParams::default()
        .resource_url("https://rs.example.com/resource")
        .access_token("foo")
        .retry(true)
        .options(options);

    let _ = client.request_resource_async(params, &http_client).await;

    let options2 = RequestResourceOptions {
        dpop: Some(&key),
        ..Default::default()
    };

    let params = RequestResourceParams::default()
        .resource_url("https://rs.example.com/resource")
        .access_token("foo")
        .retry(true)
        .options(options2);

    let _ = client.request_resource_async(params, &http_client).await;

    let options3 = RequestResourceOptions {
        dpop: Some(&key),
        ..Default::default()
    };

    let params = RequestResourceParams::default()
        .resource_url("https://rs.example.com/resource")
        .access_token("foo")
        .retry(true)
        .options(options3);

    let err = client
        .request_resource_async(params, &http_client)
        .await
        .unwrap_err();

    assert!(err.is_op_error());
    let op_error = err.op_error();
    assert_eq!("invalid_dpop_proof", op_error.error.error);
    assert_eq!(400, op_error.response.unwrap().status_code);
}

#[tokio::test]
async fn is_enabled_for_request_resource() {
    let http_client = TestHttpReqRes::new("https://rs.example.com/resource")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header("authorization", vec!["DPoP foo".to_string()])
        .assert_dpop_ath()
        .set_response_body(r#"{"sub":"foo"}"#)
        .build();

    let (_, mut client) = get_client();

    let key = get_rsa_private_key();

    let options = RequestResourceOptions {
        dpop: Some(&key),
        method: HttpMethod::POST,
        ..Default::default()
    };

    let params = RequestResourceParams::default()
        .resource_url("https://rs.example.com/resource")
        .access_token("foo")
        .retry(true)
        .options(options);

    client
        .request_resource_async(params, &http_client)
        .await
        .unwrap();
}

#[tokio::test]
async fn returns_error_if_access_token_is_dpop_bound_but_dpop_was_not_passed_in() {
    let issuer_metadata = IssuerMetadata {
        issuer: "https://op.example.com".to_string(),
        pushed_authorization_request_endpoint: Some("https://op.example.com/par".to_string()),
        dpop_signing_alg_values_supported: Some(vec![
            "PS256".to_string(),
            "PS512".to_string(),
            "PS384".to_string(),
            "EdDSA".to_string(),
            "ES256".to_string(),
        ]),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("client".to_string()),
        token_endpoint_auth_method: Some("none".to_string()),
        redirect_uri: Some("https://rp.example.com/cb".to_string()),
        dpop_bound_access_tokens: Some(true),
        ..Default::default()
    };

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let options = RequestResourceOptions {
        dpop: None,
        ..Default::default()
    };

    let params = RequestResourceParams::default()
        .resource_url("https://rs.example.com/resource")
        .access_token("foo")
        .retry(true)
        .options(options);

    let err = client
        .request_resource_async(params, &DefaultHttpClient)
        .await
        .unwrap_err();

    assert!(err.is_type_error());

    assert_eq!("DPoP key not set", err.type_error().error.message);
}

#[tokio::test]
async fn is_enabled_for_grant() {
    let http_client = TestHttpReqRes::new("https://op.example.com/token")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header(
            "content-type",
            vec!["application/x-www-form-urlencoded".to_string()],
        )
        .assert_request_header("content-length", vec!["46".to_string()])
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_body("grant_type=client_credentials&client_id=client")
        .assert_dpop()
        .set_response_body(r#"{"access_token":"foo"}"#)
        .build();

    let (_, mut client) = get_client();

    let key = get_rsa_private_key();
    let extras = GrantExtras {
        dpop: Some(&key),
        ..Default::default()
    };

    let mut body = HashMap::new();

    body.insert("grant_type".to_string(), "client_credentials".to_owned());

    let params = GrantParams::default().body(body).extras(extras);

    client.grant_async(&http_client, params).await.unwrap();
}

#[tokio::test]
async fn is_enabled_for_refresh() {
    let http_client = TestHttpReqRes::new("https://op.example.com/token")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header(
            "content-type",
            vec!["application/x-www-form-urlencoded".to_string()],
        )
        .assert_request_header("content-length", vec!["59".to_string()])
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_body("grant_type=refresh_token&client_id=client&refresh_token=foo")
        .assert_dpop()
        .set_response_body(r#"{"access_token":"foo"}"#)
        .build();

    let (_, mut client) = get_client();

    let token_params = TokenSetParams {
        refresh_token: Some("foo".to_string()),
        ..Default::default()
    };
    let token_set = TokenSet::new(token_params);

    let key = get_rsa_private_key();
    let params = RefreshTokenExtras {
        dpop: Some(&key),
        client_assertion_payload: None,
        exchange_body: None,
    };

    client
        .refresh_async(token_set, Some(params), &http_client)
        .await
        .unwrap();
}

#[tokio::test]
async fn is_enabled_for_oauthcallback() {
    let http_client = TestHttpReqRes::new("https://op.example.com/token")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header(
            "content-type",
            vec!["application/x-www-form-urlencoded".to_string()],
        )
        .assert_request_header("content-length", vec!["56".to_string()])
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_body("grant_type=authorization_code&client_id=client&code=code")
        .assert_dpop()
        .set_response_body(r#"{"access_token":"foo"}"#)
        .build();

    let (_, mut client) = get_client();

    let params = CallbackParams {
        code: Some("code".to_string()),
        ..Default::default()
    };

    let extras = CallbackExtras {
        dpop: Some(get_rsa_private_key()),
        client_assertion_payload: None,
        exchange_body: None,
    };

    let params = OAuthCallbackParams::default()
        .parameters(params)
        .extras(extras);

    client
        .oauth_callback_async(&http_client, params)
        .await
        .unwrap();
}

#[tokio::test]
async fn is_enabled_for_callback() {
    let http_client = TestHttpReqRes::new("https://op.example.com/token")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header(
            "content-type",
            vec!["application/x-www-form-urlencoded".to_string()],
        )
        .assert_request_header("content-length", vec!["56".to_string()])
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_body("grant_type=authorization_code&client_id=client&code=code")
        .assert_dpop()
        .set_response_body(r#"{"access_token":"foo"}"#)
        .build();

    let (_, mut client) = get_client();

    let params = CallbackParams {
        code: Some("code".to_string()),
        ..Default::default()
    };

    let extras = CallbackExtras {
        dpop: Some(get_rsa_private_key()),
        client_assertion_payload: None,
        exchange_body: None,
    };

    let params = OpenIdCallbackParams::default()
        .parameters(params)
        .extras(extras);

    client
        .callback_async(&http_client, params)
        .await
        .unwrap_err();
}

#[tokio::test]
async fn is_enabled_for_deviceauthorization() {
    let http_client = TestHttpClient::new()
        .add(
            TestHttpReqRes::new("https://op.example.com/device")
                .assert_request_method(HttpMethod::POST)
                .assert_request_header("accept", vec!["application/json".to_string()])
                .assert_request_header(
                    "content-type",
                    vec!["application/x-www-form-urlencoded".to_string()],
                )
                .assert_request_header("content-length", vec!["95".to_string()])
                .assert_request_body("client_id=client&redirect_uri=https%3A%2F%2Frp.example.com%2Fcb&response_type=code&scope=openid")
                .set_response_content_type_header("application/json")
                .set_response_body(r#"{"expires_in": 60,"device_code": "foo","user_code": "foo","verification_uri": "foo","interval": 1}"#),
        )
        .add(
            TestHttpReqRes::new("https://op.example.com/token")
                .assert_request_method(HttpMethod::POST)
                .assert_request_header(
                    "content-type",
                    vec!["application/x-www-form-urlencoded".to_string()],
                )
                .assert_request_header("content-length", vec!["98".to_string()])
                .assert_request_header("accept", vec!["application/json".to_string()])
                .assert_request_body("client_id=client&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=foo")
                .assert_dpop()
                .set_response_body(r#"{"access_token":"foo"}"#),
        );

    let (_, mut client) = get_client();

    let extras = DeviceAuthorizationExtras {
        dpop: Some(get_rsa_private_key()),
        ..Default::default()
    };

    let mut handle = client
        .device_authorization_async(
            DeviceAuthorizationParams::default(),
            Some(extras),
            &http_client,
        )
        .await
        .unwrap();

    handle.grant_async(&http_client).await.unwrap();
}

#[tokio::test]
async fn is_enabled_for_pushed_authorization() {
    let http_client = TestHttpReqRes::new("https://op.example.com/par")
    .assert_request_method(HttpMethod::POST)
    .assert_request_header("accept", vec!["application/json".to_string()])
    .assert_request_header(
        "content-type",
        vec!["application/x-www-form-urlencoded".to_string()],
    )
    .assert_dpop()
    .assert_request_header("content-length", vec!["95".to_string()])
    .assert_request_body("client_id=client&redirect_uri=https%3A%2F%2Frp.example.com%2Fcb&response_type=code&scope=openid")
    .set_response_status_code(201)
    .set_response_body(r#"{"expires_in":60,"request_uri":"urn:ietf:params:oauth:request_uri:random"}"#)
    .build();

    let (_, mut client) = get_client();

    let key = get_rsa_private_key();
    let extras = PushedAuthorizationRequestExtras {
        dpop: Some(&key),
        client_assertion_payload: None,
    };
    client
        .pushed_authorization_request_async(None, Some(extras), &http_client)
        .await
        .unwrap();
}
