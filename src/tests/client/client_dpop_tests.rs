use std::collections::HashMap;

use httpmock::{
    Method::{GET, POST},
    MockServer,
};
use josekit::jwk::{
    alg::{ec::EcCurve, ed::EdCurve},
    Jwk,
};
use reqwest::Method;
use serde_json::{json, Value};

use crate::{
    client::Client,
    helpers::decode_jwt,
    issuer::Issuer,
    tests::test_interceptors::get_default_test_interceptor,
    tokenset::{TokenSet, TokenSetParams},
    types::{
        CallbackExtras, CallbackParams, ClientMetadata, DeviceAuthorizationExtras,
        DeviceAuthorizationParams, GrantExtras, IssuerMetadata, RefreshTokenExtras,
        RequestResourceOptions, UserinfoOptions,
    },
};

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

fn get_client(port: Option<u16>) -> (Issuer, Client) {
    let issuer_metadata = IssuerMetadata {
        issuer: "https://op.example.com".to_string(),
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        token_endpoint: Some("https://op.example.com/token".to_string()),
        introspection_endpoint: Some("https://op.example.com/token/introspect".to_string()),
        revocation_endpoint: Some("https://op.example.com/token/revoke".to_string()),
        device_authorization_endpoint: Some("https://op.example.com/device".to_string()),
        dpop_signing_alg_values_supported: Some(vec![
            "PS256".to_string(),
            "PS512".to_string(),
            "PS384".to_string(),
            "EdDSA".to_string(),
            "ES256".to_string(),
        ]),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata, get_default_test_interceptor(port));

    let client_metadata = ClientMetadata {
        client_id: Some("client".to_string()),
        token_endpoint_auth_method: Some("none".to_string()),
        ..Default::default()
    };

    let client = issuer
        .client(client_metadata, None, None, None, None)
        .unwrap();
    (issuer, client)
}

mod dpop_proof_tests {
    use crate::helpers::decode_jwt;

    use super::*;

    #[test]
    fn must_be_passed_a_payload_object() {
        let (_, client) = get_client(None);
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
        let (_, client) = get_client(None);

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
        let (_, client) = get_client(None);
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
        let (_, mut client) = get_client(None);

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
    let mock_http_server = MockServer::start();

    let _server = mock_http_server.mock(|when, then| {
        when.method(GET).path("/me").matches(|req| {
            let binding = req.headers.clone().unwrap();
            let (_, val) = binding
                .iter()
                .find(|(k, _)| k.to_lowercase() == "dpop")
                .unwrap();

            let decoded = decode_jwt(val).unwrap();

            decoded.payload.claim("ath").is_some()
        });
        then.status(200).body(r#"{"sub":"foo"}"#);
    });

    let (_, mut client) = get_client(Some(mock_http_server.port()));

    let token_params = TokenSetParams {
        access_token: Some("foo".to_string()),
        ..Default::default()
    };
    let token_set = TokenSet::new(token_params);

    let options = UserinfoOptions {
        dpop: Some(get_rsa_private_key()),
        ..Default::default()
    };

    client.userinfo_async(&token_set, options).await.unwrap();
}

#[tokio::test]
async fn handles_dpop_nonce_in_userinfo() {
    let mock_http_server = MockServer::start();

    let _1 = mock_http_server.mock(|when, then| {
        when.method(GET).path("/me").matches(|req| {
            if let Some(qp) = &req.query_params {
                if qp
                    .iter()
                    .find(|(x, y)| x == "only_for_fail_test" && y == "doesntaffecttest")
                    .is_some()
                {
                    return false;
                }
            }
            let binding = req.headers.clone().unwrap();
            let (_, val) = binding
                .iter()
                .find(|(k, _)| k.to_lowercase() == "dpop")
                .unwrap();

            let decoded = decode_jwt(val).unwrap();

            decoded.payload.claim("nonce").is_none()
        });
        then.status(401)
            .header("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\"")
            .header("DPoP-Nonce", "eyJ7S_zG.eyJH0-Z.HX4w-7v");
    });

    let _2 = mock_http_server.mock(|when, then| {
        when.method(GET).path("/me").matches(|req| {
            if let Some(qp) = &req.query_params {
                if qp
                    .iter()
                    .find(|(x, y)| x == "only_for_fail_test" && y == "doesntaffecttest")
                    .is_some()
                {
                    return false;
                }
            }
            let binding = req.headers.clone().unwrap();
            let (_, val) = binding
                .iter()
                .find(|(k, _)| k.to_lowercase() == "dpop")
                .unwrap();

            let decoded = decode_jwt(val).unwrap();

            if let Some(Value::String(nonce)) = decoded.payload.claim("nonce") {
                return nonce == "eyJ7S_zG.eyJH0-Z.HX4w-7v";
            }
            false
        });
        then.status(200).body(
            r#"{
            "sub":"foo"
          }"#,
        );
    });

    let _3 = mock_http_server.mock(|when, then| {
        when.method(GET).path("/me").matches(|req| {
            if let Some(qp) = &req.query_params {
                if qp
                    .iter()
                    .find(|(x, y)| x == "only_for_fail_test" && y == "doesntaffecttest")
                    .is_none()
                {
                    return false;
                }
            }
            let binding = req.headers.clone().unwrap();
            let (_, val) = binding
                .iter()
                .find(|(k, _)| k.to_lowercase() == "dpop")
                .unwrap();

            let decoded = decode_jwt(val).unwrap();

            if let Some(Value::String(nonce)) = decoded.payload.claim("nonce") {
                return nonce == "eyJ7S_zG.eyJH0-Z.HX4w-7v";
            }
            false
        });
        then.status(400)
            .header("WWW-Authenticate", "DPoP error=\"invalid_dpop_proof\"");
    });

    let (_, mut client) = get_client(Some(mock_http_server.port()));

    let token_params = TokenSetParams {
        access_token: Some("foo".to_string()),
        ..Default::default()
    };
    let token_set = TokenSet::new(token_params);

    let key = get_rsa_private_key();

    let options = UserinfoOptions {
        dpop: Some(key.clone()),
        ..Default::default()
    };

    client.userinfo_async(&token_set, options).await.unwrap();

    let options2 = UserinfoOptions {
        dpop: Some(key.clone()),
        ..Default::default()
    };

    client.userinfo_async(&token_set, options2).await.unwrap();

    let mut other = HashMap::new();

    other.insert("only_for_fail_test".to_string(), json!("doesntaffecttest"));

    let options3 = UserinfoOptions {
        dpop: Some(key.clone()),
        params: Some(other),
        ..Default::default()
    };

    let err = client
        .userinfo_async(&token_set, options3)
        .await
        .unwrap_err();

    assert!(err.is_op_error());
    assert_eq!("invalid_dpop_proof", err.op_error().error.error);
}

#[tokio::test]
async fn handles_dpop_nonce_in_grant() {
    let mock_http_server = MockServer::start();

    let _1 = mock_http_server.mock(|when, then| {
        when.method(POST).path("/token").matches(|req| {
            let body_str = String::from_utf8(req.body.clone().unwrap().to_vec()).unwrap();
            if body_str.contains("fail_case=shouldnotaffect") {
                return false;
            }
            let binding = req.headers.clone().unwrap();
            let (_, val) = binding
                .iter()
                .find(|(k, _)| k.to_lowercase() == "dpop")
                .unwrap();

            let decoded = decode_jwt(val).unwrap();

            decoded.payload.claim("nonce").is_none()
        });
        then.status(400)
            .body(r#"{"error":"use_dpop_nonce"}"#)
            .header("DPoP-Nonce", "eyJ7S_zG.eyJH0-Z.HX4w-7v");
    });

    let _2 = mock_http_server.mock(|when, then| {
        when.method(POST).path("/token").matches(|req| {
            let body_str = String::from_utf8(req.body.clone().unwrap().to_vec()).unwrap();
            if body_str.contains("fail_case=shouldnotaffect") {
                return false;
            }

            let binding = req.headers.clone().unwrap();
            let (_, val) = binding
                .iter()
                .find(|(k, _)| k.to_lowercase() == "dpop")
                .unwrap();

            let decoded = decode_jwt(val).unwrap();

            if let Some(Value::String(nonce)) = decoded.payload.claim("nonce") {
                return nonce == "eyJ7S_zG.eyJH0-Z.HX4w-7v";
            }
            false
        });
        then.status(200).body(
            r#"{
            "access_token":"foo"
          }"#,
        );
    });

    let _3 = mock_http_server.mock(|when, then| {
        when.method(POST).path("/token").matches(|req| {
            let body_str = String::from_utf8(req.body.clone().unwrap().to_vec()).unwrap();
            if !body_str.contains("fail_case=shouldnotaffect") {
                return false;
            }
            let binding = req.headers.clone().unwrap();
            let (_, val) = binding
                .iter()
                .find(|(k, _)| k.to_lowercase() == "dpop")
                .unwrap();

            let decoded = decode_jwt(val).unwrap();

            if let Some(Value::String(nonce)) = decoded.payload.claim("nonce") {
                return nonce == "eyJ7S_zG.eyJH0-Z.HX4w-7v";
            }
            false
        });
        then.status(400).body(r#"{"error":"invalid_dpop_proof"}"#);
    });

    let (_, mut client) = get_client(Some(mock_http_server.port()));

    let key = get_rsa_private_key();

    let extras = GrantExtras {
        dpop: Some(key.clone()),
        ..Default::default()
    };

    let mut body = HashMap::new();

    body.insert("grant_type".to_string(), json!("client_credentials"));
    client
        .grant_async(body.clone(), extras.clone(), true)
        .await
        .unwrap();

    client
        .grant_async(body.clone(), extras.clone(), true)
        .await
        .unwrap();

    body.insert("fail_case".to_string(), json!("shouldnotaffect"));

    let err = client.grant_async(body, extras, true).await.unwrap_err();

    assert!(err.is_op_error());
    assert_eq!("invalid_dpop_proof", err.op_error().error.error);
}

#[tokio::test]
async fn handles_dpop_nonce_in_request_resource() {
    let mock_http_server = MockServer::start();

    let _1 = mock_http_server.mock(|when, then| {
        when.method(GET).path("/resource").matches(|req| {
            let body_str = String::from_utf8(req.body.clone().unwrap().to_vec()).unwrap();
            if body_str.contains("fail_case_should_not_affect") {
                return false;
            }
            let binding = req.headers.clone().unwrap();
            let (_, val) = binding
                .iter()
                .find(|(k, _)| k.to_lowercase() == "dpop")
                .unwrap();

            let decoded = decode_jwt(val).unwrap();

            decoded.payload.claim("nonce").is_none()
        });
        then.status(401)
            .header("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\"")
            .header("DPoP-Nonce", "eyJ7S_zG.eyJH0-Z.HX4w-7v");
    });

    let _2 = mock_http_server.mock(|when, then| {
        when.method(GET).path("/resource").matches(|req| {
            let body_str = String::from_utf8(req.body.clone().unwrap().to_vec()).unwrap();
            if body_str.contains("fail_case_should_not_affect") {
                return false;
            }
            let binding = req.headers.clone().unwrap();
            let (_, val) = binding
                .iter()
                .find(|(k, _)| k.to_lowercase() == "dpop")
                .unwrap();

            let decoded = decode_jwt(val).unwrap();

            if let Some(Value::String(nonce)) = decoded.payload.claim("nonce") {
                return nonce == "eyJ7S_zG.eyJH0-Z.HX4w-7v";
            }
            false
        });
        then.status(200).body(
            r#"{
            "sub":"foo"
          }"#,
        );
    });

    let _3 = mock_http_server.mock(|when, then| {
        when.method(GET).path("/resource").matches(|req| {
            let body_str = String::from_utf8(req.body.clone().unwrap().to_vec()).unwrap();
            if !body_str.contains("fail_case_should_not_affect") {
                return false;
            }
            let binding = req.headers.clone().unwrap();
            let (_, val) = binding
                .iter()
                .find(|(k, _)| k.to_lowercase() == "dpop")
                .unwrap();

            let decoded = decode_jwt(val).unwrap();

            if let Some(Value::String(nonce)) = decoded.payload.claim("nonce") {
                return nonce == "eyJ7S_zG.eyJH0-Z.HX4w-7v";
            }
            false
        });
        then.status(400)
            .header("WWW-Authenticate", "DPoP error=\"invalid_dpop_proof\"");
    });

    let (_, mut client) = get_client(Some(mock_http_server.port()));

    let key = get_rsa_private_key();

    let options = RequestResourceOptions {
        dpop: Some(key.clone()),
        ..Default::default()
    };

    client
        .request_resource_async(
            "https://rs.example.com/resource",
            "foo",
            None,
            true,
            options,
        )
        .await
        .unwrap();

    let options2 = RequestResourceOptions {
        dpop: Some(key.clone()),
        ..Default::default()
    };

    client
        .request_resource_async(
            "https://rs.example.com/resource",
            "foo",
            None,
            true,
            options2,
        )
        .await
        .unwrap();

    let options3 = RequestResourceOptions {
        dpop: Some(key.clone()),
        body: Some("fail_case_should_not_affect".to_string()),
        ..Default::default()
    };

    let err = client
        .request_resource_async(
            "https://rs.example.com/resource",
            "foo",
            None,
            true,
            options3,
        )
        .await
        .unwrap_err();

    assert!(err.is_op_error());
    assert_eq!("invalid_dpop_proof", err.op_error().error.error);
}

#[tokio::test]
async fn is_enabled_for_request_resource() {
    let mock_http_server = MockServer::start();

    let _server = mock_http_server.mock(|when, then| {
        when.method(POST)
            .path("/resource")
            .matches(|req| {
                let mut no_content_length = false;
                let mut no_transfer_encoding = false;

                if let Some(headers) = &req.headers {
                    no_content_length = headers
                        .iter()
                        .find(|x| x.0 == "content-length" && x.1.parse::<u64>().is_ok())
                        .is_none();

                    no_transfer_encoding = headers
                        .iter()
                        .find(|x| x.0 == "transfer-encoding")
                        .is_none();
                }

                no_content_length && no_transfer_encoding
            })
            .matches(|req| {
                let binding = req.headers.clone().unwrap();
                let (_, val) = binding
                    .iter()
                    .find(|(k, _)| k.to_lowercase() == "dpop")
                    .unwrap();

                let decoded = decode_jwt(val).unwrap();

                decoded.payload.claim("ath").is_some()
            });
        then.status(200).body(r#"{"sub":"foo"}"#);
    });

    let (_, mut client) = get_client(Some(mock_http_server.port()));

    let options = RequestResourceOptions {
        dpop: Some(get_rsa_private_key()),
        method: Method::POST,
        ..Default::default()
    };

    client
        .request_resource_async(
            "https://rs.example.com/resource",
            "foo",
            None,
            true,
            options,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn is_enabled_for_grant() {
    let mock_http_server = MockServer::start();

    let _server = mock_http_server.mock(|when, then| {
        when.method(POST).path("/token").matches(|req| {
            let binding = req.headers.clone().unwrap();
            let header = binding.iter().find(|(k, _)| k.to_lowercase() == "dpop");

            header.is_some()
        });
        then.status(200).body(r#"{"access_token":"foo"}"#);
    });

    let (_, mut client) = get_client(Some(mock_http_server.port()));

    let extra = GrantExtras {
        dpop: Some(get_rsa_private_key()),
        ..Default::default()
    };

    let mut body = HashMap::new();

    body.insert("grant_type".to_string(), json!("client_credentials"));

    client.grant_async(body, extra, true).await.unwrap();
}

#[tokio::test]
async fn is_enabled_for_refresh() {
    let mock_http_server = MockServer::start();

    let _server = mock_http_server.mock(|when, then| {
        when.method(POST).path("/token").matches(|req| {
            let binding = req.headers.clone().unwrap();
            let header = binding.iter().find(|(k, _)| k.to_lowercase() == "dpop");

            header.is_some()
        });
        then.status(200).body(r#"{"access_token":"foo"}"#);
    });

    let (_, mut client) = get_client(Some(mock_http_server.port()));

    let token_params = TokenSetParams {
        refresh_token: Some("foo".to_string()),
        ..Default::default()
    };
    let token_set = TokenSet::new(token_params);

    let params = RefreshTokenExtras {
        dpop: Some(get_rsa_private_key()),
        client_assertion_payload: None,
        exchange_body: None,
    };

    client.refresh_async(token_set, Some(params)).await.unwrap();
}

#[tokio::test]
async fn is_enabled_for_oauthcallback() {
    let mock_http_server = MockServer::start();

    let _server = mock_http_server.mock(|when, then| {
        when.method(POST).path("/token").matches(|req| {
            let binding = req.headers.clone().unwrap();
            let header = binding.iter().find(|(k, _)| k.to_lowercase() == "dpop");

            header.is_some()
        });
        then.status(200).body(r#"{"access_token":"foo"}"#);
    });

    let (_, mut client) = get_client(Some(mock_http_server.port()));

    let params = CallbackParams {
        code: Some("code".to_string()),
        ..Default::default()
    };

    let extras = CallbackExtras {
        dpop: Some(get_rsa_private_key()),
        client_assertion_payload: None,
        exchange_body: None,
    };

    client
        .oauth_callback_async(None, params, None, Some(extras))
        .await
        .unwrap();
}

#[tokio::test]
async fn is_enabled_for_callback() {
    let mock_http_server = MockServer::start();

    let _server = mock_http_server.mock(|when, then| {
        when.method(POST).path("/token").matches(|req| {
            let binding = req.headers.clone().unwrap();
            let header = binding.iter().find(|(k, _)| k.to_lowercase() == "dpop");

            header.is_some()
        });
        then.status(200).body(r#"{"access_token":"foo"}"#);
    });

    let (_, mut client) = get_client(Some(mock_http_server.port()));

    let params = CallbackParams {
        code: Some("code".to_string()),
        ..Default::default()
    };

    let extras = CallbackExtras {
        dpop: Some(get_rsa_private_key()),
        client_assertion_payload: None,
        exchange_body: None,
    };

    client
        .callback_async(None, params, None, Some(extras))
        .await
        .unwrap_err();
}

#[tokio::test]
async fn is_enabled_for_deviceauthorization() {
    let mock_http_server = MockServer::start();

    let _server = mock_http_server.mock(|when, then| {
        when.method(POST).path("/device").matches(|req| {
            let binding = req.headers.clone().unwrap();
            let header = binding.iter().find(|(k, _)| k.to_lowercase() == "dpop");

            header.is_none()
        });
        then.status(200).body(
            r#"{
            "expires_in": 60,
            "device_code": "foo",
            "user_code": "foo",
            "verification_uri": "foo",
            "interval": 1
          }"#,
        );
    });

    let (_, mut client) = get_client(Some(mock_http_server.port()));

    let extras = DeviceAuthorizationExtras {
        dpop: Some(get_rsa_private_key()),
        ..Default::default()
    };

    let mut handle = client
        .device_authorization_async(DeviceAuthorizationParams::default(), Some(extras))
        .await
        .unwrap();

    let _server2 = mock_http_server.mock(|when, then| {
        when.method(POST).path("/token").matches(|req| {
            let binding = req.headers.clone().unwrap();
            let header = binding.iter().find(|(k, _)| k.to_lowercase() == "dpop");

            header.is_some()
        });
        then.status(200).body(r#"{"access_token":"foo"}"#);
    });

    handle.grant_async().await.unwrap();
}
