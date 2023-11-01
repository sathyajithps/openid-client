use assert_json_diff::{assert_json_eq, assert_json_include};
use httpmock::{Method, MockServer};
use josekit::jwk::{alg::ec::EcCurve, Jwk};
use serde_json::{json, Value};

use crate::{
    issuer::Issuer,
    jwks::Jwks,
    tests::test_interceptors::get_default_test_interceptor,
    types::{ClientMetadata, IssuerMetadata},
};

fn get_jwks(key_use: &str, set_alg: bool) -> Jwks {
    let mut jwk = Jwk::generate_rsa_key(2048).unwrap();

    if set_alg {
        jwk.set_algorithm("RS256");
    }

    jwk.set_key_id("someid");
    jwk.set_key_use(key_use);
    jwk.set_key_type("RSA");

    Jwks::from(vec![jwk.clone()])
}

fn get_issuer(port: Option<u16>) -> Issuer {
    let issuer_metadata = IssuerMetadata {
        issuer: "https://op.example.com".to_string(),
        jwks_uri: Some("https://op.example.com/certs".to_string()),
        ..Default::default()
    };
    Issuer::new(issuer_metadata, get_default_test_interceptor(port))
}

#[tokio::test]
async fn verifies_that_keystore_is_set() {
    let issuer = get_issuer(None);

    let client_metadata = ClientMetadata {
        client_id: Some("identifer".to_string()),
        request_object_signing_alg: Some("EdDSA".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let err = client
        .request_object_async(json!({"state":"foobar"}))
        .await
        .unwrap_err();

    assert!(err.is_type_error());
    assert_eq!(
        "no keystore present for client, cannot sign using alg EdDSA",
        err.type_error().error.message
    )
}

#[tokio::test]
async fn verifies_keystore_has_the_appropriate_key() {
    let mut jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();

    jwk.set_algorithm("ES256");

    let jwks = Jwks::from(vec![jwk.clone()]);

    let issuer = get_issuer(None);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        request_object_signing_alg: Some("EdDSA".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, Some(jwks), None, false)
        .unwrap();

    let err = client
        .request_object_async(json!({"state":"foobar"}))
        .await
        .unwrap_err();

    assert!(err.is_type_error());
    assert_eq!(
        "no key to sign with found for alg EdDSA",
        err.type_error().error.message
    )
}

#[tokio::test]
async fn sign_alg_none() {
    let issuer = get_issuer(None);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        request_object_signing_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let signed = client
        .request_object_async(json!({"state":"foobar"}))
        .await
        .unwrap();

    let split = signed.split('.').collect::<Vec<&str>>();

    let header = serde_json::from_slice::<Value>(&base64_url::decode(split[0]).unwrap()).unwrap();
    let payload = serde_json::from_slice::<Value>(&base64_url::decode(split[1]).unwrap()).unwrap();

    assert_json_eq!(
        json!({
          "alg": "none",
          "typ": "oauth-authz-req+jwt",
        }),
        header
    );

    assert_json_include!(
        expected: json!({
          "iss":"identifier",
          "client_id":"identifier",
          "aud":"https://op.example.com",
          "state":"foobar",
        }),
        actual: payload
    );

    assert!(payload["jti"].is_string());
    assert!(payload["iat"].is_number());
    assert!(payload["exp"].is_number());
    assert_eq!(
        payload["iat"].as_i64().unwrap() + 300,
        payload["exp"].as_i64().unwrap()
    );
    assert!(split[2].is_empty());
}

#[tokio::test]
async fn sign_alg_hsxxx() {
    let issuer = get_issuer(None);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        client_secret: Some("atleast32byteslongforHS256mmmkay".to_string()),
        request_object_signing_alg: Some("HS256".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let signed = client
        .request_object_async(json!({"state":"foobar"}))
        .await
        .unwrap();

    let split = signed.split('.').collect::<Vec<&str>>();

    let header = serde_json::from_slice::<Value>(&base64_url::decode(split[0]).unwrap()).unwrap();
    let payload = serde_json::from_slice::<Value>(&base64_url::decode(split[1]).unwrap()).unwrap();

    assert_json_eq!(
        json!({
          "alg": "HS256",
          "typ": "oauth-authz-req+jwt",
        }),
        header
    );

    assert_json_include!(
        expected: json!({
          "iss":"identifier",
          "client_id":"identifier",
          "aud":"https://op.example.com",
          "state":"foobar",
        }),
        actual: payload
    );

    assert!(payload["jti"].is_string());
    assert!(payload["iat"].is_number());
    assert!(payload["exp"].is_number());
    assert_eq!(
        payload["iat"].as_i64().unwrap() + 300,
        payload["exp"].as_i64().unwrap()
    );
    assert!(!split[2].is_empty());
}

#[tokio::test]
async fn sign_alg_rsxxx() {
    let issuer = get_issuer(None);
    let jwks = get_jwks("sig", true);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        request_object_signing_alg: Some("RS256".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, Some(jwks), None, false)
        .unwrap();

    let signed = client
        .request_object_async(json!({"state":"foobar"}))
        .await
        .unwrap();

    let split = signed.split('.').collect::<Vec<&str>>();

    let header = serde_json::from_slice::<Value>(&base64_url::decode(split[0]).unwrap()).unwrap();
    let payload = serde_json::from_slice::<Value>(&base64_url::decode(split[1]).unwrap()).unwrap();

    assert_json_include!(
        expected: json!({
          "alg": "RS256",
          "typ": "oauth-authz-req+jwt",
        }),
        actual: header
    );

    assert!(header["kid"].is_string());

    assert_json_include!(
        expected: json!({
          "iss":"identifier",
          "client_id":"identifier",
          "aud":"https://op.example.com",
          "state":"foobar",
        }),
        actual: payload
    );

    assert!(payload["jti"].is_string());
    assert!(payload["iat"].is_number());
    assert!(payload["exp"].is_number());
    assert_eq!(
        payload["iat"].as_i64().unwrap() + 300,
        payload["exp"].as_i64().unwrap()
    );
    assert!(!split[2].is_empty());
}

#[tokio::test]
async fn encrypts_for_issuer_using_issuers_public_key_explicit_enc() {
    let mock_http_server = MockServer::start();

    mock_http_server.mock(|when, then| {
        when.method(Method::GET)
            .path("/certs")
            .header("Accept", "application/json,application/jwk-set+json");
        then.status(200)
            .body(serde_json::to_string(&get_jwks("enc", false).get_public_jwks()).unwrap());
    });

    let issuer = get_issuer(Some(mock_http_server.port()));

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        request_object_encryption_alg: Some("RSA1_5".to_string()),
        request_object_encryption_enc: Some("A128CBC-HS256".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let signed = client
        .request_object_async(json!({"state":"foobar"}))
        .await
        .unwrap();

    let split = signed.split('.').collect::<Vec<&str>>();

    let header = serde_json::from_slice::<Value>(&base64_url::decode(split[0]).unwrap()).unwrap();

    assert_json_include!(
        expected: json!({
          "alg": "RSA1_5",
          "enc": "A128CBC-HS256",
          "cty": "oauth-authz-req+jwt",
        }),
        actual: header
    );

    assert!(header["kid"].is_string());
}

#[tokio::test]
async fn encrypts_for_issuer_using_issuers_public_key_default_enc() {
    let mock_http_server = MockServer::start();

    mock_http_server.mock(|when, then| {
        when.method(Method::GET)
            .path("/certs")
            .header("Accept", "application/json,application/jwk-set+json");
        then.status(200)
            .body(serde_json::to_string(&get_jwks("enc", false).get_public_jwks()).unwrap());
    });

    let issuer = get_issuer(Some(mock_http_server.port()));

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        request_object_encryption_alg: Some("RSA1_5".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let signed = client
        .request_object_async(json!({"state":"foobar"}))
        .await
        .unwrap();

    let split = signed.split('.').collect::<Vec<&str>>();

    let header = serde_json::from_slice::<Value>(&base64_url::decode(split[0]).unwrap()).unwrap();

    assert_json_include!(
        expected: json!({
          "alg": "RSA1_5",
          "enc": "A128CBC-HS256",
          "cty": "oauth-authz-req+jwt",
        }),
        actual: header
    );

    assert!(header["kid"].is_string());
}

#[tokio::test]
async fn encrypts_for_issuer_using_pre_shared_client_secret_axxx_gcmkw() {
    let issuer = get_issuer(None);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        client_secret: Some(
            "GfsT479VMy5ZZZPquadPbN3wKzaFGYo1CTkb0IFFzDNODLEAuC2GUV3QsTye3xNQ".to_string(),
        ),
        request_object_encryption_alg: Some("A128GCMKW".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let signed = client
        .request_object_async(json!({"state":"foobar"}))
        .await
        .unwrap();

    let split = signed.split('.').collect::<Vec<&str>>();

    let header = serde_json::from_slice::<Value>(&base64_url::decode(split[0]).unwrap()).unwrap();

    assert_json_include!(
        expected: json!({
          "alg": "A128GCMKW",
          "enc": "A128CBC-HS256",
          "cty": "oauth-authz-req+jwt",
        }),
        actual: header
    );

    assert!(header.get("kid").is_none());
}

#[tokio::test]
async fn encrypts_for_issuer_using_pre_shared_client_secret_dir_a128_cbc_hs256() {
    let issuer = get_issuer(None);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        client_secret: Some(
            "GfsT479VMy5ZZZPquadPbN3wKzaFGYo1CTkb0IFFzDNODLEAuC2GUV3QsTye3xNQ".to_string(),
        ),
        request_object_encryption_alg: Some("dir".to_string()),
        request_object_encryption_enc: Some("A128CBC-HS256".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let signed = client
        .request_object_async(json!({"state":"foobar"}))
        .await
        .unwrap();

    let split = signed.split('.').collect::<Vec<&str>>();

    let header = serde_json::from_slice::<Value>(&base64_url::decode(split[0]).unwrap()).unwrap();

    assert_json_include!(
        expected: json!({
          "alg": "dir",
          "enc": "A128CBC-HS256",
          "cty": "oauth-authz-req+jwt",
        }),
        actual: header
    );

    assert!(header.get("kid").is_none());
}

#[tokio::test]
async fn encrypts_for_issuer_using_pre_shared_client_secret_dir_a192_cbc_hs384() {
    let issuer = get_issuer(None);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        client_secret: Some(
            "GfsT479VMy5ZZZPquadPbN3wKzaFGYo1CTkb0IFFzDNODLEAuC2GUV3QsTye3xNQ".to_string(),
        ),
        request_object_encryption_alg: Some("dir".to_string()),
        request_object_encryption_enc: Some("A192CBC-HS384".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let signed = client
        .request_object_async(json!({"state":"foobar"}))
        .await
        .unwrap();

    let split = signed.split('.').collect::<Vec<&str>>();

    let header = serde_json::from_slice::<Value>(&base64_url::decode(split[0]).unwrap()).unwrap();

    assert_json_include!(
        expected: json!({
          "alg": "dir",
          "enc": "A192CBC-HS384",
          "cty": "oauth-authz-req+jwt",
        }),
        actual: header
    );

    assert!(header.get("kid").is_none());
}

#[tokio::test]
async fn encrypts_for_issuer_using_pre_shared_client_secret_dir_a256_cbc_hs512() {
    let issuer = get_issuer(None);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        client_secret: Some(
            "GfsT479VMy5ZZZPquadPbN3wKzaFGYo1CTkb0IFFzDNODLEAuC2GUV3QsTye3xNQ".to_string(),
        ),
        request_object_encryption_alg: Some("dir".to_string()),
        request_object_encryption_enc: Some("A256CBC-HS512".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let signed = client
        .request_object_async(json!({"state":"foobar"}))
        .await
        .unwrap();

    let split = signed.split('.').collect::<Vec<&str>>();

    let header = serde_json::from_slice::<Value>(&base64_url::decode(split[0]).unwrap()).unwrap();

    assert_json_include!(
        expected: json!({
          "alg": "dir",
          "enc": "A256CBC-HS512",
          "cty": "oauth-authz-req+jwt",
        }),
        actual: header
    );

    assert!(header.get("kid").is_none());
}

#[tokio::test]
async fn encrypts_for_issuer_using_pre_shared_client_secret_dir_defaulted_to_a128_cbc_hs256() {
    let issuer = get_issuer(None);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        client_secret: Some(
            "GfsT479VMy5ZZZPquadPbN3wKzaFGYo1CTkb0IFFzDNODLEAuC2GUV3QsTye3xNQ".to_string(),
        ),
        request_object_encryption_alg: Some("dir".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let signed = client
        .request_object_async(json!({"state":"foobar"}))
        .await
        .unwrap();

    let split = signed.split('.').collect::<Vec<&str>>();

    let header = serde_json::from_slice::<Value>(&base64_url::decode(split[0]).unwrap()).unwrap();

    assert_json_include!(
        expected: json!({
          "alg": "dir",
          "enc": "A128CBC-HS256",
          "cty": "oauth-authz-req+jwt",
        }),
        actual: header
    );

    assert!(header.get("kid").is_none());
}

#[tokio::test]
async fn encrypts_for_issuer_using_pre_shared_client_secret_pbes2() {
    let issuer = get_issuer(None);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        client_secret: Some(
            "GfsT479VMy5ZZZPquadPbN3wKzaFGYo1CTkb0IFFzDNODLEAuC2GUV3QsTye3xNQ".to_string(),
        ),
        request_object_encryption_alg: Some("PBES2-HS256+A128KW".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let signed = client
        .request_object_async(json!({"state":"foobar"}))
        .await
        .unwrap();

    let split = signed.split('.').collect::<Vec<&str>>();

    let header = serde_json::from_slice::<Value>(&base64_url::decode(split[0]).unwrap()).unwrap();

    assert_json_include!(
        expected: json!({
          "alg": "PBES2-HS256+A128KW",
          "enc": "A128CBC-HS256",
          "cty": "oauth-authz-req+jwt",
        }),
        actual: header
    );

    assert!(header.get("kid").is_none());
}

#[tokio::test]
async fn encrypts_for_issuer_using_pre_shared_client_secret_axxx_kw() {
    let issuer = get_issuer(None);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        client_secret: Some(
            "GfsT479VMy5ZZZPquadPbN3wKzaFGYo1CTkb0IFFzDNODLEAuC2GUV3QsTye3xNQ".to_string(),
        ),
        request_object_encryption_alg: Some("A128KW".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let signed = client
        .request_object_async(json!({"state":"foobar"}))
        .await
        .unwrap();

    let split = signed.split('.').collect::<Vec<&str>>();

    let header = serde_json::from_slice::<Value>(&base64_url::decode(split[0]).unwrap()).unwrap();

    assert_json_include!(
        expected: json!({
          "alg": "A128KW",
          "enc": "A128CBC-HS256",
          "cty": "oauth-authz-req+jwt",
        }),
        actual: header
    );

    assert!(header.get("kid").is_none());
}

#[tokio::test]
async fn throws_on_non_object_inputs() {
    let issuer = get_issuer(None);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        request_object_signing_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let err = client.request_object_async(json!(true)).await.unwrap_err();

    assert!(err.is_type_error());
    assert_eq!(
        "request_object must be a plain object",
        err.type_error().error.message
    );
}

#[tokio::test]
async fn fapi_client_includes_nbf_by_default() {
    let issuer = get_issuer(None);

    let mut jwk = Jwk::generate_rsa_key(2048).unwrap();
    jwk.set_algorithm("PS256");
    jwk.set_key_use("sig");
    jwk.set_key_type("RSA");

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        request_object_signing_alg: Some("PS256".to_string()),
        token_endpoint_auth_method: Some("private_key_jwt".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(
            client_metadata,
            None,
            Some(Jwks::from(vec![jwk])),
            None,
            true,
        )
        .unwrap();

    let signed = client.request_object_async(json!({})).await.unwrap();

    let split = signed.split('.').collect::<Vec<&str>>();

    let payload = serde_json::from_slice::<Value>(&base64_url::decode(split[1]).unwrap()).unwrap();

    assert!(payload["iat"].is_number());
    assert!(payload["exp"].is_number());
    assert_eq!(
        payload["iat"].as_i64().unwrap() + 300,
        payload["exp"].as_i64().unwrap()
    );
    assert_eq!(
        payload["nbf"].as_i64().unwrap(),
        payload["iat"].as_i64().unwrap()
    )
}

#[cfg(test)]
mod ecryption_where_multiple_keys_match {
    use super::*;

    fn get_multi_jwks() -> Jwks {
        let mut jwk1 = Jwk::generate_rsa_key(2048).unwrap();

        jwk1.set_key_id("someid");
        jwk1.set_key_use("enc");
        jwk1.set_key_type("RSA");

        let mut jwk2 = Jwk::generate_rsa_key(2048).unwrap();

        jwk2.set_key_id("someid2");
        jwk2.set_key_use("enc");
        jwk2.set_key_type("RSA");

        Jwks::from(vec![jwk1, jwk2])
    }

    #[tokio::test]
    async fn encrypts_for_issuer_using_issuers_public_key_explicit_enc() {
        let mock_http_server = MockServer::start();

        mock_http_server.mock(|when, then| {
            when.method(Method::GET)
                .path("/certs")
                .header("Accept", "application/json,application/jwk-set+json");
            then.status(200)
                .body(serde_json::to_string(&get_multi_jwks().get_public_jwks()).unwrap());
        });

        let issuer = get_issuer(Some(mock_http_server.port()));

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            request_object_encryption_alg: Some("RSA1_5".to_string()),
            request_object_encryption_enc: Some("A128CBC-HS256".to_string()),
            ..Default::default()
        };

        let mut client = issuer
            .client(client_metadata, None, None, None, false)
            .unwrap();

        let signed = client
            .request_object_async(json!({"state":"foobar"}))
            .await
            .unwrap();

        let split = signed.split('.').collect::<Vec<&str>>();

        let header =
            serde_json::from_slice::<Value>(&base64_url::decode(split[0]).unwrap()).unwrap();

        assert_json_include!(
            expected: json!({
              "alg": "RSA1_5",
              "enc": "A128CBC-HS256",
              "cty": "oauth-authz-req+jwt",
            }),
            actual: header
        );

        assert!(header["kid"].is_string());
    }

    #[tokio::test]
    async fn encrypts_for_issuer_using_issuers_public_key_default_enc() {
        let mock_http_server = MockServer::start();

        mock_http_server.mock(|when, then| {
            when.method(Method::GET)
                .path("/certs")
                .header("Accept", "application/json,application/jwk-set+json");
            then.status(200)
                .body(serde_json::to_string(&get_multi_jwks().get_public_jwks()).unwrap());
        });

        let issuer = get_issuer(Some(mock_http_server.port()));

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            request_object_encryption_alg: Some("RSA1_5".to_string()),
            ..Default::default()
        };

        let mut client = issuer
            .client(client_metadata, None, None, None, false)
            .unwrap();

        let signed = client
            .request_object_async(json!({"state":"foobar"}))
            .await
            .unwrap();

        let split = signed.split('.').collect::<Vec<&str>>();

        let header =
            serde_json::from_slice::<Value>(&base64_url::decode(split[0]).unwrap()).unwrap();

        assert_json_include!(
            expected: json!({
              "alg": "RSA1_5",
              "enc": "A128CBC-HS256",
              "cty": "oauth-authz-req+jwt",
            }),
            actual: header
        );

        assert!(header["kid"].is_string());
    }
}
