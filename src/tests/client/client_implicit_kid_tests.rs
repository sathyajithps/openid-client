#[cfg(test)]
mod no_implicit_key_ids {

    use crate::tests::test_http_client::TestHttpReqRes;

    use crate::{
        client::Client,
        helpers::{decode_jwt, form_url_encoded_to_string_map},
        http_client::DefaultHttpClient,
        issuer::Issuer,
        types::{ClientMetadata, ClientRegistrationOptions, HttpMethod, IssuerMetadata},
    };
    use josekit::jwk::{alg::ec::EcCurve, Jwk};
    use serde_json::json;

    use crate::jwks::{jwks::CustomJwk, Jwks};

    fn get_no_kid_jwks() -> Jwks {
        let mut jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();

        jwk.set_algorithm("ES256");

        if !jwk.is_private_key() {
            panic!();
        }

        Jwks::from(vec![jwk])
    }

    #[test]
    fn is_not_added_to_client_assertions() {
        let issuer = Issuer::new(IssuerMetadata::default());
        let jwks = get_no_kid_jwks();

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            token_endpoint_auth_method: Some("private_key_jwt".to_string()),
            token_endpoint_auth_signing_alg: Some("ES256".to_string()),
            ..Default::default()
        };

        let client = issuer
            .client(client_metadata, Some(jwks), None, None)
            .unwrap();

        let request = client.auth_for("token", None).unwrap();

        let binding = request
            .body
            .map(|b| form_url_encoded_to_string_map(&b))
            .unwrap();

        let jwt = binding.get("client_assertion").unwrap();

        let decoded_jwt = decode_jwt(jwt).unwrap();

        assert_eq!("ES256", decoded_jwt.header.algorithm().unwrap());
        assert!(decoded_jwt.header.key_id().is_none());
    }

    #[tokio::test]
    async fn is_not_added_to_request_objects() {
        let issuer = Issuer::new(IssuerMetadata::default());
        let jwks = get_no_kid_jwks();

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            request_object_signing_alg: Some("ES256".to_string()),
            ..Default::default()
        };

        let mut client = issuer
            .client(client_metadata, Some(jwks), None, None)
            .unwrap();

        let jwt = client
            .request_object_async(&DefaultHttpClient, json!({}))
            .await
            .unwrap();

        let decoded_jwt = decode_jwt(&jwt).unwrap();

        assert_eq!("ES256", decoded_jwt.header.algorithm().unwrap());
        assert!(decoded_jwt.header.key_id().is_none());
    }

    #[tokio::test]
    async fn is_not_added_to_dynamic_registration_requests() {
        let jwks = get_no_kid_jwks();

        let jwks_pub = serde_json::to_value(&jwks.get_public_jwks()).unwrap();

        let http_client = TestHttpReqRes::new("https://op.example.com/client/registration")
            .assert_request_method(HttpMethod::POST)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .assert_request_header("content-length", vec!["207".to_string()])
            .assert_request_header("content-type", vec!["application/json".to_string()])
            .assert_request_body(
                serde_json::to_string(
                    &json!({"token_endpoint_auth_method":"private_key_jwt","jwks": jwks_pub}),
                )
                .unwrap(),
            )
            .set_response_body(
                r#"{"client_id":"identifier","token_endpoint_auth_method":"private_key_jwt"}"#,
            )
            .set_response_status_code(201)
            .build();

        let issuer_metadata = IssuerMetadata {
            issuer: "https://op.example.com".to_string(),
            registration_endpoint: Some("https://op.example.com/client/registration".to_string()),
            ..Default::default()
        };
        let issuer = Issuer::new(issuer_metadata);

        let reg_opt = ClientRegistrationOptions {
            jwks: Some(jwks),
            ..Default::default()
        };

        let client_metadata = ClientMetadata {
            token_endpoint_auth_method: Some("private_key_jwt".to_string()),
            ..Default::default()
        };

        let _ = Client::register_async(&http_client, &issuer, client_metadata, Some(reg_opt), None)
            .await
            .unwrap();
    }
}
