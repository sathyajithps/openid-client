#[cfg(test)]
mod no_implicit_key_ids {
    use crate::{
        client::Client,
        helpers::decode_jwt,
        issuer::Issuer,
        tests::test_interceptors::get_default_test_interceptor,
        types::{ClientMetadata, ClientRegistrationOptions, IssuerMetadata},
    };
    use httpmock::{Method, MockServer};
    use josekit::jwk::{alg::ec::EcCurve, Jwk};
    use serde_json::{json, Value};

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
        let issuer = Issuer::new(IssuerMetadata::default(), None);
        let jwks = get_no_kid_jwks();

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            token_endpoint_auth_method: Some("private_key_jwt".to_string()),
            token_endpoint_auth_signing_alg: Some("ES256".to_string()),
            ..Default::default()
        };

        let client = issuer
            .client(client_metadata, None, Some(jwks), None, false)
            .unwrap();

        let request = client.auth_for("token", None).unwrap();

        let binding = request.form.unwrap();

        let jwt = binding.get("client_assertion").unwrap().as_str().unwrap();

        let decoded_jwt = decode_jwt(jwt).unwrap();

        assert_eq!("ES256", decoded_jwt.header.algorithm().unwrap());
        assert!(decoded_jwt.header.key_id().is_none());
    }

    #[tokio::test]
    async fn is_not_added_to_request_objects() {
        let issuer = Issuer::new(IssuerMetadata::default(), None);
        let jwks = get_no_kid_jwks();

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            request_object_signing_alg: Some("ES256".to_string()),
            ..Default::default()
        };

        let mut client = issuer
            .client(client_metadata, None, Some(jwks), None, false)
            .unwrap();

        let jwt = client.request_object_async(json!({})).await.unwrap();

        let decoded_jwt = decode_jwt(&jwt).unwrap();

        assert_eq!("ES256", decoded_jwt.header.algorithm().unwrap());
        assert!(decoded_jwt.header.key_id().is_none());
    }

    #[tokio::test]
    async fn is_not_added_to_dynamic_registration_requests() {
        let mock_http_server = MockServer::start();

        let _server = mock_http_server.mock(|when, then| {
            when.method(Method::POST)
                .matches(|req| {
                    let body = serde_json::from_slice::<Value>(&req.body.clone().unwrap()).unwrap();

                    let jwks = &body["jwks"]["keys"].as_array().unwrap();

                    let first = jwks.first().unwrap();

                    first.is_object() && first.get("kid").is_none()
                })
                .path("/client/registration");
            then.status(201).body(
                r#"{
                "client_id":"identifier",
                "token_endpoint_auth_method":"private_key_jwt"
              }"#,
            );
        });

        let issuer_metadata = IssuerMetadata {
            issuer: "https://op.example.com".to_string(),
            registration_endpoint: Some("https://op.example.com/client/registration".to_string()),
            ..Default::default()
        };
        let issuer = Issuer::new(issuer_metadata, None);
        let jwks = get_no_kid_jwks();

        let reg_opt = ClientRegistrationOptions {
            jwks: Some(jwks),
            ..Default::default()
        };

        let client_metadata = ClientMetadata {
            token_endpoint_auth_method: Some("private_key_jwt".to_string()),
            ..Default::default()
        };

        let _ = Client::register_async(
            &issuer,
            client_metadata,
            Some(reg_opt),
            get_default_test_interceptor(Some(mock_http_server.port())),
            false,
        )
        .await
        .unwrap();
    }
}
