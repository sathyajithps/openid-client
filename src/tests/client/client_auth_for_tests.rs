#[cfg(test)]
mod when_none {
    use std::collections::HashMap;

    use crate::{
        issuer::Issuer,
        types::{ClientMetadata, HttpRequest, IssuerMetadata},
    };

    #[test]
    fn returns_the_body_http_options() {
        let issuer = Issuer::new(IssuerMetadata::default());

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            client_secret: Some("secure".to_string()),
            token_endpoint_auth_method: Some("none".to_string()),
            ..Default::default()
        };

        let client = issuer.client(client_metadata, None, None, None).unwrap();

        let request = client.auth_for("token", None).unwrap();

        let mut expected_request = HttpRequest::new();
        let mut form: HashMap<String, String> = HashMap::new();

        form.insert("client_id".to_string(), "identifier".to_owned());

        expected_request = expected_request.form(form);

        assert_eq!(
            expected_request.expectations.bearer,
            request.expectations.bearer
        );
        assert_eq!(expected_request.body, request.body);
        assert_eq!(
            expected_request.expectations.body,
            request.expectations.body
        );
        assert_eq!(
            expected_request.expectations.status_code,
            request.expectations.status_code
        );
        assert_eq!(expected_request.headers, request.headers);
        assert_eq!(expected_request.method, request.method);
        assert_eq!(expected_request.mtls, request.mtls);
        assert_eq!(
            expected_request.expectations.json_body,
            request.expectations.json_body
        );
        assert_eq!(expected_request.url, request.url);
    }
}

#[cfg(test)]
mod when_client_secret_post {

    use std::collections::HashMap;

    use crate::{
        helpers::form_url_encoded_to_string_map,
        issuer::Issuer,
        types::{ClientMetadata, HttpRequest, IssuerMetadata},
    };

    #[test]
    fn returns_the_body_http_options() {
        let issuer = Issuer::new(IssuerMetadata::default());

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            client_secret: Some("secure".to_string()),
            token_endpoint_auth_method: Some("client_secret_post".to_string()),
            ..Default::default()
        };

        let client = issuer.client(client_metadata, None, None, None).unwrap();

        let request = client.auth_for("token", None).unwrap();

        let mut expected_request = HttpRequest::new();
        let mut form: HashMap<String, String> = HashMap::new();

        form.insert("client_id".to_string(), "identifier".to_owned());
        form.insert("client_secret".to_string(), "secure".to_owned());

        expected_request = expected_request.form(form);

        assert_eq!(
            expected_request.expectations.bearer,
            request.expectations.bearer
        );
        assert_eq!(
            form_url_encoded_to_string_map(&expected_request.body.unwrap()),
            form_url_encoded_to_string_map(&request.body.unwrap())
        );
        assert_eq!(
            expected_request.expectations.body,
            request.expectations.body
        );
        assert_eq!(
            expected_request.expectations.status_code,
            request.expectations.status_code
        );
        assert_eq!(expected_request.headers, request.headers);
        assert_eq!(expected_request.method, request.method);
        assert_eq!(expected_request.mtls, request.mtls);
        assert_eq!(
            expected_request.expectations.json_body,
            request.expectations.json_body
        );
        assert_eq!(expected_request.url, request.url);
    }

    #[test]
    fn requires_client_secret_to_be_set() {
        let issuer = Issuer::new(IssuerMetadata::default());

        let client_metadata = ClientMetadata {
            client_id: Some("an:identifier".to_string()),
            token_endpoint_auth_method: Some("client_secret_post".to_string()),
            ..Default::default()
        };

        let client = issuer.client(client_metadata, None, None, None).unwrap();

        let err = client.auth_for("token", None).unwrap_err();

        assert!(err.is_type_error());

        let error = err.type_error();

        assert_eq!(
            "client_secret_post client authentication method requires a client_secret",
            error.error.message
        );
    }

    #[test]
    fn allows_client_secret_to_be_empty_string() {
        let issuer = Issuer::new(IssuerMetadata::default());

        let client_metadata = ClientMetadata {
            client_id: Some("an:identifier".to_string()),
            client_secret: Some("".to_string()),
            token_endpoint_auth_method: Some("client_secret_post".to_string()),
            ..Default::default()
        };

        let client = issuer.client(client_metadata, None, None, None).unwrap();

        let req = client.auth_for("token", None).unwrap();

        let form = req
            .body
            .map(|b| form_url_encoded_to_string_map(&b))
            .unwrap();

        assert_eq!("an:identifier", form.get("client_id").unwrap());
        assert_eq!("", form.get("client_secret").unwrap());
    }
}

#[cfg(test)]
mod when_client_secret_basic {

    use crate::{
        issuer::Issuer,
        types::{ClientMetadata, HttpRequest, IssuerMetadata},
    };

    #[test]
    fn it_is_the_default() {
        let issuer = Issuer::new(IssuerMetadata::default());

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            client_secret: Some("secure".to_string()),
            ..Default::default()
        };

        let client = issuer.client(client_metadata, None, None, None).unwrap();

        let request = client.auth_for("token", None).unwrap();

        let mut expected_request = HttpRequest::new();

        expected_request.headers.insert(
            "authorization".to_string(),
            vec!["Basic aWRlbnRpZmllcjpzZWN1cmU=".to_string()],
        );

        assert_eq!(
            expected_request.expectations.bearer,
            request.expectations.bearer
        );
        assert_eq!(expected_request.body, request.body);
        assert_eq!(
            expected_request.expectations.body,
            request.expectations.body
        );
        assert_eq!(
            expected_request.expectations.status_code,
            request.expectations.status_code
        );
        assert_eq!(expected_request.headers, request.headers);
        assert_eq!(expected_request.method, request.method);
        assert_eq!(expected_request.mtls, request.mtls);
        assert_eq!(
            expected_request.expectations.json_body,
            request.expectations.json_body
        );
        assert_eq!(expected_request.url, request.url);
    }

    #[test]
    fn works_with_non_text_characters() {
        let issuer = Issuer::new(IssuerMetadata::default());

        let client_metadata = ClientMetadata {
            client_id: Some("an:identifier".to_string()),
            client_secret: Some("some secure & non-standard secret".to_string()),
            ..Default::default()
        };

        let client = issuer.client(client_metadata, None, None, None).unwrap();

        let request = client.auth_for("token", None).unwrap();

        let mut expected_request = HttpRequest::new();

        expected_request.headers.insert(
            "authorization".to_string(),
            vec![
                "Basic YW4lM0FpZGVudGlmaWVyOnNvbWUrc2VjdXJlKyUyNitub24tc3RhbmRhcmQrc2VjcmV0"
                    .to_string(),
            ],
        );

        assert_eq!(
            expected_request.expectations.bearer,
            request.expectations.bearer
        );
        assert_eq!(expected_request.body, request.body);
        assert_eq!(
            expected_request.expectations.body,
            request.expectations.body
        );
        assert_eq!(
            expected_request.expectations.status_code,
            request.expectations.status_code
        );
        assert_eq!(expected_request.headers, request.headers);
        assert_eq!(expected_request.method, request.method);
        assert_eq!(expected_request.mtls, request.mtls);
        assert_eq!(
            expected_request.expectations.json_body,
            request.expectations.json_body
        );
        assert_eq!(expected_request.url, request.url);
    }

    #[test]
    fn requires_client_secret_to_be_set() {
        let issuer = Issuer::new(IssuerMetadata::default());

        let client_metadata = ClientMetadata {
            client_id: Some("an:identifier".to_string()),
            ..Default::default()
        };

        let client = issuer.client(client_metadata, None, None, None).unwrap();

        let err = client.auth_for("token", None).unwrap_err();

        assert!(err.is_type_error());

        let error = err.type_error();

        assert_eq!(
            "client_secret_basic client authentication method requires a client_secret",
            error.error.message
        );
    }

    #[test]
    fn allows_client_secret_to_be_empty_string() {
        let issuer = Issuer::new(IssuerMetadata::default());

        let client_metadata = ClientMetadata {
            client_id: Some("an:identifier".to_string()),
            client_secret: Some("".to_string()),
            ..Default::default()
        };

        let client = issuer.client(client_metadata, None, None, None).unwrap();

        let req = client.auth_for("token", None).unwrap();

        assert_eq!(
            "Basic YW4lM0FpZGVudGlmaWVyOg==",
            req.headers.get("authorization").unwrap().first().unwrap()
        );
    }
}

#[cfg(test)]
mod when_client_secret_jwt {
    use std::collections::HashMap;

    use assert_json_diff::assert_json_eq;
    use serde_json::{json, Value};

    use crate::{
        helpers::form_url_encoded_to_string_map,
        issuer::Issuer,
        types::{ClientMetadata, HttpRequest, IssuerMetadata},
    };

    fn get_auth_and_auth_with_assertion_payload() -> (HttpRequest, HttpRequest) {
        let issuer_metadata = IssuerMetadata {
            issuer: "https://op.example.com".to_string(),
            token_endpoint: Some("https://op.example.com/token".to_string()),
            token_endpoint_auth_signing_alg_values_supported: Some(vec![
                "HS256".to_string(),
                "HS384".to_string(),
            ]),
            ..Default::default()
        };

        let issuer = Issuer::new(issuer_metadata);

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            client_secret: Some(
                "its gotta be a long secret and i mean at least 32 characters".to_string(),
            ),
            token_endpoint_auth_method: Some("client_secret_jwt".to_string()),
            ..Default::default()
        };

        let client = issuer.client(client_metadata, None, None, None).unwrap();

        let mut payload: HashMap<String, Value> = HashMap::new();

        payload.insert("aud".to_string(), json!("https://rp.example.com"));

        (
            client.auth_for("token", None).unwrap(),
            client.auth_for("token", Some(&payload)).unwrap(),
        )
    }

    #[test]
    fn promises_a_body() {
        let (auth, _) = get_auth_and_auth_with_assertion_payload();

        assert!(auth.body.is_some());

        let form = auth
            .body
            .map(|b| form_url_encoded_to_string_map(&b))
            .unwrap();

        assert_eq!(
            form.get("client_assertion_type").map(|x| x.as_str()),
            Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
        );

        assert!(form.contains_key("client_assertion"),);
    }

    #[test]
    fn has_a_predefined_payload_properties() {
        let (auth, _) = get_auth_and_auth_with_assertion_payload();

        let split_assertion: Vec<String> = auth
            .body
            .map(|b| form_url_encoded_to_string_map(&b))
            .unwrap()
            .get("client_assertion")
            .unwrap()
            .to_string()
            .split('.')
            .map(|s| s.to_string())
            .collect();

        let payload = serde_json::from_slice::<HashMap<String, Value>>(
            &base64_url::decode(&split_assertion[1]).unwrap(),
        )
        .unwrap();

        for k in payload.keys() {
            assert!(&["iat", "exp", "jti", "iss", "sub", "aud"].contains(&k.as_str()))
        }

        assert_eq!(Some(&json!("identifier")), payload.get("iss"));
        assert_eq!(Some(&json!("identifier")), payload.get("sub"));
        assert!(payload.get("jti").unwrap().is_string());
        assert!(payload.get("iat").unwrap().is_number());
        assert!(payload.get("exp").unwrap().is_number());

        let aud =
            serde_json::from_value::<Vec<String>>(payload.get("aud").unwrap().clone()).unwrap();

        assert!(aud.contains(&"https://op.example.com/token".to_string()));
        assert!(aud.contains(&"https://op.example.com".to_string()));
    }

    #[test]
    fn can_use_client_assertion_payload_to_change_the_default_payload_properties() {
        let (_, auth_with_assertion_payload) = get_auth_and_auth_with_assertion_payload();

        let split_assertion: Vec<String> = auth_with_assertion_payload
            .body
            .map(|b| form_url_encoded_to_string_map(&b))
            .unwrap()
            .get("client_assertion")
            .unwrap()
            .to_string()
            .split('.')
            .map(|s| s.to_string())
            .collect();

        let payload = serde_json::from_slice::<HashMap<String, Value>>(
            &base64_url::decode(&split_assertion[1]).unwrap(),
        )
        .unwrap();

        for k in payload.keys() {
            assert!(&["iat", "exp", "jti", "iss", "sub", "aud"].contains(&k.as_str()))
        }

        assert_eq!(Some(&json!("identifier")), payload.get("iss"));
        assert_eq!(Some(&json!("identifier")), payload.get("sub"));
        assert!(payload.get("jti").unwrap().is_string());
        assert!(payload.get("iat").unwrap().is_number());
        assert!(payload.get("exp").unwrap().is_number());
        assert_json_eq!(
            payload.get("aud").unwrap(),
            &json!("https://rp.example.com")
        );
    }

    #[test]
    fn has_the_right_header_properties() {
        let (auth, _) = get_auth_and_auth_with_assertion_payload();

        let split_assertion: Vec<String> = auth
            .body
            .map(|b| form_url_encoded_to_string_map(&b))
            .unwrap()
            .get("client_assertion")
            .unwrap()
            .split('.')
            .map(|s| s.to_string())
            .collect();

        let header = serde_json::from_slice::<HashMap<String, Value>>(
            &base64_url::decode(&split_assertion[0]).unwrap(),
        )
        .unwrap();

        assert!(header.contains_key("alg"));

        assert_json_eq!(header.get("alg").unwrap(), json!("HS256"));
    }

    #[test]
    fn requires_client_secret_to_be_set_on_the_client() {
        let issuer_metadata = IssuerMetadata {
            issuer: "https://op.example.com".to_string(),
            token_endpoint: Some("https://op.example.com/token".to_string()),
            ..Default::default()
        };

        let issuer = Issuer::new(issuer_metadata);

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            token_endpoint_auth_method: Some("client_secret_jwt".to_string()),
            token_endpoint_auth_signing_alg: Some("HS256".to_string()),
            ..Default::default()
        };

        let client = issuer.client(client_metadata, None, None, None).unwrap();

        let error = client.auth_for("token", None).unwrap_err();

        assert!(error.is_type_error());

        assert_eq!(
            error.type_error().error.message,
            "client_secret is required"
        );
    }
}

#[cfg(test)]
mod when_private_key_jwt {

    #[cfg(test)]
    mod works_as_expected {
        use std::collections::HashMap;

        use assert_json_diff::assert_json_eq;
        use josekit::jwk::{alg::ec::EcCurve, Jwk};
        use serde_json::{json, Value};

        use crate::{
            helpers::{form_url_encoded_to_string_map, generate_random},
            issuer::Issuer,
            jwks::Jwks,
            types::{ClientMetadata, HttpRequest, IssuerMetadata},
        };

        fn get_client() -> (HttpRequest, HttpRequest) {
            let issuer_metadata = IssuerMetadata {
                issuer: "https://op.example.com".to_string(),
                token_endpoint: Some("https://op.example.com/token".to_string()),
                token_endpoint_auth_signing_alg_values_supported: Some(vec![
                    "ES256".to_string(),
                    "ES384".to_string(),
                ]),
                ..Default::default()
            };

            let issuer = Issuer::new(issuer_metadata);

            let client_metadata = ClientMetadata {
                client_id: Some("identifier".to_string()),
                token_endpoint_auth_method: Some("private_key_jwt".to_string()),
                ..Default::default()
            };

            let mut jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();

            jwk.set_algorithm("ES256");
            jwk.set_key_id(generate_random(None));

            let jwks = Jwks::from(vec![jwk]);

            let client = issuer
                .client(client_metadata, Some(jwks), None, None)
                .unwrap();

            let mut payload: HashMap<String, Value> = HashMap::new();

            payload.insert("aud".to_string(), json!("https://rp.example.com"));

            (
                client.auth_for("token", None).unwrap(),
                client.auth_for("token", Some(&payload)).unwrap(),
            )
        }

        #[test]
        fn promises_a_body() {
            let (auth, _) = get_client();

            assert!(auth.body.is_some());

            let form = auth
                .body
                .map(|b| form_url_encoded_to_string_map(&b))
                .unwrap();

            assert_eq!(
                form.get("client_assertion_type").map(|x| x.as_str()),
                Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
            );

            assert!(form.contains_key("client_assertion"),);
        }

        #[test]
        fn has_a_predefined_payload_properties() {
            let (auth, _) = get_client();

            let split_assertion: Vec<String> = auth
                .body
                .map(|b| form_url_encoded_to_string_map(&b))
                .unwrap()
                .get("client_assertion")
                .unwrap()
                .to_string()
                .split('.')
                .map(|s| s.to_string())
                .collect();

            let payload = serde_json::from_slice::<HashMap<String, Value>>(
                &base64_url::decode(&split_assertion[1]).unwrap(),
            )
            .unwrap();

            for k in payload.keys() {
                assert!(&["iat", "exp", "jti", "iss", "sub", "aud"].contains(&k.as_str()))
            }

            assert_eq!(Some(&json!("identifier")), payload.get("iss"));
            assert_eq!(Some(&json!("identifier")), payload.get("sub"));
            assert!(payload.get("jti").unwrap().is_string());
            assert!(payload.get("iat").unwrap().is_number());
            assert!(payload.get("exp").unwrap().is_number());

            let aud =
                serde_json::from_value::<Vec<String>>(payload.get("aud").unwrap().clone()).unwrap();

            assert!(aud.contains(&"https://op.example.com/token".to_string()));
            assert!(aud.contains(&"https://op.example.com".to_string()));
        }

        #[test]
        fn can_use_client_assertion_payload_to_change_the_default_payload_properties() {
            let (_, auth_with_assertion_payload) = get_client();

            let split_assertion: Vec<String> = auth_with_assertion_payload
                .body
                .map(|b| form_url_encoded_to_string_map(&b))
                .unwrap()
                .get("client_assertion")
                .unwrap()
                .to_string()
                .split('.')
                .map(|s| s.to_string())
                .collect();

            let payload = serde_json::from_slice::<HashMap<String, Value>>(
                &base64_url::decode(&split_assertion[1]).unwrap(),
            )
            .unwrap();

            for k in payload.keys() {
                assert!(&["iat", "exp", "jti", "iss", "sub", "aud"].contains(&k.as_str()))
            }

            assert_eq!(Some(&json!("identifier")), payload.get("iss"));
            assert_eq!(Some(&json!("identifier")), payload.get("sub"));
            assert!(payload.get("jti").unwrap().is_string());
            assert!(payload.get("iat").unwrap().is_number());
            assert!(payload.get("exp").unwrap().is_number());
            assert_json_eq!(
                payload.get("aud").unwrap(),
                &json!("https://rp.example.com")
            );
        }

        #[test]
        fn has_the_right_header_properties() {
            let (auth, _) = get_client();

            let split_assertion: Vec<String> = auth
                .body
                .map(|b| form_url_encoded_to_string_map(&b))
                .unwrap()
                .get("client_assertion")
                .unwrap()
                .split('.')
                .map(|s| s.to_string())
                .collect();

            let header = serde_json::from_slice::<HashMap<String, Value>>(
                &base64_url::decode(&split_assertion[0]).unwrap(),
            )
            .unwrap();

            assert!(header.contains_key("alg"));
            assert!(header.contains_key("kid"));

            assert_json_eq!(header.get("alg").unwrap(), json!("ES256"));
        }

        #[test]
        fn requires_jwks_to_be_provided_when_the_client_was_instantiated() {
            let issuer_metadata = IssuerMetadata {
                issuer: "https://op.example.com".to_string(),
                token_endpoint: Some("https://op.example.com/token".to_string()),
                ..Default::default()
            };

            let issuer = Issuer::new(issuer_metadata);

            let client_metadata = ClientMetadata {
                client_id: Some("identifier".to_string()),
                token_endpoint_auth_method: Some("private_key_jwt".to_string()),
                token_endpoint_auth_signing_alg: Some("RS256".to_string()),
                ..Default::default()
            };

            let client = issuer.client(client_metadata, None, None, None).unwrap();

            let error = client.auth_for("token", None).unwrap_err();

            assert!(error.is_type_error());
            assert_eq!(
                "no client jwks provided for signing a client assertion with",
                error.type_error().error.message
            );
        }
    }

    #[cfg(test)]
    mod alg_resolution {
        use josekit::jwk::{alg::ec::EcCurve, Jwk};

        use crate::{
            helpers::generate_random,
            issuer::Issuer,
            jwks::Jwks,
            types::{ClientMetadata, IssuerMetadata},
        };

        #[test]
        fn rejects_when_no_valid_key_is_present() {
            let issuer_metadata = IssuerMetadata {
                issuer: "https://op.example.com".to_string(),
                token_endpoint: Some("https://op.example.com/token".to_string()),
                ..Default::default()
            };

            let issuer = Issuer::new(issuer_metadata);

            let client_metadata = ClientMetadata {
                client_id: Some("identifier".to_string()),
                token_endpoint_auth_method: Some("private_key_jwt".to_string()),
                token_endpoint_auth_signing_alg: Some("EdDSA".to_string()),
                ..Default::default()
            };

            let mut jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();

            jwk.set_algorithm("ES256");
            jwk.set_key_id(generate_random(None));

            let jwks = Jwks::from(vec![jwk]);

            let client = issuer
                .client(client_metadata, Some(jwks), None, None)
                .unwrap();

            let error = client.auth_for("token", None).unwrap_err();

            assert_eq!(
                "no key found in client jwks to sign a client assertion with using alg EdDSA",
                error.rp_error().error.message
            );
        }
    }
}
