use crate::tests::test_http_client::TestHttpReqRes;
use crate::{
    client::Client,
    http_client::DefaultHttpClient,
    issuer::Issuer,
    types::{
        CallbackParams, ClientMetadata, HttpMethod, IssuerMetadata, OAuthCallbackChecks,
        OpenIDCallbackChecks, OpenIdCallbackParams,
    },
};

fn get_iss_client_iss() -> (Issuer, Client, Issuer) {
    let issuer_metadata = IssuerMetadata {
        issuer: "https://op.example.com".to_string(),
        token_endpoint: Some("https://op.example.com/token".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        client_secret: Some("secure".to_string()),
        ..Default::default()
    };

    let client = issuer.client(client_metadata, None, None, None).unwrap();

    let issuer_metadata_with_iss = IssuerMetadata {
        issuer: "https://op.example.com".to_string(),
        token_endpoint: Some("https://op.example.com/token".to_string()),
        authorization_response_iss_parameter_supported: Some(true),
        ..Default::default()
    };

    (issuer, client, Issuer::new(issuer_metadata_with_iss))
}

#[tokio::test]
async fn does_an_authorization_code_grant_with_code_and_redirect_uri() {
    let http_client = TestHttpReqRes::new("https://op.example.com/token")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header("content-type", vec!["application/x-www-form-urlencoded".to_string()],
        ).assert_request_header(
        "authorization",
        vec!["Basic aWRlbnRpZmllcjpzZWN1cmU=".to_string()],
    )
        .assert_request_header("content-length", vec!["91".to_string()])
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_body(
            "grant_type=authorization_code&redirect_uri=https%3A%2F%2Frp.example.com%2Fcb&code=codeValue",
        )
        .set_response_body("{}")
        .build();

    let (_, mut client, _) = get_iss_client_iss();

    let callback_params = CallbackParams {
        code: Some("codeValue".to_string()),
        ..Default::default()
    };

    let params = OpenIdCallbackParams::default()
        .redirect_uri("https://rp.example.com/cb")
        .parameters(callback_params);

    let _ = client.callback_async(&http_client, params).await;

    http_client.assert();
}

#[tokio::test]
async fn resolves_a_tokenset_with_just_a_state_for_response_type_none() {
    let (_, mut client, _) = get_iss_client_iss();

    let callback_params = CallbackParams {
        state: Some("state".to_string()),
        ..Default::default()
    };

    let checks = OpenIDCallbackChecks {
        oauth_checks: Some(OAuthCallbackChecks {
            state: Some("state"),
            ..Default::default()
        }),
        ..Default::default()
    };

    let params = OpenIdCallbackParams::default()
        .redirect_uri("https://rp.example.com/cb")
        .parameters(callback_params)
        .checks(checks);

    let token_set = client
        .callback_async(&DefaultHttpClient, params)
        .await
        .unwrap();

    assert_eq!(
        "state",
        token_set.get_other().unwrap().get("state").unwrap()
    )
}

#[tokio::test]
async fn rejects_with_op_error_when_part_of_the_response() {
    let (_, mut client, _) = get_iss_client_iss();

    let params = CallbackParams {
        error: Some("invalid_request".to_string()),
        ..Default::default()
    };

    let params = OpenIdCallbackParams::default()
        .redirect_uri("https://rp.example.com/cb")
        .parameters(params);

    let err = client
        .callback_async(&DefaultHttpClient, params)
        .await
        .unwrap_err();

    assert!(err.is_op_error());

    assert_eq!("invalid_request", err.op_error().error.error);
}

#[cfg(test)]
mod state_checks {
    use crate::types::OAuthCallbackChecks;

    use super::*;

    #[tokio::test]
    async fn rejects_with_an_error_when_states_mismatch_returned() {
        let (_, mut client, _) = get_iss_client_iss();

        let params = CallbackParams {
            state: Some("should be checked for this".to_string()),
            ..Default::default()
        };

        let params = OpenIdCallbackParams::default()
            .redirect_uri("https://rp.example.com/cb")
            .parameters(params);

        let err = client
            .callback_async(&DefaultHttpClient, params)
            .await
            .unwrap_err();

        assert!(err.is_type_error());

        assert_eq!(
            "checks.state argument is missing",
            err.type_error().error.message
        );
    }

    #[tokio::test]
    async fn rejects_with_an_error_when_states_mismatch_not_returned() {
        let (_, mut client, _) = get_iss_client_iss();

        let checks = OpenIDCallbackChecks {
            oauth_checks: Some(OAuthCallbackChecks {
                state: Some("should be this"),
                ..Default::default()
            }),
            ..Default::default()
        };

        let params = OpenIdCallbackParams::default()
            .redirect_uri("https://rp.example.com/cb")
            .checks(checks);

        let err = client
            .callback_async(&DefaultHttpClient, params)
            .await
            .unwrap_err();

        assert!(err.is_rp_error());

        assert_eq!(
            "state missing from the response",
            err.rp_error().error.message
        );
    }

    #[tokio::test]
    async fn rejects_with_an_error_when_states_mismatch_general_mismatch() {
        let (_, mut client, _) = get_iss_client_iss();

        let params = CallbackParams {
            state: Some("foo".to_string()),
            ..Default::default()
        };

        let checks = OpenIDCallbackChecks {
            oauth_checks: Some(OAuthCallbackChecks {
                state: Some("bar"),
                ..Default::default()
            }),
            ..Default::default()
        };

        let params = OpenIdCallbackParams::default()
            .redirect_uri("https://rp.example.com/cb")
            .parameters(params)
            .checks(checks);

        let err = client
            .callback_async(&DefaultHttpClient, params)
            .await
            .unwrap_err();

        assert!(err.is_rp_error());

        assert_eq!(
            "state mismatch, expected bar, got: foo",
            err.rp_error().error.message
        );
    }
}

#[cfg(test)]
mod jarm_response_mode {
    use josekit::{
        jwe::{alg::direct::DirectJweAlgorithm::Dir, JweHeader},
        jws::JwsHeader,
        jwt::JwtPayload,
    };
    use serde_json::json;

    use crate::{helpers::now, types::OAuthCallbackChecks};

    use super::*;

    #[tokio::test]
    async fn consumes_jarm_responses() {
        let http_client = TestHttpReqRes::new("https://op.example.com/token")
            .assert_request_method(HttpMethod::POST)
            .assert_request_header("content-type", vec!["application/x-www-form-urlencoded".to_string()],
            ).assert_request_header(
            "authorization",
            vec!["Basic aWRlbnRpZmllcjpsYXJnZXJfdGhhbl8zMl9jaGFyX2NsaWVudF9zZWNyZXQ=".to_string()],
        )
            .assert_request_header("content-length", vec!["85".to_string()])
            .assert_request_header("accept", vec!["application/json".to_string()])
            .assert_request_body(
                "grant_type=authorization_code&redirect_uri=https%3A%2F%2Frp.example.com%2Fcb&code=foo",
            )
            .set_response_body("{}")
            .build();

        let (_, _, iss) = get_iss_client_iss();

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            client_secret: Some("larger_than_32_char_client_secret".to_string()),
            authorization_signed_response_alg: Some("HS256".to_string()),
            ..Default::default()
        };

        let mut payload = JwtPayload::new();
        payload.set_claim("code", Some(json!("foo"))).unwrap();
        payload
            .set_claim("iss", Some(json!(iss.issuer.clone())))
            .unwrap();
        let iat = now();
        let exp = iat + 300;

        payload.set_claim("iat", Some(json!(iat))).unwrap();
        payload.set_claim("exp", Some(json!(exp))).unwrap();
        payload.set_claim("aud", Some(json!("identifier"))).unwrap();

        let mut header = JwsHeader::new();
        header.set_claim("alg", Some(json!("HS256"))).unwrap();

        let signer = josekit::jws::HS256
            .signer_from_bytes("larger_than_32_char_client_secret")
            .unwrap();

        let response = josekit::jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        let mut client = iss.client(client_metadata, None, None, None).unwrap();

        let callback_params = CallbackParams {
            response: Some(response),
            ..Default::default()
        };

        let checks = OpenIDCallbackChecks {
            oauth_checks: Some(OAuthCallbackChecks {
                jarm: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };

        let params = OpenIdCallbackParams::default()
            .redirect_uri("https://rp.example.com/cb")
            .parameters(callback_params)
            .checks(checks);

        let _ = client.callback_async(&http_client, params).await;

        http_client.assert();
    }

    #[tokio::test]
    async fn consumes_encrypted_jarm_responses() {
        let http_client = TestHttpReqRes::new("https://op.example.com/token")
            .assert_request_method(HttpMethod::POST)
            .assert_request_header("content-type", vec!["application/x-www-form-urlencoded".to_string()],
            ).assert_request_header(
            "authorization",
            vec!["Basic aWRlbnRpZmllcjpsYXJnZXJfdGhhbl8zMl9jaGFyX2NsaWVudF9zZWNyZXQ=".to_string()],
        )
            .assert_request_header("content-length", vec!["85".to_string()])
            .assert_request_header("accept", vec!["application/json".to_string()])
            .assert_request_body(
                "grant_type=authorization_code&redirect_uri=https%3A%2F%2Frp.example.com%2Fcb&code=foo",
            )
            .set_response_body("{}")
            .build();

        let (_, _, iss) = get_iss_client_iss();

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            client_secret: Some("larger_than_32_char_client_secret".to_string()),
            authorization_signed_response_alg: Some("HS256".to_string()),
            authorization_encrypted_response_alg: Some("dir".to_string()),
            authorization_encrypted_response_enc: Some("A128GCM".to_string()),
            ..Default::default()
        };

        let mut client = iss.client(client_metadata, None, None, None).unwrap();

        let secret = client.secret_for_alg("A128GCM").unwrap();

        let encrypter = Dir.encrypter_from_jwk(&secret).unwrap();

        let mut payload = JwtPayload::new();
        payload.set_claim("code", Some(json!("foo"))).unwrap();
        payload
            .set_claim("iss", Some(json!(iss.issuer.clone())))
            .unwrap();
        let iat = now();
        let exp = iat + 300;

        payload.set_claim("iat", Some(json!(iat))).unwrap();
        payload.set_claim("exp", Some(json!(exp))).unwrap();
        payload.set_claim("aud", Some(json!("identifier"))).unwrap();

        let mut header = JwsHeader::new();
        header.set_claim("alg", Some(json!("HS256"))).unwrap();

        let signer = josekit::jws::HS256
            .signer_from_bytes("larger_than_32_char_client_secret")
            .unwrap();

        let response = josekit::jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        let mut jwe_header = JweHeader::new();

        jwe_header.set_claim("alg", Some(json!("dir"))).unwrap();
        jwe_header.set_claim("enc", Some(json!("A128GCM"))).unwrap();

        let encrypted_response =
            josekit::jwe::serialize_compact(response.as_bytes(), &jwe_header, &encrypter).unwrap();

        let callback_params = CallbackParams {
            response: Some(encrypted_response),
            ..Default::default()
        };

        let checks = OpenIDCallbackChecks {
            oauth_checks: Some(OAuthCallbackChecks {
                jarm: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };

        let params = OpenIdCallbackParams::default()
            .redirect_uri("https://rp.example.com/cb")
            .parameters(callback_params)
            .checks(checks);

        let _ = client.callback_async(&http_client, params).await;

        http_client.assert();
    }

    #[tokio::test]
    async fn rejects_the_callback_unless_jarm_was_used() {
        let callback_params = CallbackParams {
            code: Some("foo".to_string()),
            ..Default::default()
        };

        let checks = OpenIDCallbackChecks {
            oauth_checks: Some(OAuthCallbackChecks {
                jarm: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };

        let (_, mut client, _) = get_iss_client_iss();

        let params = OpenIdCallbackParams::default()
            .redirect_uri("https://rp.example.com/cb")
            .parameters(callback_params)
            .checks(checks);

        let err = client
            .callback_async(&DefaultHttpClient, params)
            .await
            .unwrap_err();

        assert!(err.is_rp_error());
        assert_eq!("expected a JARM response", err.rp_error().error.message);
    }

    #[tokio::test]
    async fn verifies_the_jarm_alg() {
        let (_, _, iss) = get_iss_client_iss();

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            client_secret: Some("larger_than_32_char_client_secret".to_string()),
            authorization_signed_response_alg: Some("RS256".to_string()),
            ..Default::default()
        };

        let mut payload = JwtPayload::new();
        payload.set_claim("code", Some(json!("foo"))).unwrap();
        payload
            .set_claim("iss", Some(json!(iss.issuer.clone())))
            .unwrap();
        let iat = now();
        let exp = iat + 300;

        payload.set_claim("iat", Some(json!(iat))).unwrap();
        payload.set_claim("exp", Some(json!(exp))).unwrap();
        payload.set_claim("aud", Some(json!("identifier"))).unwrap();

        let mut header = JwsHeader::new();
        header.set_claim("alg", Some(json!("HS256"))).unwrap();

        let signer = josekit::jws::HS256
            .signer_from_bytes("larger_than_32_char_client_secret")
            .unwrap();

        let response = josekit::jwt::encode_with_signer(&payload, &header, &signer).unwrap();

        let mut client = iss.client(client_metadata, None, None, None).unwrap();

        let callback_params = CallbackParams {
            response: Some(response),
            ..Default::default()
        };

        let checks = OpenIDCallbackChecks {
            oauth_checks: Some(OAuthCallbackChecks {
                jarm: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };

        let params = OpenIdCallbackParams::default()
            .redirect_uri("https://rp.example.com/cb")
            .parameters(callback_params)
            .checks(checks);

        let err = client
            .callback_async(&DefaultHttpClient, params)
            .await
            .unwrap_err();

        assert!(err.is_rp_error());
        assert_eq!(
            "unexpected JWT alg received, expected RS256, got: HS256",
            err.rp_error().error.message
        );
    }
}

#[cfg(test)]
mod response_type_checks {
    use crate::types::OAuthCallbackChecks;

    use super::*;

    #[tokio::test]
    async fn rejects_with_an_error_when_code_is_missing() {
        let (_, mut client, _) = get_iss_client_iss();

        let params = CallbackParams {
            // code: Some("foo".to_string()),
            access_token: Some("foo".to_string()),
            token_type: Some("Bearer".to_string()),
            id_token: Some("foo".to_string()),
            ..Default::default()
        };

        let checks = OpenIDCallbackChecks {
            oauth_checks: Some(OAuthCallbackChecks {
                response_type: Some("code id_token token"),
                ..Default::default()
            }),
            ..Default::default()
        };

        let params = OpenIdCallbackParams::default()
            .redirect_uri("https://rp.example.com/cb")
            .parameters(params)
            .checks(checks);

        let err = client
            .callback_async(&DefaultHttpClient, params)
            .await
            .unwrap_err();

        assert!(err.is_rp_error());

        assert_eq!("code missing from response", err.rp_error().error.message);
    }

    #[tokio::test]
    async fn rejects_with_an_error_when_id_token_is_missing() {
        let (_, mut client, _) = get_iss_client_iss();

        let params = CallbackParams {
            code: Some("foo".to_string()),
            access_token: Some("foo".to_string()),
            token_type: Some("Bearer".to_string()),
            // id_token: Some("foo".to_string()),
            ..Default::default()
        };

        let checks = OpenIDCallbackChecks {
            oauth_checks: Some(OAuthCallbackChecks {
                response_type: Some("code id_token token"),
                ..Default::default()
            }),
            ..Default::default()
        };

        let params = OpenIdCallbackParams::default()
            .redirect_uri("https://rp.example.com/cb")
            .parameters(params)
            .checks(checks);

        let err = client
            .callback_async(&DefaultHttpClient, params)
            .await
            .unwrap_err();

        assert!(err.is_rp_error());

        assert_eq!(
            "id_token missing from response",
            err.rp_error().error.message
        );
    }

    #[tokio::test]
    async fn rejects_with_an_error_when_token_type_is_missing() {
        let (_, mut client, _) = get_iss_client_iss();

        let params = CallbackParams {
            code: Some("foo".to_string()),
            access_token: Some("foo".to_string()),
            // token_type: Some("Bearer".to_string()),
            id_token: Some("foo".to_string()),
            ..Default::default()
        };

        let checks = OpenIDCallbackChecks {
            oauth_checks: Some(OAuthCallbackChecks {
                response_type: Some("code id_token token"),
                ..Default::default()
            }),
            ..Default::default()
        };

        let params = OpenIdCallbackParams::default()
            .redirect_uri("https://rp.example.com/cb")
            .parameters(params)
            .checks(checks);

        let err = client
            .callback_async(&DefaultHttpClient, params)
            .await
            .unwrap_err();

        assert!(err.is_rp_error());

        assert_eq!(
            "token_type missing from response",
            err.rp_error().error.message
        );
    }

    #[tokio::test]
    async fn rejects_with_an_error_when_access_token_is_missing() {
        let (_, mut client, _) = get_iss_client_iss();

        let params = CallbackParams {
            code: Some("foo".to_string()),
            // access_token: Some("foo".to_string()),
            token_type: Some("Bearer".to_string()),
            id_token: Some("foo".to_string()),
            ..Default::default()
        };

        let checks = OpenIDCallbackChecks {
            oauth_checks: Some(OAuthCallbackChecks {
                response_type: Some("code id_token token"),
                ..Default::default()
            }),
            ..Default::default()
        };

        let params = OpenIdCallbackParams::default()
            .redirect_uri("https://rp.example.com/cb")
            .parameters(params)
            .checks(checks);

        let err = client
            .callback_async(&DefaultHttpClient, params)
            .await
            .unwrap_err();

        assert!(err.is_rp_error());

        assert_eq!(
            "access_token missing from response",
            err.rp_error().error.message
        );
    }

    #[tokio::test]
    async fn rejects_with_an_error_when_code_param_is_encoutered_during_none_response() {
        let (_, mut client, _) = get_iss_client_iss();

        let params = CallbackParams {
            code: Some("foo".to_string()),
            ..Default::default()
        };

        let checks = OpenIDCallbackChecks {
            oauth_checks: Some(OAuthCallbackChecks {
                response_type: Some("none"),
                ..Default::default()
            }),
            ..Default::default()
        };

        let params = OpenIdCallbackParams::default()
            .redirect_uri("https://rp.example.com/cb")
            .parameters(params)
            .checks(checks);

        let err = client
            .callback_async(&DefaultHttpClient, params)
            .await
            .unwrap_err();

        assert!(err.is_rp_error());

        assert_eq!(
            "unexpected params encountered for \"none\" response",
            err.rp_error().error.message
        );
    }

    #[tokio::test]
    async fn rejects_with_an_error_when_access_token_param_is_encoutered_during_none_response() {
        let (_, mut client, _) = get_iss_client_iss();

        let params = CallbackParams {
            access_token: Some("foo".to_string()),
            ..Default::default()
        };

        let checks = OpenIDCallbackChecks {
            oauth_checks: Some(OAuthCallbackChecks {
                response_type: Some("none"),
                ..Default::default()
            }),
            ..Default::default()
        };

        let params = OpenIdCallbackParams::default()
            .redirect_uri("https://rp.example.com/cb")
            .parameters(params)
            .checks(checks);

        let err = client
            .callback_async(&DefaultHttpClient, params)
            .await
            .unwrap_err();

        assert!(err.is_rp_error());

        assert_eq!(
            "unexpected params encountered for \"none\" response",
            err.rp_error().error.message
        );
    }

    #[tokio::test]
    async fn rejects_with_an_error_when_id_token_param_is_encoutered_during_none_response() {
        let (_, mut client, _) = get_iss_client_iss();

        let params = CallbackParams {
            id_token: Some("foo".to_string()),
            ..Default::default()
        };

        let checks = OpenIDCallbackChecks {
            oauth_checks: Some(OAuthCallbackChecks {
                response_type: Some("none"),
                ..Default::default()
            }),
            ..Default::default()
        };

        let params = OpenIdCallbackParams::default()
            .redirect_uri("https://rp.example.com/cb")
            .parameters(params)
            .checks(checks);

        let err = client
            .callback_async(&DefaultHttpClient, params)
            .await
            .unwrap_err();

        assert!(err.is_rp_error());

        assert_eq!(
            "unexpected params encountered for \"none\" response",
            err.rp_error().error.message
        );
    }
}
