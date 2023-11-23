use httpmock::{Method::POST, MockServer};

use crate::{
    client::Client,
    issuer::Issuer,
    tests::test_interceptors::get_default_test_interceptor,
    types::{CallbackParams, ClientMetadata, IssuerMetadata},
};

fn get_iss_client_iss(port: Option<u16>) -> (Issuer, Client, Issuer) {
    let issuer_metadata = IssuerMetadata {
        issuer: "https://op.example.com".to_string(),
        token_endpoint: Some("https://op.example.com/token".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata, get_default_test_interceptor(port));

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        client_secret: Some("secure".to_string()),
        ..Default::default()
    };

    let client = issuer
        .client(
            client_metadata,
            get_default_test_interceptor(port),
            None,
            None,
            None,
        )
        .unwrap();

    let issuer_metadata_with_iss = IssuerMetadata {
        issuer: "https://op.example.com".to_string(),
        token_endpoint: Some("https://op.example.com/token".to_string()),
        authorization_response_iss_parameter_supported: Some(true),
        ..Default::default()
    };

    (
        issuer,
        client,
        Issuer::new(issuer_metadata_with_iss, get_default_test_interceptor(port)),
    )
}

#[tokio::test]
async fn does_an_authorization_code_grant_with_code_and_redirect_uri() {
    let mock_http_server = MockServer::start();

    let oauth_callback_server = mock_http_server.mock(|when, then| {
        when.method(POST)
            .header("Accept", "application/json")
            .matches(|req| {
                let decoded =
                    urlencoding::decode(std::str::from_utf8(&req.body.as_ref().unwrap()).unwrap())
                        .unwrap();

                let kvp = querystring::querify(&decoded);

                let code = kvp.iter().find(|(k, v)| k == &"code" && v == &"codeValue");
                let redirect_uri = kvp
                    .iter()
                    .find(|(k, v)| k == &"redirect_uri" && v == &"https://rp.example.com/cb");
                let grant_type = kvp
                    .iter()
                    .find(|(k, v)| k == &"grant_type" && v == &"authorization_code");
                code.is_some() && redirect_uri.is_some() && grant_type.is_some()
            })
            .path("/token");
        then.status(200).body("{\"access_token\":\"tokenValue\"}");
    });

    let (_, mut client, _) = get_iss_client_iss(Some(mock_http_server.port()));

    let callback_params = CallbackParams {
        code: Some("codeValue".to_string()),
        ..Default::default()
    };

    let token_set = client
        .oauth_callback_async(
            Some("https://rp.example.com/cb"),
            callback_params,
            None,
            None,
        )
        .await
        .unwrap();

    oauth_callback_server.assert();

    assert_eq!("tokenValue", token_set.get_access_token().unwrap());
}

#[tokio::test]
async fn handles_implicit_responses_too() {
    let (_, mut client, _) = get_iss_client_iss(None);

    let callback_params = CallbackParams {
        access_token: Some("tokenValue".to_string()),
        ..Default::default()
    };

    let token_set = client
        .oauth_callback_async(None, callback_params, None, None)
        .await
        .unwrap();

    assert_eq!("tokenValue", token_set.get_access_token().unwrap())
}

#[cfg(test)]
mod oauth_2_0_authorization_server_issuer_identification {

    // TODO: after callback_async(), implement the respective tests for those methods below

    use super::*;

    #[tokio::test]
    async fn iss_mismatch_in_oauth_callback_async() {
        let (_, mut client, _) = get_iss_client_iss(None);

        let callback_params = CallbackParams {
            iss: Some("https://other-op.example.com".to_string()),
            ..Default::default()
        };

        let token_set = client
            .oauth_callback_async(None, callback_params, None, None)
            .await
            .unwrap_err();

        assert!(token_set.is_rp_error());

        let error = token_set.rp_error().error;
        assert_eq!(
            "iss mismatch, expected https://op.example.com, got: https://other-op.example.com",
            error.message
        );
    }

    #[tokio::test]
    async fn iss_mismatch_in_callback_async() {
        let (_, mut client, _) = get_iss_client_iss(None);

        let callback_params = CallbackParams {
            iss: Some("https://other-op.example.com".to_string()),
            ..Default::default()
        };

        let token_set = client
            .callback_async(None, callback_params, None, None)
            .await
            .unwrap_err();

        assert!(token_set.is_rp_error());

        let error = token_set.rp_error().error;
        assert_eq!(
            "iss mismatch, expected https://op.example.com, got: https://other-op.example.com",
            error.message
        );
    }

    #[tokio::test]
    async fn iss_missing_in_oauth_callback_async() {
        let (_, _, iss) = get_iss_client_iss(None);

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            ..Default::default()
        };

        let mut client = iss.client(client_metadata, None, None, None, None).unwrap();

        let token_set = client
            .oauth_callback_async(None, Default::default(), None, None)
            .await
            .unwrap_err();

        assert!(token_set.is_rp_error());

        let error = token_set.rp_error().error;
        assert_eq!("iss missing from the response", error.message);
    }

    #[tokio::test]
    async fn iss_missing_in_callback_async() {
        let (_, _, iss) = get_iss_client_iss(None);

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            ..Default::default()
        };

        let mut client = iss.client(client_metadata, None, None, None, None).unwrap();

        let token_set = client
            .callback_async(None, Default::default(), None, None)
            .await
            .unwrap_err();

        assert!(token_set.is_rp_error());

        let error = token_set.rp_error().error;
        assert_eq!("iss missing from the response", error.message);
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
        let mock_http_server = MockServer::start();

        let oauth_callback_server = mock_http_server.mock(|when, then| {
            when.method(POST)
                .header("accept", "application/json")
                .matches(|req| {
                    let mut content_length_exists = false;
                    let mut no_transfer_encoding = false;

                    if let Some(headers) = &req.headers {
                        content_length_exists = headers
                            .iter()
                            .find(|x| x.0 == "content-length" && x.1.parse::<u64>().is_ok())
                            .is_some();

                        no_transfer_encoding = headers
                            .iter()
                            .find(|x| x.0 == "transfer-encoding")
                            .is_none();
                    }

                    let decoded = urlencoding::decode(
                        std::str::from_utf8(&req.body.as_ref().unwrap()).unwrap(),
                    )
                    .unwrap();

                    let kvp = querystring::querify(&decoded);

                    let code = kvp.iter().find(|(k, v)| k == &"code" && v == &"foo");
                    let redirect_uri = kvp
                        .iter()
                        .find(|(k, v)| k == &"redirect_uri" && v == &"https://rp.example.com/cb");
                    let grant_type = kvp
                        .iter()
                        .find(|(k, v)| k == &"grant_type" && v == &"authorization_code");
                    code.is_some()
                        && redirect_uri.is_some()
                        && grant_type.is_some()
                        && content_length_exists
                        && no_transfer_encoding
                })
                .path("/token");
            then.status(200).body("{}");
        });

        let (_, _, iss) = get_iss_client_iss(Some(mock_http_server.port()));

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

        let mut client = iss.client(client_metadata, None, None, None, None).unwrap();

        let callback_params = CallbackParams {
            response: Some(response),
            ..Default::default()
        };

        let checks = OAuthCallbackChecks {
            jarm: Some(true),
            ..Default::default()
        };

        let _ = client
            .oauth_callback_async(
                Some("https://rp.example.com/cb"),
                callback_params,
                Some(checks),
                None,
            )
            .await;

        oauth_callback_server.assert_async().await;
    }

    #[tokio::test]
    async fn consumes_encrypted_jarm_responses() {
        let mock_http_server = MockServer::start();

        let oauth_callback_server = mock_http_server.mock(|when, then| {
            when.method(POST)
                .header("accept", "application/json")
                .matches(|req| {
                    let mut content_length_exists = false;
                    let mut no_transfer_encoding = false;

                    if let Some(headers) = &req.headers {
                        content_length_exists = headers
                            .iter()
                            .find(|x| x.0 == "content-length" && x.1.parse::<u64>().is_ok())
                            .is_some();

                        no_transfer_encoding = headers
                            .iter()
                            .find(|x| x.0 == "transfer-encoding")
                            .is_none();
                    }

                    let decoded = urlencoding::decode(
                        std::str::from_utf8(&req.body.as_ref().unwrap()).unwrap(),
                    )
                    .unwrap();

                    let kvp = querystring::querify(&decoded);

                    let code = kvp.iter().find(|(k, v)| k == &"code" && v == &"foo");
                    let redirect_uri = kvp
                        .iter()
                        .find(|(k, v)| k == &"redirect_uri" && v == &"https://rp.example.com/cb");
                    let grant_type = kvp
                        .iter()
                        .find(|(k, v)| k == &"grant_type" && v == &"authorization_code");
                    code.is_some()
                        && redirect_uri.is_some()
                        && grant_type.is_some()
                        && content_length_exists
                        && no_transfer_encoding
                })
                .path("/token");
            then.status(200).body("{}");
        });

        let (_, _, iss) = get_iss_client_iss(Some(mock_http_server.port()));

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            client_secret: Some("larger_than_32_char_client_secret".to_string()),
            authorization_signed_response_alg: Some("HS256".to_string()),
            authorization_encrypted_response_alg: Some("dir".to_string()),
            authorization_encrypted_response_enc: Some("A128GCM".to_string()),
            ..Default::default()
        };

        let mut client = iss.client(client_metadata, None, None, None, None).unwrap();

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

        let checks = OAuthCallbackChecks {
            jarm: Some(true),
            ..Default::default()
        };

        let _ = client
            .oauth_callback_async(
                Some("https://rp.example.com/cb"),
                callback_params,
                Some(checks),
                None,
            )
            .await;

        oauth_callback_server.assert_async().await;
    }

    #[tokio::test]
    async fn rejects_the_callback_unless_jarm_was_used() {
        let callback_params = CallbackParams {
            code: Some("foo".to_string()),
            ..Default::default()
        };

        let checks = OAuthCallbackChecks {
            jarm: Some(true),
            ..Default::default()
        };

        let (_, mut client, _) = get_iss_client_iss(None);

        let err = client
            .oauth_callback_async(
                Some("https://rp.example.com/cb"),
                callback_params,
                Some(checks),
                None,
            )
            .await
            .unwrap_err();

        assert!(err.is_rp_error());
        assert_eq!("expected a JARM response", err.rp_error().error.message);
    }

    #[tokio::test]
    async fn verifies_the_jarm_alg() {
        let (_, _, iss) = get_iss_client_iss(None);

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

        let mut client = iss.client(client_metadata, None, None, None, None).unwrap();

        let callback_params = CallbackParams {
            response: Some(response),
            ..Default::default()
        };

        let checks = OAuthCallbackChecks {
            jarm: Some(true),
            ..Default::default()
        };

        let err = client
            .oauth_callback_async(
                Some("https://rp.example.com/cb"),
                callback_params,
                Some(checks),
                None,
            )
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
mod cannot_be_used_for_id_token_responses {
    use super::*;

    #[tokio::test]
    async fn rejects_when_id_token_was_issued_by_the_authorization_endpoint() {
        let (_, mut client, _) = get_iss_client_iss(None);

        let params = CallbackParams {
            id_token: Some("foo".to_string()),
            code: Some("foo".to_string()),
            ..Default::default()
        };

        let err = client
            .oauth_callback_async(Some("https://rp.example.com/cb"), params, None, None)
            .await
            .unwrap_err();

        assert!(err.is_rp_error());
        assert_eq!("id_token detected in the response, you must use client.callback_async() instead of client.oauth_callback_async()", err.rp_error().error.message);
    }

    #[tokio::test]
    async fn ignores_the_id_token_when_falsy() {
        let (_, mut client, _) = get_iss_client_iss(None);

        let params = CallbackParams {
            id_token: Some("".to_string()),
            token_type: Some("bearer".to_string()),
            access_token: Some("foo".to_string()),
            ..Default::default()
        };

        let tokens = client
            .oauth_callback_async(Some("https://rp.example.com/cb"), params, None, None)
            .await
            .unwrap();

        assert!(tokens.get_id_token().is_none());
    }

    #[tokio::test]
    async fn rejects_when_id_token_was_issued_by_the_token_endpoint() {
        let mock_http_server = MockServer::start();

        let _oauth_callback_server = mock_http_server.mock(|when, then| {
            when.method(POST)
                .header("accept", "application/json")
                .matches(|req| {
                    let mut content_length_exists = false;
                    let mut no_transfer_encoding = false;

                    if let Some(headers) = &req.headers {
                        content_length_exists = headers
                            .iter()
                            .find(|x| x.0 == "content-length" && x.1.parse::<u64>().is_ok())
                            .is_some();

                        no_transfer_encoding = headers
                            .iter()
                            .find(|x| x.0 == "transfer-encoding")
                            .is_none();
                    }

                    content_length_exists && no_transfer_encoding
                })
                .path("/token");
            then.status(200).body(r#"{"id_token":"foo"}"#);
        });

        let (_, mut client, _) = get_iss_client_iss(Some(mock_http_server.port()));

        let params = CallbackParams {
            code: Some("foo".to_string()),
            ..Default::default()
        };

        let err = client
            .oauth_callback_async(Some("https://rp.example.com/cb"), params, None, None)
            .await
            .unwrap_err();

        assert!(err.is_rp_error());
        assert_eq!("id_token detected in the response, you must use client.callback_async() instead of client.oauth_callback_async()", err.rp_error().error.message);
    }

    #[tokio::test]
    async fn ignores_the_the_token_endpoint_id_token_property_when_falsy() {
        let mock_http_server = MockServer::start();

        let _oauth_callback_server = mock_http_server.mock(|when, then| {
            when.method(POST)
                .header("accept", "application/json")
                .matches(|req| {
                    let mut content_length_exists = false;
                    let mut no_transfer_encoding = false;

                    if let Some(headers) = &req.headers {
                        content_length_exists = headers
                            .iter()
                            .find(|x| x.0 == "content-length" && x.1.parse::<u64>().is_ok())
                            .is_some();

                        no_transfer_encoding = headers
                            .iter()
                            .find(|x| x.0 == "transfer-encoding")
                            .is_none();
                    }

                    content_length_exists && no_transfer_encoding
                })
                .path("/token");
            then.status(200).body(r#"{"id_token":""}"#);
        });

        let (_, mut client, _) = get_iss_client_iss(Some(mock_http_server.port()));

        let params = CallbackParams {
            code: Some("foo".to_string()),
            ..Default::default()
        };

        let tokens = client
            .oauth_callback_async(Some("https://rp.example.com/cb"), params, None, None)
            .await
            .unwrap();

        assert!(tokens.get_id_token().is_none());
    }
}

#[cfg(test)]
mod response_type_checks {
    use crate::types::OAuthCallbackChecks;

    use super::*;

    #[tokio::test]
    async fn rejects_with_an_error_when_code_is_missing() {
        let (_, mut client, _) = get_iss_client_iss(None);

        let params = CallbackParams {
            // code: Some("foo".to_string()),
            access_token: Some("foo".to_string()),
            token_type: Some("Bearer".to_string()),
            ..Default::default()
        };

        let checks = OAuthCallbackChecks {
            response_type: Some("code token"),
            ..Default::default()
        };

        let err = client
            .oauth_callback_async(
                Some("https://rp.example.com/cb"),
                params,
                Some(checks),
                None,
            )
            .await
            .unwrap_err();

        assert!(err.is_rp_error());

        assert_eq!("code missing from response", err.rp_error().error.message);
    }

    #[tokio::test]
    async fn rejects_with_an_error_when_token_type_is_missing() {
        let (_, mut client, _) = get_iss_client_iss(None);

        let params = CallbackParams {
            code: Some("foo".to_string()),
            access_token: Some("foo".to_string()),
            // token_type: Some("Bearer".to_string()),
            ..Default::default()
        };

        let checks = OAuthCallbackChecks {
            response_type: Some("code token"),
            ..Default::default()
        };

        let err = client
            .oauth_callback_async(
                Some("https://rp.example.com/cb"),
                params,
                Some(checks),
                None,
            )
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
        let (_, mut client, _) = get_iss_client_iss(None);

        let params = CallbackParams {
            code: Some("foo".to_string()),
            // access_token: Some("foo".to_string()),
            token_type: Some("Bearer".to_string()),
            ..Default::default()
        };

        let checks = OAuthCallbackChecks {
            response_type: Some("code token"),
            ..Default::default()
        };

        let err = client
            .oauth_callback_async(
                Some("https://rp.example.com/cb"),
                params,
                Some(checks),
                None,
            )
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
        let (_, mut client, _) = get_iss_client_iss(None);

        let params = CallbackParams {
            code: Some("foo".to_string()),
            ..Default::default()
        };

        let checks = OAuthCallbackChecks {
            response_type: Some("none"),
            ..Default::default()
        };

        let err = client
            .oauth_callback_async(
                Some("https://rp.example.com/cb"),
                params,
                Some(checks),
                None,
            )
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
        let (_, mut client, _) = get_iss_client_iss(None);

        let params = CallbackParams {
            access_token: Some("foo".to_string()),
            ..Default::default()
        };

        let checks = OAuthCallbackChecks {
            response_type: Some("none"),
            ..Default::default()
        };

        let err = client
            .oauth_callback_async(
                Some("https://rp.example.com/cb"),
                params,
                Some(checks),
                None,
            )
            .await
            .unwrap_err();

        assert!(err.is_rp_error());

        assert_eq!(
            "unexpected params encountered for \"none\" response",
            err.rp_error().error.message
        );
    }
}

#[tokio::test]
async fn rejects_with_op_error_when_part_of_the_response() {
    let (_, mut client, _) = get_iss_client_iss(None);

    let params = CallbackParams {
        error: Some("invalid_request".to_string()),
        ..Default::default()
    };

    let err = client
        .oauth_callback_async(Some("https://rp.example.com/cb"), params, None, None)
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
        let (_, mut client, _) = get_iss_client_iss(None);

        let params = CallbackParams {
            state: Some("should be checked for this".to_string()),
            ..Default::default()
        };

        let err = client
            .oauth_callback_async(Some("https://rp.example.com/cb"), params, None, None)
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
        let (_, mut client, _) = get_iss_client_iss(None);

        let checks = OAuthCallbackChecks {
            state: Some("should be this"),
            ..Default::default()
        };

        let err = client
            .oauth_callback_async(
                Some("https://rp.example.com/cb"),
                Default::default(),
                Some(checks),
                None,
            )
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
        let (_, mut client, _) = get_iss_client_iss(None);

        let params = CallbackParams {
            state: Some("foo".to_string()),
            ..Default::default()
        };

        let checks = OAuthCallbackChecks {
            state: Some("bar"),
            ..Default::default()
        };

        let err = client
            .oauth_callback_async(
                Some("https://rp.example.com/cb"),
                params,
                Some(checks),
                None,
            )
            .await
            .unwrap_err();

        assert!(err.is_rp_error());

        assert_eq!(
            "state mismatch, expected bar, got: foo",
            err.rp_error().error.message
        );
    }
}
