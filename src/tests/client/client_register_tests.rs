use crate::{
    client::Client,
    http_client::DefaultHttpClient,
    issuer::Issuer,
    types::{ClientMetadata, HttpMethod, IssuerMetadata},
};

use crate::tests::test_http_client::TestHttpReqRes;

static DEFAULT_CLIENT_READ: &str = r#"{"client_id":"identifier","client_secret":"secure"}"#;

#[tokio::test]
async fn asserts_the_issuer_has_a_registration_endpoint() {
    let issuer_metadata = IssuerMetadata::default();

    let issuer = Issuer::new(issuer_metadata);

    let client_error = Client::register_async(
        &DefaultHttpClient,
        &issuer,
        ClientMetadata::default(),
        None,
        None,
    )
    .await
    .unwrap_err();

    assert_eq!(
        "registration_endpoint must be configured on the issuer",
        client_error.type_error().error.message
    );
}

#[tokio::test]
async fn accepts_and_assigns_the_registered_metadata() {
    let http_client = TestHttpReqRes::new("https://op.example.com/client/registration")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header("content-length", vec!["2".to_string()])
        .assert_request_header("content-type", vec!["application/json".to_string()])
        .assert_request_body("{}")
        .set_response_body(DEFAULT_CLIENT_READ)
        .set_response_content_type_header("application/json")
        .set_response_status_code(201)
        .build();

    let registration_endpoint = "https://op.example.com/client/registration".to_string();

    let issuer_metadata = IssuerMetadata {
        registration_endpoint: Some(registration_endpoint),
        ..IssuerMetadata::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client =
        Client::register_async(&http_client, &issuer, ClientMetadata::default(), None, None)
            .await
            .unwrap();

    assert_eq!("identifier", client.client_id);

    assert_eq!("secure", client.client_secret.unwrap());
}

#[tokio::test]
async fn is_rejected_with_op_error_upon_oidc_error() {
    let http_client = TestHttpReqRes::new("https://op.example.com/client/registration")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header("content-length", vec!["2".to_string()])
        .assert_request_header("content-type", vec!["application/json".to_string()])
        .assert_request_body("{}")
        .set_response_body(
            r#"{"error":"server_error","error_description":"bad things are happening"}"#,
        )
        .set_response_status_code(500)
        .build();

    let registration_endpoint = "https://op.example.com/client/registration".to_string();

    let issuer_metadata = IssuerMetadata {
        registration_endpoint: Some(registration_endpoint),
        ..IssuerMetadata::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_error =
        Client::register_async(&http_client, &issuer, ClientMetadata::default(), None, None)
            .await
            .unwrap_err();

    assert!(client_error.is_op_error());

    let err = client_error.op_error().error;

    assert_eq!("server_error", err.error);

    assert_eq!(
        Some("bad things are happening".to_string()),
        err.error_description
    );
}

#[tokio::test]
async fn is_rejected_with_op_error_upon_oidc_error_in_www_authenticate_header() {
    let http_client = TestHttpReqRes::new("https://op.example.com/client/registration")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header("content-length", vec!["2".to_string()])
        .assert_request_header("content-type", vec!["application/json".to_string()])
        .assert_request_body("{}")
        .set_response_body("Unauthorized")
        .set_response_www_authenticate_header(
            r#"Bearer error="invalid_token", error_description="bad things are happening""#,
        )
        .set_response_status_code(401)
        .build();

    let registration_endpoint = "https://op.example.com/client/registration".to_string();

    let issuer_metadata = IssuerMetadata {
        registration_endpoint: Some(registration_endpoint),
        ..IssuerMetadata::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_error =
        Client::register_async(&http_client, &issuer, ClientMetadata::default(), None, None)
            .await
            .unwrap_err();

    assert!(client_error.is_op_error());

    let err = client_error.op_error().error;

    assert_eq!("invalid_token", err.error);

    assert_eq!(
        Some("bad things are happening".to_string()),
        err.error_description
    );
}

#[tokio::test]
async fn is_rejected_with_when_non_200_is_returned() {
    let http_client = TestHttpReqRes::new("https://op.example.com/client/registration")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header("content-length", vec!["2".to_string()])
        .assert_request_header("content-type", vec!["application/json".to_string()])
        .assert_request_body("{}")
        .set_response_body("Internal Server Error")
        .set_response_status_code(500)
        .build();

    let registration_endpoint = "https://op.example.com/client/registration".to_string();

    let issuer_metadata = IssuerMetadata {
        registration_endpoint: Some(registration_endpoint),
        ..IssuerMetadata::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_error =
        Client::register_async(&http_client, &issuer, ClientMetadata::default(), None, None)
            .await
            .unwrap_err();

    assert!(client_error.is_op_error());

    let err = client_error.op_error();

    assert!(err.response.is_some());

    assert_eq!(
        Some("expected 201 Created, got: 500 Internal Server Error".to_string()),
        err.error.error_description
    );
}

#[tokio::test]
async fn is_rejected_with_json_parse_error_upon_invalid_response() {
    let http_client = TestHttpReqRes::new("https://op.example.com/client/registration")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header("content-length", vec!["2".to_string()])
        .assert_request_header("content-type", vec!["application/json".to_string()])
        .assert_request_body("{}")
        .set_response_body(r#"{"notvalid"}"#)
        .set_response_status_code(201)
        .build();

    let registration_endpoint = "https://op.example.com/client/registration".to_string();

    let issuer_metadata = IssuerMetadata {
        registration_endpoint: Some(registration_endpoint),
        ..IssuerMetadata::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_error =
        Client::register_async(&http_client, &issuer, ClientMetadata::default(), None, None)
            .await
            .unwrap_err();

    assert!(client_error.is_type_error());

    let err = client_error.type_error().error;

    assert_eq!("unexpected body type", err.message);
}

#[cfg(test)]
mod with_key_store_as_an_option {
    use serde_json::json;

    use crate::{helpers::convert_json_to, jwks::Jwks, types::ClientRegistrationOptions};

    use super::*;

    static DEFAULT_JWKS: &str = r#"{"keys":[{"kty":"EC","d":"okqKR79UYsyRRIVT1cQU8vyJxa4HF14Ig9BaXioH1co","use":"sig","crv":"P-256","kid":"E5e5oAXKlVe1Pp1uYlorEE2XEDzZ-5sTNDuS4RcU_VA","x":"hBWMzCM4tmlWWK0ovPlg2oCnpcdWAcVvtr9M5bichiA","y":"yP7NOAHMReiT1PG-Nxl4MbegpvwJnUGfLCI_llPQIg4","alg":"ES256"}]}"#;

    #[tokio::test]
    async fn enriches_the_registration_with_jwks_if_not_provided_or_jwks_uri() {
        let http_client = TestHttpReqRes::new("https://op.example.com/client/registration")
            .assert_request_method(HttpMethod::POST)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .assert_request_header("content-length", vec!["224".to_string()])
            .assert_request_header("content-type", vec!["application/json".to_string()])
            .assert_request_body(r#"{"jwks":{"keys":[{"kty":"EC","use":"sig","crv":"P-256","x":"hBWMzCM4tmlWWK0ovPlg2oCnpcdWAcVvtr9M5bichiA","y":"yP7NOAHMReiT1PG-Nxl4MbegpvwJnUGfLCI_llPQIg4","alg":"ES256","kid":"E5e5oAXKlVe1Pp1uYlorEE2XEDzZ-5sTNDuS4RcU_VA"}]}}"#)
            .set_response_body(DEFAULT_CLIENT_READ)
            .set_response_status_code(201)
            .build();

        let registration_endpoint = "https://op.example.com/client/registration".to_string();

        let issuer_metadata = IssuerMetadata {
            registration_endpoint: Some(registration_endpoint),
            ..IssuerMetadata::default()
        };

        let issuer = Issuer::new(issuer_metadata);

        let register_options = ClientRegistrationOptions::default()
            .set_jwks(convert_json_to::<Jwks>(DEFAULT_JWKS).unwrap());

        let _ = Client::register_async(
            &http_client,
            &issuer,
            ClientMetadata::default(),
            Some(register_options),
            None,
        )
        .await
        .unwrap();

        http_client.assert();
    }

    #[tokio::test]
    async fn ignores_the_keystore_during_registration_if_jwks_is_provided() {
        let http_client = TestHttpReqRes::new("https://op.example.com/client/registration")
            .assert_request_method(HttpMethod::POST)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .assert_request_header("content-length", vec!["20".to_string()])
            .assert_request_header("content-type", vec!["application/json".to_string()])
            .assert_request_body(serde_json::to_string(&json!({"jwks": Jwks::default()})).unwrap())
            .set_response_body(DEFAULT_CLIENT_READ)
            .set_response_status_code(201)
            .build();

        let registration_endpoint = "https://op.example.com/client/registration".to_string();

        let issuer_metadata = IssuerMetadata {
            registration_endpoint: Some(registration_endpoint),
            ..IssuerMetadata::default()
        };

        let issuer = Issuer::new(issuer_metadata);

        let register_options = ClientRegistrationOptions::default()
            .set_jwks(convert_json_to::<Jwks>(DEFAULT_JWKS).unwrap());

        let client_metadata = ClientMetadata {
            jwks: Some(Jwks::default()),
            ..Default::default()
        };

        let _ = Client::register_async(
            &http_client,
            &issuer,
            client_metadata,
            Some(register_options),
            None,
        )
        .await
        .unwrap();

        http_client.assert();
    }

    #[tokio::test]
    async fn ignores_the_keystore_during_registration_if_jwks_uri_is_provided() {
        let http_client = TestHttpReqRes::new("https://op.example.com/client/registration")
            .assert_request_method(HttpMethod::POST)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .assert_request_header("content-length", vec!["43".to_string()])
            .assert_request_header("content-type", vec!["application/json".to_string()])
            .assert_request_body(r#"{"jwks_uri":"https://rp.example.com/certs"}"#)
            .set_response_body(DEFAULT_CLIENT_READ)
            .set_response_status_code(201)
            .build();

        let registration_endpoint = "https://op.example.com/client/registration".to_string();

        let issuer_metadata = IssuerMetadata {
            registration_endpoint: Some(registration_endpoint),
            ..IssuerMetadata::default()
        };

        let issuer = Issuer::new(issuer_metadata);

        let register_options = ClientRegistrationOptions::default()
            .set_jwks(convert_json_to::<Jwks>(DEFAULT_JWKS).unwrap());

        let client_metadata = ClientMetadata {
            jwks_uri: Some("https://rp.example.com/certs".to_string()),
            ..Default::default()
        };

        let _ = Client::register_async(
            &http_client,
            &issuer,
            client_metadata,
            Some(register_options),
            None,
        )
        .await
        .unwrap();

        http_client.assert();
    }

    #[tokio::test]
    async fn does_not_accept_oct_keys() {
        let registration_endpoint = "https://op.example.com/client/registration".to_string();

        let issuer_metadata = IssuerMetadata {
            registration_endpoint: Some(registration_endpoint.to_string()),
            ..IssuerMetadata::default()
        };

        let issuer = Issuer::new(issuer_metadata);

        let register_options = ClientRegistrationOptions::default().set_jwks(convert_json_to::<Jwks>(r#"{"keys":[{"k":"qHedLw","kty":"oct","kid":"R5OsS5S7xvrW7E0k0t0PwRsskJpdOkyfnAZi8S806Bg"}]}"#).unwrap());

        let client_metadata = ClientMetadata::default();

        let client_error = Client::register_async(
            &DefaultHttpClient,
            &issuer,
            client_metadata,
            Some(register_options),
            None,
        )
        .await
        .unwrap_err();

        assert_eq!(
            "jwks must only contain private keys",
            client_error.error().error.message
        );
    }

    #[tokio::test]
    async fn does_not_accept_public_keys() {
        let registration_endpoint = "https://op.example.com/client/registration".to_string();

        let issuer_metadata = IssuerMetadata {
            registration_endpoint: Some(registration_endpoint.to_string()),
            ..IssuerMetadata::default()
        };

        let issuer = Issuer::new(issuer_metadata);

        let register_options = ClientRegistrationOptions::default().set_jwks(convert_json_to::<Jwks>(r#"{"keys":[{"kty":"EC","kid":"MFZeG102dQiqbANoaMlW_Jmf7fOZmtRsHt77JFhTpF0","crv":"P-256","x":"FWZ9rSkLt6Dx9E3pxLybhdM6xgR5obGsj5_pqmnz5J4","y":"_n8G69C-A2Xl4xUW2lF0i8ZGZnk_KPYrhv4GbTGu5G4"}]}"#).unwrap());

        let client_metadata = ClientMetadata::default();

        let client_error = Client::register_async(
            &DefaultHttpClient,
            &issuer,
            client_metadata,
            Some(register_options),
            None,
        )
        .await
        .unwrap_err();

        assert_eq!(
            "jwks must only contain private keys",
            client_error.error().error.message
        );
    }
}

#[cfg(test)]
mod with_initial_access_token {
    use crate::types::ClientRegistrationOptions;

    use super::*;

    #[tokio::test]
    async fn uses_the_initial_access_token_in_a_bearer_authorization_scheme() {
        let http_client = TestHttpReqRes::new("https://op.example.com/client/registration")
            .assert_request_method(HttpMethod::POST)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .assert_request_header("authorization", vec!["Bearer foobar".to_string()])
            .assert_request_header("content-length", vec!["2".to_string()])
            .assert_request_header("content-type", vec!["application/json".to_string()])
            .assert_request_body("{}")
            .set_response_body(DEFAULT_CLIENT_READ)
            .set_response_status_code(201)
            .build();

        let registration_endpoint = "https://op.example.com/client/registration".to_string();

        let issuer_metadata = IssuerMetadata {
            registration_endpoint: Some(registration_endpoint),
            ..IssuerMetadata::default()
        };

        let issuer = Issuer::new(issuer_metadata);

        let register_options =
            ClientRegistrationOptions::default().set_iniatial_access_token("foobar");

        let _ = Client::register_async(
            &http_client,
            &issuer,
            ClientMetadata::default(),
            Some(register_options),
            None,
        )
        .await
        .unwrap();

        http_client.assert();
    }
}

#[cfg(test)]
mod dynamic_registration_defaults_not_supported_by_issuer {
    use crate::{
        issuer::Issuer,
        types::{ClientMetadata, IssuerMetadata},
    };

    #[test]
    fn token_endpoint_auth_method_vs_token_endpoint_auth_methods_supported() {
        let issuer_metadata = IssuerMetadata {
            issuer: "https://op.example.com".to_string(),
            token_endpoint_auth_methods_supported: Some(vec![
                "client_secret_post".to_string(),
                "private_key_jwt".to_string(),
            ]),
            ..IssuerMetadata::default()
        };
        let issuer = Issuer::new(issuer_metadata);

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            ..ClientMetadata::default()
        };

        let client = issuer.client(client_metadata, None, None, None).unwrap();

        assert_eq!(
            "client_secret_post".to_string(),
            client.token_endpoint_auth_method.unwrap()
        );
    }
}
