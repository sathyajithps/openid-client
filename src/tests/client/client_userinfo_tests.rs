use crate::issuer::Issuer;
use crate::tests::test_interceptors::get_default_test_interceptor;
use crate::tokenset::{TokenSet, TokenSetParams};
use crate::types::{ClientMetadata, IssuerMetadata, UserinfoOptions};
use httpmock::{Method, MockServer};
use serde_json::json;
use std::collections::HashMap;

#[tokio::test]
async fn takes_a_token_set() {
    let mock_http_server = MockServer::start();

    let userinfo_server = mock_http_server.mock(|when, then| {
        when.method(Method::GET)
            .header("Accept", "application/json")
            .header("Authorization", "Bearer tokenValue")
            .path("/me");
        then.status(200).body(r#"{"sub":"subject"}"#);
    });

    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(
        issuer_metadata,
        get_default_test_interceptor(Some(mock_http_server.port())),
    );

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let token_set_params = TokenSetParams {
        id_token: Some("eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdWJqZWN0In0.".to_string()),
        refresh_token: Some("bar".to_string()),
        access_token: Some("tokenValue".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let _ = client
        .userinfo_async(&token_set, UserinfoOptions::default())
        .await
        .unwrap();

    userinfo_server.assert();
}

#[tokio::test]
async fn only_get_and_post_is_supported() {
    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata, get_default_test_interceptor(None));

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let token_set_params = TokenSetParams {
        id_token: Some("eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdWJqZWN0In0.".to_string()),
        refresh_token: Some("bar".to_string()),
        access_token: Some("tokenValue".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let mut options = UserinfoOptions::default();

    options.method = reqwest::Method::PUT;

    let err = client
        .userinfo_async(&token_set, options)
        .await
        .unwrap_err();

    assert!(err.is_type_error());
    assert_eq!(
        "userinfo_async() method can only be POST or a GET",
        err.type_error().error.message
    );
}

#[tokio::test]
async fn takes_a_token_set_with_token() {
    let mock_http_server = MockServer::start();

    let userinfo_server = mock_http_server.mock(|when, then| {
        when.method(Method::GET)
            .header("Accept", "application/json")
            .header("Authorization", "DPoP tokenValue")
            .path("/me");
        then.status(200).body(r#"{"sub":"subject"}"#);
    });

    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(
        issuer_metadata,
        get_default_test_interceptor(Some(mock_http_server.port())),
    );

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let token_set_params = TokenSetParams {
        id_token: Some("eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdWJqZWN0In0.".to_string()),
        refresh_token: Some("bar".to_string()),
        access_token: Some("tokenValue".to_string()),
        token_type: Some("DPoP".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let options = UserinfoOptions::default();

    let _ = client.userinfo_async(&token_set, options).await.unwrap();

    userinfo_server.assert();
}

#[tokio::test]
async fn takes_a_token_set_and_validates_the_subject_in_id_token_is_the_same_in_userinfo() {
    let mock_http_server = MockServer::start();

    let userinfo_server = mock_http_server.mock(|when, then| {
        when.method(Method::GET)
            .header("Accept", "application/json")
            .path("/me");
        then.status(200).body(r#"{"sub":"different-subject"}"#);
    });

    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(
        issuer_metadata,
        get_default_test_interceptor(Some(mock_http_server.port())),
    );

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let token_set_params = TokenSetParams {
        id_token: Some("eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdWJqZWN0In0.".to_string()),
        refresh_token: Some("bar".to_string()),
        access_token: Some("tokenValue".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let options = UserinfoOptions::default();

    let err = client
        .userinfo_async(&token_set, options)
        .await
        .unwrap_err();

    userinfo_server.assert();
    assert!(err.is_rp_error());
    assert_eq!(
        "userinfo sub mismatch, expected subject, got: different-subject",
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn validates_an_access_token_is_present_in_the_tokenset() {
    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata, get_default_test_interceptor(None));

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let token_set_params = TokenSetParams {
        id_token: Some("eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdWJqZWN0In0.".to_string()),
        refresh_token: Some("bar".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let options = UserinfoOptions::default();

    let err = client
        .userinfo_async(&token_set, options)
        .await
        .unwrap_err();

    assert!(err.is_type_error());
    assert_eq!(
        "access_token is required in token_set",
        err.type_error().error.message
    );
}

#[tokio::test]
async fn can_do_a_post_call() {
    let mock_http_server = MockServer::start();

    let userinfo_server = mock_http_server.mock(|when, then| {
        when.method(Method::POST)
            .header("Accept", "application/json")
            .matches(|req| {
                if let Some(h) = &req.headers {
                    return h.iter().all(|(k, _)| k.to_lowercase() != "content-type");
                }
                false
            })
            .path("/me");
        then.status(200).body(r#"{}"#);
    });

    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(
        issuer_metadata,
        get_default_test_interceptor(Some(mock_http_server.port())),
    );

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let token_set_params = TokenSetParams {
        access_token: Some("tokenValue".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let mut options = UserinfoOptions::default();
    options.method = reqwest::Method::POST;

    let _ = client.userinfo_async(&token_set, options).await;

    userinfo_server.assert();
}

#[tokio::test]
async fn can_submit_access_token_in_a_body_when_post() {
    let mock_http_server = MockServer::start();

    let userinfo_server = mock_http_server.mock(|when, then| {
        when.method(Method::POST)
            .header("Accept", "application/json")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .matches(|req| {
                String::from_utf8(req.body.as_ref().unwrap().to_owned()).unwrap()
                    == "access_token=tokenValue"
            })
            .path("/me");
        then.status(200).body("{}");
    });

    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(
        issuer_metadata,
        get_default_test_interceptor(Some(mock_http_server.port())),
    );

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let token_set_params = TokenSetParams {
        access_token: Some("tokenValue".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let mut options = UserinfoOptions::default();
    options.method = reqwest::Method::POST;
    options.via = "body".to_string();

    let _ = client.userinfo_async(&token_set, options).await.unwrap();
    userinfo_server.assert();
}

#[tokio::test]
async fn can_add_extra_params_in_a_body_when_post() {
    let mock_http_server = MockServer::start();

    let userinfo_server = mock_http_server.mock(|when, then| {
        when.method(Method::POST)
            .header("Accept", "application/json")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .matches(|req| {
                let body = String::from_utf8(req.body.as_ref().unwrap().to_owned()).unwrap();
                body == "access_token=tokenValue&foo=bar"
                    || body == "foo=bar&access_token=tokenValue"
            })
            .path("/me");
        then.status(200).body("{}");
    });

    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(
        issuer_metadata,
        get_default_test_interceptor(Some(mock_http_server.port())),
    );

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let token_set_params = TokenSetParams {
        access_token: Some("tokenValue".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let mut options = UserinfoOptions::default();
    options.method = reqwest::Method::POST;
    options.via = "body".to_string();
    let mut params = HashMap::new();
    params.insert("foo".to_string(), json!("bar"));
    options.params = Some(params);

    let _ = client.userinfo_async(&token_set, options).await.unwrap();
    userinfo_server.assert();
}

#[tokio::test]
async fn can_add_extra_params_in_a_body_when_post_but_via_header() {
    let mock_http_server = MockServer::start();

    let userinfo_server = mock_http_server.mock(|when, then| {
        when.method(Method::POST)
            .header("Accept", "application/json")
            .header("Authorization", "Bearer tokenValue")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .matches(|req| {
                String::from_utf8(req.body.as_ref().unwrap().to_owned()).unwrap() == "foo=bar"
            })
            .path("/me");
        then.status(200).body("{}");
    });

    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(
        issuer_metadata,
        get_default_test_interceptor(Some(mock_http_server.port())),
    );

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let token_set_params = TokenSetParams {
        access_token: Some("tokenValue".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let mut options = UserinfoOptions::default();
    options.method = reqwest::Method::POST;

    let mut params = HashMap::new();
    params.insert("foo".to_string(), json!("bar"));
    options.params = Some(params);

    let _ = client.userinfo_async(&token_set, options).await.unwrap();
    userinfo_server.assert();
}

#[tokio::test]
async fn can_add_extra_params_in_a_query_when_non_post() {
    let mock_http_server = MockServer::start();

    let userinfo_server = mock_http_server.mock(|when, then| {
        when.method(Method::GET)
            .header("Accept", "application/json")
            .header("Authorization", "Bearer tokenValue")
            .query_param("foo", "bar")
            .path("/me");
        then.status(200).body("{}");
    });

    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(
        issuer_metadata,
        get_default_test_interceptor(Some(mock_http_server.port())),
    );

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let token_set_params = TokenSetParams {
        access_token: Some("tokenValue".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let mut options = UserinfoOptions::default();

    let mut params = HashMap::new();
    params.insert("foo".to_string(), json!("bar"));
    options.params = Some(params);

    let _ = client.userinfo_async(&token_set, options).await.unwrap();
    userinfo_server.assert();
}

#[tokio::test]
async fn can_only_submit_access_token_in_a_body_when_post() {
    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata, get_default_test_interceptor(None));

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let token_set_params = TokenSetParams {
        access_token: Some("tokenValue".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let mut options = UserinfoOptions::default();

    options.method = reqwest::Method::GET;
    options.via = "body".to_string();

    let err = client
        .userinfo_async(&token_set, options)
        .await
        .unwrap_err();

    assert!(err.is_type_error());
    assert_eq!("can only send body on POST", err.type_error().error.message);
}

#[tokio::test]
async fn is_rejected_with_op_error_upon_oidc_error() {
    let mock_http_server = MockServer::start();

    let _userinfo_server = mock_http_server.mock(|when, then| {
        when.method(Method::GET)
            .header("Accept", "application/json")
            .path("/me");
        then.status(401)
            .body(r#"{"error":"invalid_token","error_description":"bad things are happening"}"#);
    });

    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(
        issuer_metadata,
        get_default_test_interceptor(Some(mock_http_server.port())),
    );

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let token_set_params = TokenSetParams {
        access_token: Some("foo".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let options = UserinfoOptions::default();

    let err = client
        .userinfo_async(&token_set, options)
        .await
        .unwrap_err();

    assert!(err.is_op_error());
    let op_error = err.op_error().error;

    assert_eq!("invalid_token", op_error.error);
    assert_eq!(
        "bad things are happening",
        op_error.error_description.unwrap()
    );
}

#[tokio::test]
async fn is_rejected_with_op_error_upon_oidc_error_in_www_authenticate_header() {
    let mock_http_server = MockServer::start();

    let _userinfo_server = mock_http_server.mock(|when, then| {
        when.method(Method::GET)
            .header("Accept", "application/json")
            .path("/me");
        then.status(401).body("Unauthorized").header(
            "WWW-Authenticate",
            r#"Bearer error="invalid_token", error_description="bad things are happening""#,
        );
    });

    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(
        issuer_metadata,
        get_default_test_interceptor(Some(mock_http_server.port())),
    );

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let token_set_params = TokenSetParams {
        access_token: Some("foo".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let options = UserinfoOptions::default();

    let err = client
        .userinfo_async(&token_set, options)
        .await
        .unwrap_err();

    assert!(err.is_op_error());
    let op_error = err.op_error().error;

    assert_eq!("invalid_token", op_error.error);
    assert_eq!(
        "bad things are happening",
        op_error.error_description.unwrap()
    );
}

#[tokio::test]
async fn is_rejected_with_when_non_200_is_returned() {
    let mock_http_server = MockServer::start();

    let _userinfo_server = mock_http_server.mock(|when, then| {
        when.method(Method::GET)
            .header("Accept", "application/json")
            .path("/me");
        then.status(500).body("Internal Server Error");
    });

    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(
        issuer_metadata,
        get_default_test_interceptor(Some(mock_http_server.port())),
    );

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let token_set_params = TokenSetParams {
        access_token: Some("foo".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let options = UserinfoOptions::default();

    let err = client
        .userinfo_async(&token_set, options)
        .await
        .unwrap_err();

    assert!(err.is_op_error());
    let op_error = err.op_error().error;

    assert_eq!("server_error", op_error.error);
    assert_eq!(
        "expected 200 OK, got: 500 Internal Server Error",
        op_error.error_description.unwrap()
    );
}

#[tokio::test]
async fn is_rejected_with_json_parse_error_upon_invalid_response() {
    let mock_http_server = MockServer::start();

    let _userinfo_server = mock_http_server.mock(|when, then| {
        when.method(Method::GET)
            .header("Accept", "application/json")
            .path("/me");
        then.status(200).body(r#"{"notavalid"}"#);
    });
    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(
        issuer_metadata,
        get_default_test_interceptor(Some(mock_http_server.port())),
    );

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let token_set_params = TokenSetParams {
        access_token: Some("foo".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let options = UserinfoOptions::default();

    let err = client
        .userinfo_async(&token_set, options)
        .await
        .unwrap_err();

    assert!(err.is_type_error());
    let type_error = err.type_error();
    assert!(type_error.response.is_some());
    assert_eq!("unexpected body type", type_error.error.message);
}

#[cfg(test)]
mod signed_response_content_type_application_jwt {

    use super::*;
    use crate::helpers::now;

    #[tokio::test]
    async fn decodes_and_validates_the_jwt_userinfo() {
        let mock_http_server = MockServer::start();

        let iat = now();
        let exp = iat + 100;

        let payload = base64_url::encode(&format!("{{\"iss\":\"https://op.example.com\",\"sub\":\"foobar\",\"aud\":\"foobar\",\"exp\":{},\"iat\":{}}}",exp, iat));
        let header = base64_url::encode(r#"{"alg":"none"}"#);

        let _userinfo_server = mock_http_server.mock(|when, then| {
            when.method(Method::GET)
                .header("Accept", "application/jwt")
                .path("/me");
            then.status(200)
                .body(format!("{}.{}.", header, payload))
                .header("content-type", "application/jwt; charset=utf-8");
        });

        let issuer_metadata = IssuerMetadata {
            issuer: "https://op.example.com".to_string(),
            userinfo_endpoint: Some("https://op.example.com/me".to_string()),
            ..Default::default()
        };

        let issuer = Issuer::new(
            issuer_metadata,
            get_default_test_interceptor(Some(mock_http_server.port())),
        );

        let client_metadata = ClientMetadata {
            client_id: Some("foobar".to_string()),
            userinfo_signed_response_alg: Some("none".to_string()),
            ..Default::default()
        };

        let mut client = issuer
            .client(client_metadata, None, None, None, false)
            .unwrap();

        let token_set_params = TokenSetParams {
            access_token: Some("accessToken".to_string()),
            ..Default::default()
        };

        let token_set = TokenSet::new(token_set_params);

        let options = UserinfoOptions::default();

        let payload = client.userinfo_async(&token_set, options).await.unwrap();

        assert_eq!(
            "https://op.example.com",
            payload.get("iss").unwrap().as_str().unwrap()
        );
        assert_eq!("foobar", payload.get("sub").unwrap().as_str().unwrap());
        assert_eq!("foobar", payload.get("aud").unwrap().as_str().unwrap());
        assert_eq!(exp, payload.get("exp").unwrap().as_i64().unwrap());
        assert_eq!(iat, payload.get("iat").unwrap().as_i64().unwrap());
    }

    #[tokio::test]
    async fn validates_the_used_alg_of_signed_userinfo() {
        let mock_http_server = MockServer::start();

        let payload = base64_url::encode("{}");
        let header = base64_url::encode(r#"{"alg":"none"}"#);

        let _userinfo_server = mock_http_server.mock(|when, then| {
            when.method(Method::GET)
                .header("Accept", "application/jwt")
                .path("/me");
            then.status(200)
                .body(format!("{}.{}.", header, payload))
                .header("content-type", "application/jwt; charset=utf-8");
        });

        let issuer_metadata = IssuerMetadata {
            issuer: "https://op.example.com".to_string(),
            userinfo_endpoint: Some("https://op.example.com/me".to_string()),
            ..Default::default()
        };

        let issuer = Issuer::new(
            issuer_metadata,
            get_default_test_interceptor(Some(mock_http_server.port())),
        );

        let client_metadata = ClientMetadata {
            client_id: Some("foobar".to_string()),
            userinfo_signed_response_alg: Some("RS256".to_string()),
            ..Default::default()
        };

        let mut client = issuer
            .client(client_metadata, None, None, None, false)
            .unwrap();

        let token_set_params = TokenSetParams {
            access_token: Some("foo".to_string()),
            ..Default::default()
        };

        let token_set = TokenSet::new(token_set_params);

        let options = UserinfoOptions::default();

        let err = client
            .userinfo_async(&token_set, options)
            .await
            .unwrap_err();

        assert!(err.is_rp_error());
        assert_eq!(
            "unexpected JWT alg received, expected RS256, got: none",
            err.rp_error().error.message
        );
    }

    #[tokio::test]
    async fn validates_the_response_is_a_application_jwt() {
        let mock_http_server = MockServer::start();

        let _userinfo_server = mock_http_server.mock(|when, then| {
            when.method(Method::GET)
                .header("Accept", "application/jwt")
                .path("/me");
            then.status(200).body("{}");
        });

        let issuer_metadata = IssuerMetadata {
            issuer: "https://op.example.com".to_string(),
            userinfo_endpoint: Some("https://op.example.com/me".to_string()),
            ..Default::default()
        };

        let issuer = Issuer::new(
            issuer_metadata,
            get_default_test_interceptor(Some(mock_http_server.port())),
        );

        let client_metadata = ClientMetadata {
            client_id: Some("foobar".to_string()),
            userinfo_signed_response_alg: Some("RS256".to_string()),
            ..Default::default()
        };

        let mut client = issuer
            .client(client_metadata, None, None, None, false)
            .unwrap();

        let token_set_params = TokenSetParams {
            access_token: Some("foo".to_string()),
            ..Default::default()
        };

        let token_set = TokenSet::new(token_set_params);

        let options = UserinfoOptions::default();

        let err = client
            .userinfo_async(&token_set, options)
            .await
            .unwrap_err();

        assert!(err.is_rp_error());
        assert_eq!(
            "expected application/jwt response from the userinfo_endpoint",
            err.rp_error().error.message
        );
    }
}
