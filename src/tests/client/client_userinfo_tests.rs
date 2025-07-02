use crate::http_client::DefaultHttpClient;
use crate::issuer::Issuer;
use crate::tokenset::{TokenSet, TokenSetParams};
use crate::types::{ClientMetadata, HttpMethod, IssuerMetadata, UserinfoOptions};
use std::collections::HashMap;

use crate::tests::test_http_client::TestHttpReqRes;

#[tokio::test]
async fn takes_a_token_set() {
    let http_client = TestHttpReqRes::new("https://op.example.com/me")
        .assert_request_method(HttpMethod::GET)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header("authorization", vec!["Bearer tokenValue".to_string()])
        .set_response_body(r#"{"sub":"subject"}"#)
        .build();

    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let token_set_params = TokenSetParams {
        id_token: Some("eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdWJqZWN0In0.".to_string()),
        refresh_token: Some("bar".to_string()),
        access_token: Some("tokenValue".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let _ = client
        .userinfo_async(&http_client, &token_set, UserinfoOptions::default())
        .await
        .unwrap();

    http_client.assert();
}

#[tokio::test]
async fn only_get_and_post_is_supported() {
    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let token_set_params = TokenSetParams {
        id_token: Some("eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdWJqZWN0In0.".to_string()),
        refresh_token: Some("bar".to_string()),
        access_token: Some("tokenValue".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let mut options = UserinfoOptions::default();

    options.method = "PUT";

    let err = client
        .userinfo_async(&DefaultHttpClient, &token_set, options)
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
    let http_client = TestHttpReqRes::new("https://op.example.com/me")
        .assert_request_method(HttpMethod::GET)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header("authorization", vec!["DPoP tokenValue".to_string()])
        .set_response_body(r#"{"sub":"subject"}"#)
        .build();

    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let token_set_params = TokenSetParams {
        id_token: Some("eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdWJqZWN0In0.".to_string()),
        refresh_token: Some("bar".to_string()),
        access_token: Some("tokenValue".to_string()),
        token_type: Some("DPoP".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let options = UserinfoOptions::default();

    let _ = client
        .userinfo_async(&http_client, &token_set, options)
        .await
        .unwrap();

    http_client.assert();
}

#[tokio::test]
async fn takes_a_token_set_and_validates_the_subject_in_id_token_is_the_same_in_userinfo() {
    let http_client = TestHttpReqRes::new("https://op.example.com/me")
        .assert_request_method(HttpMethod::GET)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header("authorization", vec!["Bearer tokenValue".to_string()])
        .set_response_body(r#"{"sub":"different-subject"}"#)
        .build();

    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let token_set_params = TokenSetParams {
        id_token: Some("eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdWJqZWN0In0.".to_string()),
        refresh_token: Some("bar".to_string()),
        access_token: Some("tokenValue".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let options = UserinfoOptions::default();

    let err = client
        .userinfo_async(&http_client, &token_set, options)
        .await
        .unwrap_err();

    http_client.assert();

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

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let token_set_params = TokenSetParams {
        id_token: Some("eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdWJqZWN0In0.".to_string()),
        refresh_token: Some("bar".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let options = UserinfoOptions::default();

    let err = client
        .userinfo_async(&DefaultHttpClient, &token_set, options)
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
    let http_client = TestHttpReqRes::new("https://op.example.com/me")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header("authorization", vec!["Bearer tokenValue".to_string()])
        .set_response_body("{}")
        .build();

    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let token_set_params = TokenSetParams {
        access_token: Some("tokenValue".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let mut options = UserinfoOptions::default();
    options.method = "POST";

    let _ = client
        .userinfo_async(&http_client, &token_set, options)
        .await;

    http_client.assert();
}

#[tokio::test]
async fn can_submit_access_token_in_a_body_when_post() {
    let http_client = TestHttpReqRes::new("https://op.example.com/me")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header("content-length", vec!["23".to_string()])
        .assert_request_header(
            "content-type",
            vec!["application/x-www-form-urlencoded".to_string()],
        )
        .assert_request_body("access_token=tokenValue")
        .set_response_body("{}")
        .build();

    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        token_endpoint_auth_method: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let token_set_params = TokenSetParams {
        access_token: Some("tokenValue".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let mut options = UserinfoOptions::default();
    options.method = "POST";
    options.via = "body";

    let _ = client
        .userinfo_async(&http_client, &token_set, options)
        .await
        .unwrap();

    http_client.assert();
}

#[tokio::test]
async fn can_add_extra_params_in_a_body_when_post() {
    let http_client = TestHttpReqRes::new("https://op.example.com/me")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header("content-length", vec!["31".to_string()])
        .assert_request_header(
            "content-type",
            vec!["application/x-www-form-urlencoded".to_string()],
        )
        .assert_request_body("access_token=tokenValue&foo=bar")
        .set_response_body("{}")
        .build();

    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let token_set_params = TokenSetParams {
        access_token: Some("tokenValue".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let mut options = UserinfoOptions::default();
    options.method = "POST";
    options.via = "body";
    let mut params = HashMap::new();
    params.insert("foo".to_string(), "bar".to_string());
    options.params = Some(params);

    let _ = client
        .userinfo_async(&http_client, &token_set, options)
        .await
        .unwrap();

    http_client.assert();
}

#[tokio::test]
async fn can_add_extra_params_in_a_body_when_post_but_via_header() {
    let http_client = TestHttpReqRes::new("https://op.example.com/me")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header("content-length", vec!["7".to_string()])
        .assert_request_header("authorization", vec!["Bearer tokenValue".to_string()])
        .assert_request_header(
            "content-type",
            vec!["application/x-www-form-urlencoded".to_string()],
        )
        .assert_request_body("foo=bar")
        .set_response_body("{}")
        .build();

    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let token_set_params = TokenSetParams {
        access_token: Some("tokenValue".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let mut options = UserinfoOptions::default();
    options.method = "POST";

    let mut params = HashMap::new();
    params.insert("foo".to_string(), "bar".to_string());
    options.params = Some(params);

    let _ = client
        .userinfo_async(&http_client, &token_set, options)
        .await
        .unwrap();

    http_client.assert();
}

#[tokio::test]
async fn can_add_extra_params_in_a_query_when_non_post() {
    let http_client = TestHttpReqRes::new("https://op.example.com/me?foo=bar")
        .assert_request_method(HttpMethod::GET)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header("authorization", vec!["Bearer tokenValue".to_string()])
        .set_response_body("{}")
        .build();

    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let token_set_params = TokenSetParams {
        access_token: Some("tokenValue".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let mut options = UserinfoOptions::default();

    let mut params = HashMap::new();
    params.insert("foo".to_string(), "bar".to_string());
    options.params = Some(params);

    let _ = client
        .userinfo_async(&http_client, &token_set, options)
        .await
        .unwrap();

    http_client.assert();
}

#[tokio::test]
async fn can_only_submit_access_token_in_a_body_when_post() {
    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let token_set_params = TokenSetParams {
        access_token: Some("tokenValue".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let mut options = UserinfoOptions::default();

    options.method = "GET";
    options.via = "body";

    let err = client
        .userinfo_async(&DefaultHttpClient, &token_set, options)
        .await
        .unwrap_err();

    assert!(err.is_type_error());
    assert_eq!("can only send body on POST", err.type_error().error.message);
}

#[tokio::test]
async fn is_rejected_with_op_error_upon_oidc_error() {
    let http_client = TestHttpReqRes::new("https://op.example.com/me")
        .assert_request_method(HttpMethod::GET)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header("authorization", vec!["Bearer foo".to_string()])
        .set_response_status_code(401)
        .set_response_body(
            r#"{"error":"invalid_token","error_description":"bad things are happening"}"#,
        )
        .build();

    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let token_set_params = TokenSetParams {
        access_token: Some("foo".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let options = UserinfoOptions::default();

    let err = client
        .userinfo_async(&http_client, &token_set, options)
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
    let http_client = TestHttpReqRes::new("https://op.example.com/me")
        .assert_request_method(HttpMethod::GET)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header("authorization", vec!["Bearer foo".to_string()])
        .set_response_status_code(401)
        .set_response_body("Unauthorized")
        .set_response_www_authenticate_header(
            r#"Bearer error="invalid_token", error_description="bad things are happening""#,
        )
        .build();

    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let token_set_params = TokenSetParams {
        access_token: Some("foo".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let options = UserinfoOptions::default();

    let err = client
        .userinfo_async(&http_client, &token_set, options)
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
    let http_client = TestHttpReqRes::new("https://op.example.com/me")
        .assert_request_method(HttpMethod::GET)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header("authorization", vec!["Bearer foo".to_string()])
        .set_response_status_code(500)
        .set_response_body("Internal Server Error")
        .build();

    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let token_set_params = TokenSetParams {
        access_token: Some("foo".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let options = UserinfoOptions::default();

    let err = client
        .userinfo_async(&http_client, &token_set, options)
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
    let http_client = TestHttpReqRes::new("https://op.example.com/me")
        .assert_request_method(HttpMethod::GET)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header("authorization", vec!["Bearer foo".to_string()])
        .set_response_status_code(200)
        .set_response_body(r#"{"notavalid"}"#)
        .build();

    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        ..Default::default()
    };

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let token_set_params = TokenSetParams {
        access_token: Some("foo".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let options = UserinfoOptions::default();

    let err = client
        .userinfo_async(&http_client, &token_set, options)
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
        let iat = now();
        let exp = iat + 100;

        let payload = base64_url::encode(&format!("{{\"iss\":\"https://op.example.com\",\"sub\":\"foobar\",\"aud\":\"foobar\",\"exp\":{},\"iat\":{}}}",exp, iat));
        let header = base64_url::encode(r#"{"alg":"none"}"#);

        let http_client = TestHttpReqRes::new("https://op.example.com/me")
            .assert_request_method(HttpMethod::GET)
            .assert_request_header("accept", vec!["application/jwt".to_string()])
            .assert_request_header("authorization", vec!["Bearer accessToken".to_string()])
            .set_response_status_code(200)
            .set_response_body(format!("{}.{}.", header, payload))
            .set_response_content_type_header("application/jwt; charset=utf-8")
            .build();

        let issuer_metadata = IssuerMetadata {
            issuer: "https://op.example.com".to_string(),
            userinfo_endpoint: Some("https://op.example.com/me".to_string()),
            ..Default::default()
        };

        let issuer = Issuer::new(issuer_metadata);

        let client_metadata = ClientMetadata {
            client_id: Some("foobar".to_string()),
            userinfo_signed_response_alg: Some("none".to_string()),
            ..Default::default()
        };

        let mut client = issuer.client(client_metadata, None, None, None).unwrap();

        let token_set_params = TokenSetParams {
            access_token: Some("accessToken".to_string()),
            ..Default::default()
        };

        let token_set = TokenSet::new(token_set_params);

        let options = UserinfoOptions::default();

        let payload = client
            .userinfo_async(&http_client, &token_set, options)
            .await
            .unwrap();

        assert_eq!(
            "https://op.example.com",
            payload.get("iss").unwrap().as_str().unwrap()
        );
        assert_eq!("foobar", payload.get("sub").unwrap().as_str().unwrap());
        assert_eq!("foobar", payload.get("aud").unwrap().as_str().unwrap());
        assert_eq!(exp, payload.get("exp").unwrap().as_u64().unwrap());
        assert_eq!(iat, payload.get("iat").unwrap().as_u64().unwrap());
    }

    #[tokio::test]
    async fn validates_the_used_alg_of_signed_userinfo() {
        let payload = base64_url::encode("{}");
        let header = base64_url::encode(r#"{"alg":"none"}"#);

        let http_client = TestHttpReqRes::new("https://op.example.com/me")
            .assert_request_method(HttpMethod::GET)
            .assert_request_header("accept", vec!["application/jwt".to_string()])
            .assert_request_header("authorization", vec!["Bearer foo".to_string()])
            .set_response_status_code(200)
            .set_response_body(format!("{}.{}.", header, payload))
            .set_response_content_type_header("application/jwt; charset=utf-8")
            .build();

        let issuer_metadata = IssuerMetadata {
            issuer: "https://op.example.com".to_string(),
            userinfo_endpoint: Some("https://op.example.com/me".to_string()),
            ..Default::default()
        };

        let issuer = Issuer::new(issuer_metadata);

        let client_metadata = ClientMetadata {
            client_id: Some("foobar".to_string()),
            userinfo_signed_response_alg: Some("RS256".to_string()),
            ..Default::default()
        };

        let mut client = issuer.client(client_metadata, None, None, None).unwrap();

        let token_set_params = TokenSetParams {
            access_token: Some("foo".to_string()),
            ..Default::default()
        };

        let token_set = TokenSet::new(token_set_params);

        let options = UserinfoOptions::default();

        let err = client
            .userinfo_async(&http_client, &token_set, options)
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
        let http_client = TestHttpReqRes::new("https://op.example.com/me")
            .assert_request_method(HttpMethod::GET)
            .assert_request_header("accept", vec!["application/jwt".to_string()])
            .assert_request_header("authorization", vec!["Bearer foo".to_string()])
            .set_response_status_code(200)
            .set_response_body("{}")
            .build();

        let issuer_metadata = IssuerMetadata {
            issuer: "https://op.example.com".to_string(),
            userinfo_endpoint: Some("https://op.example.com/me".to_string()),
            ..Default::default()
        };

        let issuer = Issuer::new(issuer_metadata);

        let client_metadata = ClientMetadata {
            client_id: Some("foobar".to_string()),
            userinfo_signed_response_alg: Some("RS256".to_string()),
            ..Default::default()
        };

        let mut client = issuer.client(client_metadata, None, None, None).unwrap();

        let token_set_params = TokenSetParams {
            access_token: Some("foo".to_string()),
            ..Default::default()
        };

        let token_set = TokenSet::new(token_set_params);

        let options = UserinfoOptions::default();

        let err = client
            .userinfo_async(&http_client, &token_set, options)
            .await
            .unwrap_err();

        assert!(err.is_rp_error());
        assert_eq!(
            "expected application/jwt response from the userinfo_endpoint",
            err.rp_error().error.message
        );
    }
}

#[tokio::test]
async fn returns_error_if_access_token_is_dpop_bound_but_dpop_was_not_passed_in() {
    let issuer_metadata = IssuerMetadata {
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_signed_response_alg: Some("none".to_string()),
        dpop_bound_access_tokens: Some(true),
        ..Default::default()
    };

    let mut client = issuer.client(client_metadata, None, None, None).unwrap();

    let token_set_params = TokenSetParams {
        id_token: Some("eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdWJqZWN0In0.".to_string()),
        refresh_token: Some("bar".to_string()),
        access_token: Some("tokenValue".to_string()),
        ..Default::default()
    };

    let token_set = TokenSet::new(token_set_params);

    let err = client
        .userinfo_async(&DefaultHttpClient, &token_set, UserinfoOptions::default())
        .await
        .unwrap_err();

    assert!(err.is_type_error());

    assert_eq!("DPoP key not set", err.type_error().error.message);
}
