use crate::{
    client::Client,
    issuer::Issuer,
    types::{ClientMetadata, IssuerMetadata},
};

fn get_client() -> (Issuer, Client) {
    let issuer_metadata = IssuerMetadata {
        issuer: "https://op.example.com".to_string(),
        backchannel_authentication_endpoint: Some("https://op.example.com/auth/ciba".to_string()),
        token_endpoint: Some("https://op.example.com/token".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("client".to_string()),
        token_endpoint_auth_method: Some("none".to_string()),
        backchannel_token_delivery_mode: Some("poll".to_string()),
        ..Default::default()
    };

    let client = issuer.client(client_metadata, None, None, None).unwrap();
    (issuer, client)
}

#[cfg(test)]
mod ciba_authorization {
    use std::collections::HashMap;

    use crate::{
        client::{client::client_test::client_ciba_tests::get_client, CibaHandle},
        tests::test_http_client::TestHttpReqRes,
        types::{CibaAuthRequest, CibaAuthResponse, CibaGrantResponse, HttpMethod},
    };

    #[tokio::test]
    async fn returns_a_handle_to_poll_token_endpoint() {
        let http_client = TestHttpReqRes::new("https://op.example.com/auth/ciba")
            .assert_request_method(HttpMethod::POST)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .assert_request_header(
                "content-type",
                vec!["application/x-www-form-urlencoded".to_string()],
            )
            .assert_request_header("content-length", vec!["223".to_string()])
            .assert_request_body("client_id=client&scope=openid&foo=bar&user_code=NotPassword&client_notification_token=token_client&id_token_hint=id_token_hint&requested_expiry=500&binding_message=Pay&login_hint=login_hint&login_hint_token=login_hint_token")
            .set_response_content_type_header("application/json")
            .set_response_body(
                r#"{
                "auth_req_id": "abcd",
                "expires_in": 500,
                "interval": 5
              }"#,
            )
            .build();

        let (_, mut client) = get_client();

        let ciba_request = CibaAuthRequest::new()
            .add_scope("openid")
            .set_requested_expiry(500)
            .set_binding_message("Pay")
            .set_client_notification_token("token_client")
            .set_user_code("NotPassword")
            .set_login_hint("login_hint")
            .set_login_hint_token("login_hint_token")
            .set_id_token_hint("id_token_hint")
            .add_request_body_param("foo", "bar");

        let (response, handle) = client
            .ciba_authenticate_async(&http_client, ciba_request, None)
            .await
            .unwrap();

        let handle = handle.unwrap();

        assert_eq!("abcd", response.auth_req_id);
        assert_eq!("abcd", handle.response().auth_req_id);
        assert_eq!(500, response.expires_in);
        assert_eq!(500, handle.response().expires_in);
        assert_eq!(Some(5), response.interval);
        assert_eq!(Some(5), handle.response().interval);
        assert!(handle.expires_in() <= 500);
        assert_eq!(false, handle.expired());
    }

    #[tokio::test]
    async fn retruns_error_if_status_code_is_not_200() {
        let http_client = TestHttpReqRes::new("https://op.example.com/auth/ciba")
            .assert_request_method(HttpMethod::POST)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .assert_request_header("content-length", vec!["29".to_string()])
            .assert_request_header(
                "content-type",
                vec!["application/x-www-form-urlencoded".to_string()],
            )
            .assert_request_body("client_id=client&scope=openid")
            .set_response_content_type_header("application/json")
            .set_response_status_code(201)
            .set_response_body(
                r#"{
                "auth_req_id": "abcd",
                "expires_in": 500,
                "interval": 5
              }"#,
            )
            .build();

        let (_, mut client) = get_client();

        let ciba_request = CibaAuthRequest::new().add_scope("openid");

        let err = client
            .ciba_authenticate_async(&http_client, ciba_request, None)
            .await;

        assert!(err.is_err());

        let op_error = err.err().unwrap();

        assert!(op_error.is_op_error());

        let op_error = op_error.op_error();

        assert_eq!(
            Some("expected 200 OK, got: 201 Created".into()),
            op_error.error.error_description
        );

        assert_eq!("server_error", op_error.error.error);
    }

    #[tokio::test]
    async fn calls_the_token_endpoint_and_returns_the_tokenset() {
        let http_client = TestHttpReqRes::new("https://op.example.com/token")
            .assert_request_method(HttpMethod::POST)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .assert_request_header(
                "content-type",
                vec!["application/x-www-form-urlencoded".to_string()],
            )
            .assert_request_header("content-length", vec!["86".to_string()])
            .assert_request_body("client_id=client&auth_req_id=abcd&grant_type=urn%3Aopenid%3Aparams%3Agrant-type%3Aciba")
            .set_response_content_type_header("application/json")
            .set_response_body(
                r#"{
                "auth_req_id": "abcd",
                "access_token": "G5kXH2wHvUra0sHlDy1iTkDJgsgUO1bN",
                "token_type": "Bearer",
                "refresh_token": "4bwc0ESC_IAhflf-ACC_vjD_ltc11ne-8gFPfA2Kx16",
                "expires_in": 120
              }"#,
            )
            .build();

        let (_, client) = get_client();

        let mut handle = CibaHandle::new(
            client,
            CibaAuthResponse {
                auth_req_id: "abcd".to_string(),
                expires_in: 500,
                interval: Some(5),
                timestamp: None,
                others: HashMap::default(),
            },
            None,
        );

        let result = handle.grant_async(&http_client).await.unwrap();

        if let CibaGrantResponse::Successful(_) = result {
            assert!(true)
        } else {
            assert!(false)
        }
    }

    #[tokio::test]
    async fn returns_auth_pending_response_when_authorization_pending_is_received_with_the_same_interval(
    ) {
        let http_client = TestHttpReqRes::new("https://op.example.com/token")
            .assert_request_method(HttpMethod::POST)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .assert_request_header(
                "content-type",
                vec!["application/x-www-form-urlencoded".to_string()],
            )
            .assert_request_header("content-length", vec!["86".to_string()])
            .assert_request_body("client_id=client&auth_req_id=abcd&grant_type=urn%3Aopenid%3Aparams%3Agrant-type%3Aciba")
            .set_response_content_type_header("application/json")
            .set_response_status_code(400)
            .set_response_body(r#"{"error": "authorization_pending"}"#)
            .build();

        let (_, client) = get_client();

        let mut handle = CibaHandle::new(
            client,
            CibaAuthResponse {
                auth_req_id: "abcd".to_string(),
                expires_in: 500,
                interval: Some(5),
                timestamp: None,
                others: HashMap::default(),
            },
            None,
        );

        let interval = handle.interval();

        let result = handle.grant_async(&http_client).await.unwrap();

        if handle.interval() == interval {
            if let CibaGrantResponse::AuthorizationPending = result {
                assert!(true);
                return;
            }
        }

        assert!(false);
    }

    #[tokio::test]
    async fn returns_slowdown_response_when_slow_down_is_received_and_increases_the_interval_by_5_sec(
    ) {
        let http_client = TestHttpReqRes::new("https://op.example.com/token")
            .assert_request_method(HttpMethod::POST)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .assert_request_header(
                "content-type",
                vec!["application/x-www-form-urlencoded".to_string()],
            )
            .assert_request_header("content-length", vec!["86".to_string()])
            .assert_request_body("client_id=client&auth_req_id=abcd&grant_type=urn%3Aopenid%3Aparams%3Agrant-type%3Aciba")
            .set_response_content_type_header("application/json")
            .set_response_status_code(400)
            .set_response_body(r#"{"error": "slow_down"}"#)
            .build();

        let (_, client) = get_client();

        let mut handle = CibaHandle::new(
            client,
            CibaAuthResponse {
                auth_req_id: "abcd".to_string(),
                expires_in: 500,
                interval: Some(5),
                timestamp: None,
                others: HashMap::default(),
            },
            None,
        );

        let interval = handle.interval();

        let result = handle.grant_async(&http_client).await.unwrap();

        if handle.interval() == interval + 5 {
            if let CibaGrantResponse::SlowDown = result {
                assert!(true);
                return;
            }
        }

        assert!(false);
    }

    #[tokio::test]
    async fn validates_the_id_token_when_there_is_one_returned() {
        let http_client = TestHttpReqRes::new("https://op.example.com/token")
            .assert_request_method(HttpMethod::POST)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .assert_request_header(
                "content-type",
                vec!["application/x-www-form-urlencoded".to_string()],
            )
            .assert_request_header("content-length", vec!["86".to_string()])
            .assert_request_body("client_id=client&auth_req_id=abcd&grant_type=urn%3Aopenid%3Aparams%3Agrant-type%3Aciba")
            .set_response_content_type_header("application/json")
            .set_response_body(
                r#"{
                "auth_req_id": "abcd",
                "id_token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdWJqZWN0IiwidXJuOm9wZW5pZDpwYXJhbXM6and0OmNsYWltOmF1dGhfcmVxX2lkIjoiYWJjZCJ9.",
                "access_token": "G5kXH2wHvUra0sHlDy1iTkDJgsgUO1bN",
                "token_type": "Bearer",
                "refresh_token": "4bwc0ESC_IAhflf-ACC_vjD_ltc11ne-8gFPfA2Kx16",
                "expires_in": 120
              }"#,
            )
            .build();

        let (_, client) = get_client();

        let mut handle = CibaHandle::new(
            client,
            CibaAuthResponse {
                auth_req_id: "abcd".to_string(),
                expires_in: 500,
                interval: Some(5),
                timestamp: None,
                others: HashMap::default(),
            },
            None,
        );

        let err = handle.grant_async(&http_client).await.unwrap_err();

        assert!(err.is_rp_error());
        assert_eq!(
            "unexpected JWT alg received, expected RS256, got: none",
            err.rp_error().error.message
        );
    }

    #[tokio::test]
    async fn returns_on_other_errors_and_rejects() {
        let http_client = TestHttpReqRes::new("https://op.example.com/token")
            .assert_request_method(HttpMethod::POST)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .assert_request_header(
                "content-type",
                vec!["application/x-www-form-urlencoded".to_string()],
            )
            .assert_request_header("content-length", vec!["86".to_string()])
            .assert_request_body("client_id=client&auth_req_id=abcd&grant_type=urn%3Aopenid%3Aparams%3Agrant-type%3Aciba")
            .set_response_content_type_header("application/json")
            .set_response_body(r#"{
            "error": "server_error",
            "error_description": "bad things are happening"
            }"#,)
            .set_response_status_code(400)
            .build();

        let (_, client) = get_client();

        let mut handle = CibaHandle::new(
            client,
            CibaAuthResponse {
                auth_req_id: "abcd".to_string(),
                expires_in: 500,
                interval: Some(5),
                timestamp: None,
                others: HashMap::default(),
            },
            None,
        );

        let err = handle.grant_async(&http_client).await.unwrap_err();

        assert!(err.is_op_error());
        let op_error = err.op_error();
        assert_eq!("server_error", op_error.error.error);
        assert_eq!(
            "bad things are happening",
            op_error.error.error_description.unwrap()
        );
    }

    #[tokio::test]
    async fn the_handle_tracks_expiration_of_the_device_code() {
        let (_, mut client) = get_client();

        client.now = || 1699172;

        let mut handle = CibaHandle::new(
            client,
            CibaAuthResponse {
                auth_req_id: "abcd".to_string(),
                expires_in: 300,
                interval: Some(5),
                timestamp: None,
                others: HashMap::default(),
            },
            None,
        );

        handle.now = || 1699172;

        assert_eq!(false, handle.expired());

        handle.now = || 1699272;

        assert_eq!(false, handle.expired());

        handle.now = || 1699500;

        assert_eq!(true, handle.expired());
    }

    #[tokio::test]
    async fn debounces_if_requested_within_interval() {
        let http_client = TestHttpReqRes::new("https://op.example.com/token")
            .assert_request_method(HttpMethod::POST)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .assert_request_header(
                "content-type",
                vec!["application/x-www-form-urlencoded".to_string()],
            )
            .assert_request_header("content-length", vec!["86".to_string()])
            .assert_request_body("client_id=client&auth_req_id=abcd&grant_type=urn%3Aopenid%3Aparams%3Agrant-type%3Aciba")
            .set_response_content_type_header("application/json")
            .set_response_status_code(400)
            .set_response_body(r#"{"error": "authorization_pending"}"#)
            .build();

        let (_, mut client) = get_client();

        client.now = || 1699172;

        let mut handle = CibaHandle::new(
            client,
            CibaAuthResponse {
                auth_req_id: "abcd".to_string(),
                expires_in: 300,
                interval: Some(5),
                timestamp: None,
                others: HashMap::default(),
            },
            None,
        );

        handle.now = || 1699172;

        let _ = handle.grant_async(&http_client).await.unwrap();

        handle.now = || 1699174;

        let res = handle.grant_async(&http_client).await.unwrap();

        if let CibaGrantResponse::Debounced = res {
            assert!(true);
            return;
        }

        assert!(false);
    }
}
