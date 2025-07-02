use crate::{
    client::Client,
    issuer::Issuer,
    types::{ClientMetadata, IssuerMetadata},
};

fn get_client() -> (Issuer, Client) {
    let issuer_metadata = IssuerMetadata {
        issuer: "https://op.example.com".to_string(),
        device_authorization_endpoint: Some("https://op.example.com/auth/device".to_string()),
        token_endpoint: Some("https://op.example.com/token".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("client".to_string()),
        token_endpoint_auth_method: Some("none".to_string()),
        ..Default::default()
    };

    let client = issuer.client(client_metadata, None, None, None).unwrap();
    (issuer, client)
}

#[cfg(test)]
mod device_authorization {
    use serde_json::json;

    use crate::{
        http_client::DefaultHttpClient,
        types::{DeviceAuthorizationParams, HttpMethod},
    };

    use crate::tests::test_http_client::TestHttpReqRes;

    use super::*;

    #[tokio::test]
    async fn returns_a_handle_without_optional_response_parameters() {
        let http_client = TestHttpReqRes::new("https://op.example.com/auth/device")
            .assert_request_method(HttpMethod::POST)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .assert_request_header(
                "content-type",
                vec!["application/x-www-form-urlencoded".to_string()],
            )
            .assert_request_header("content-length", vec!["56".to_string()])
            .assert_request_body("client_id=client&response_type=code&scope=openid&foo=bar")
            .set_response_content_type_header("application/json")
            .set_response_body(
                r#"{
                "verification_uri": "https://op.example.com/device",
                "user_code": "AAAA-AAAA",
                "device_code": "foobar",
                "expires_in": 300
              }"#,
            )
            .build();

        let (_, mut client) = get_client();

        let mut params = DeviceAuthorizationParams::default();
        params.other.insert("foo".to_string(), json!("bar"));

        let handle = client
            .device_authorization_async(&http_client, params, None)
            .await
            .unwrap();

        assert_eq!("AAAA-AAAA", handle.user_code());
        assert_eq!("foobar", handle.device_code());
        assert_eq!("https://op.example.com/device", handle.verification_uri());
        assert_eq!(None, handle.verification_uri_complete());
        assert!(handle.expires_in() <= 300);
        assert_eq!(false, handle.expired());
    }

    #[tokio::test]
    async fn returns_a_handle_with_optional_response_parameters() {
        let http_client = TestHttpReqRes::new("https://op.example.com/auth/device")
            .assert_request_method(HttpMethod::POST)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .assert_request_header(
                "content-type",
                vec!["application/x-www-form-urlencoded".to_string()],
            )
            .assert_request_header("content-length", vec!["48".to_string()])
            .assert_request_body("client_id=client&response_type=code&scope=openid")
            .set_response_content_type_header("application/json")
            .set_response_body(
                r#"{
                "verification_uri": "https://op.example.com/device",
                "verification_uri_complete": "https://op.example.com/device/AAAA-AAAA",
                "user_code": "AAAA-AAAA",
                "device_code": "foobar",
                "expires_in": 300,
                "interval": 5
              }"#,
            )
            .build();

        let (_, mut client) = get_client();

        let handle = client
            .device_authorization_async(&http_client, DeviceAuthorizationParams::default(), None)
            .await
            .unwrap();

        assert_eq!("AAAA-AAAA", handle.user_code());
        assert_eq!("foobar", handle.device_code());
        assert_eq!("https://op.example.com/device", handle.verification_uri());
        assert_eq!(
            "https://op.example.com/device/AAAA-AAAA",
            handle.verification_uri_complete().unwrap()
        );
        assert!(handle.expires_in() <= 300);
        assert_eq!(false, handle.expired());
        assert_eq!(5, handle.interval());
    }

    #[tokio::test]
    async fn requires_the_issuer_to_have_device_authorization_endpoint() {
        let (mut issuer, mut client) = get_client();

        issuer.device_authorization_endpoint = None;

        client.issuer = Some(issuer);

        let err = client
            .device_authorization_async(
                &DefaultHttpClient,
                DeviceAuthorizationParams::default(),
                None,
            )
            .await
            .unwrap_err();

        assert!(err.is_type_error());
        assert_eq!(
            "device_authorization_endpoint must be configured on the issuer",
            err.type_error().error.message
        );
    }

    #[tokio::test]
    async fn requires_the_issuer_to_have_token_endpoint() {
        let (mut issuer, mut client) = get_client();

        issuer.token_endpoint = None;

        client.issuer = Some(issuer);

        let err = client
            .device_authorization_async(
                &DefaultHttpClient,
                DeviceAuthorizationParams::default(),
                None,
            )
            .await
            .unwrap_err();

        assert!(err.is_type_error());
        assert_eq!(
            "token_endpoint must be configured on the issuer",
            err.type_error().error.message
        );
    }
}

#[cfg(test)]
mod device_flow_handle {
    use crate::{
        client::DeviceFlowHandle,
        http_client::DefaultHttpClient,
        types::{DeviceAuthorizationResponse, DeviceFlowGrantResponse, HttpMethod},
    };

    use crate::tests::test_http_client::TestHttpReqRes;

    use super::*;

    #[tokio::test]
    async fn calls_the_token_endpoint_and_returns_the_tokenset() {
        let http_client = TestHttpReqRes::new("https://op.example.com/token")
            .assert_request_method(HttpMethod::POST)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .assert_request_header(
                "content-type",
                vec!["application/x-www-form-urlencoded".to_string()],
            )
            .assert_request_header("content-length", vec!["101".to_string()])
            .assert_request_body("client_id=client&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=foobar")
            .set_response_content_type_header("application/json")
            .set_response_body(
                r#"{
                    "expires_in": 300,
                    "access_token": "at"
                  }"#,
            )
            .build();

        let (_, client) = get_client();

        let mut handle = DeviceFlowHandle::new(
            client,
            DeviceAuthorizationResponse {
                verification_uri: "https://op.example.com/device".to_string(),
                user_code: "AAAA-AAAA".to_string(),
                device_code: "foobar".to_string(),
                interval: Some(5),
                expires_in: 300,
                verification_uri_complete: None,
            },
            None,
            None,
        );

        let res = handle.grant_async(&http_client).await.unwrap();

        if let DeviceFlowGrantResponse::Successful(_) = res {
            assert!(true);
        } else {
            assert!(false);
        }
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
        .assert_request_header("content-length", vec!["101".to_string()])
        .assert_request_body("client_id=client&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=foobar")
        .set_response_content_type_header("application/json")
        .set_response_body(r#"{"error": "slow_down"}"#)
        .set_response_status_code(400)
        .build();

        let (_, client) = get_client();

        let mut handle = DeviceFlowHandle::new(
            client,
            DeviceAuthorizationResponse {
                verification_uri: "https://op.example.com/device".to_string(),
                user_code: "AAAA-AAAA".to_string(),
                device_code: "foobar".to_string(),
                interval: Some(5),
                expires_in: 300,
                verification_uri_complete: None,
            },
            None,
            None,
        );

        let interval = handle.interval();

        let res = handle.grant_async(&http_client).await.unwrap();

        if handle.interval() == interval + 5 {
            if let DeviceFlowGrantResponse::SlowDown = res {
                assert!(true);
                return;
            }
        }

        assert!(false);
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
        .assert_request_header("content-length", vec!["101".to_string()])
        .assert_request_body("client_id=client&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=foobar")
        .set_response_content_type_header("application/json")
        .set_response_body(r#"{"error":"authorization_pending"}"#)
        .set_response_status_code(400)
        .build();

        let (_, client) = get_client();

        let mut handle = DeviceFlowHandle::new(
            client,
            DeviceAuthorizationResponse {
                verification_uri: "https://op.example.com/device".to_string(),
                user_code: "AAAA-AAAA".to_string(),
                device_code: "foobar".to_string(),
                interval: Some(5),
                expires_in: 300,
                verification_uri_complete: None,
            },
            None,
            None,
        );

        let interval = handle.interval();

        let res = handle.grant_async(&http_client).await.unwrap();

        if handle.interval() == interval {
            if let DeviceFlowGrantResponse::AuthorizationPending = res {
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
        .assert_request_header("content-length", vec!["101".to_string()])
        .assert_request_body("client_id=client&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=foobar")
        .set_response_content_type_header("application/json")
        .set_response_body( r#"{
            "id_token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdWJqZWN0In0.",
            "refresh_token": "bar",
            "access_token": "tokenValue"
          }"#,)
        .build();

        let (_, client) = get_client();

        let mut handle = DeviceFlowHandle::new(
            client,
            DeviceAuthorizationResponse {
                verification_uri: "https://op.example.com/device".to_string(),
                user_code: "AAAA-AAAA".to_string(),
                device_code: "foobar".to_string(),
                interval: Some(5),
                expires_in: 300,
                verification_uri_complete: None,
            },
            None,
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
        .assert_request_header("content-length", vec!["101".to_string()])
        .assert_request_body("client_id=client&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=foobar")
        .set_response_content_type_header("application/json")
        .set_response_body(r#"{
            "error": "server_error",
            "error_description": "bad things are happening"
          }"#,)
          .set_response_status_code(400)
        .build();

        let (_, client) = get_client();

        let mut handle = DeviceFlowHandle::new(
            client,
            DeviceAuthorizationResponse {
                verification_uri: "https://op.example.com/device".to_string(),
                user_code: "AAAA-AAAA".to_string(),
                device_code: "foobar".to_string(),
                interval: Some(5),
                expires_in: 300,
                verification_uri_complete: None,
            },
            None,
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
    async fn does_not_grant_when_expired() {
        let (_, client) = get_client();

        let mut handle = DeviceFlowHandle::new(
            client,
            DeviceAuthorizationResponse {
                verification_uri: "https://op.example.com/device".to_string(),
                user_code: "AAAA-AAAA".to_string(),
                device_code: "foobar".to_string(),
                interval: Some(5),
                expires_in: 0,
                verification_uri_complete: None,
            },
            None,
            None,
        );

        let err = handle.grant_async(&DefaultHttpClient).await.unwrap_err();

        assert!(err.is_rp_error());
        assert_eq!(
            "the device code foobar has expired and the device authorization session has concluded",
            err.rp_error().error.message
        );
    }

    #[tokio::test]
    async fn the_handle_tracks_expiration_of_the_device_code() {
        let (_, mut client) = get_client();

        client.now = || 1699172;

        let mut handle = DeviceFlowHandle::new(
            client,
            DeviceAuthorizationResponse {
                verification_uri: "https://op.example.com/device".to_string(),
                user_code: "AAAA-AAAA".to_string(),
                device_code: "foobar".to_string(),
                interval: Some(5),
                expires_in: 300,
                verification_uri_complete: None,
            },
            None,
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
        .assert_request_header("content-length", vec!["101".to_string()])
        .assert_request_body("client_id=client&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=foobar")
        .set_response_content_type_header("application/json")
        .set_response_body( r#"{"error": "authorization_pending"}"#,)
          .set_response_status_code(400)
        .build();

        let (_, mut client) = get_client();

        client.now = || 1699172;

        let mut handle = DeviceFlowHandle::new(
            client,
            DeviceAuthorizationResponse {
                verification_uri: "https://op.example.com/device".to_string(),
                user_code: "AAAA-AAAA".to_string(),
                device_code: "foobar".to_string(),
                interval: Some(5),
                expires_in: 300,
                verification_uri_complete: None,
            },
            None,
            None,
        );

        handle.now = || 1699172;

        let _ = handle.grant_async(&http_client).await.unwrap();

        handle.now = || 1699174;

        let res = handle.grant_async(&http_client).await.unwrap();

        if let DeviceFlowGrantResponse::Debounced = res {
            assert!(true);
            return;
        }

        assert!(false);
    }
}
