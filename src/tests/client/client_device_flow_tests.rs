use crate::{
    client::Client,
    issuer::Issuer,
    tests::test_interceptors::get_default_test_interceptor,
    types::{ClientMetadata, IssuerMetadata},
};

fn get_client(port: Option<u16>) -> (Issuer, Client) {
    let issuer_metadata = IssuerMetadata {
        issuer: "https://op.example.com".to_string(),
        device_authorization_endpoint: Some("https://op.example.com/auth/device".to_string()),
        token_endpoint: Some("https://op.example.com/token".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata, get_default_test_interceptor(port));

    let client_metadata = ClientMetadata {
        client_id: Some("client".to_string()),
        token_endpoint_auth_method: Some("none".to_string()),
        ..Default::default()
    };

    let client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();
    (issuer, client)
}

#[cfg(test)]
mod device_authorization {
    use httpmock::{Method::POST, MockServer};
    use serde_json::json;

    use crate::types::DeviceAuthorizationParams;

    use super::*;

    #[tokio::test]
    async fn returns_a_handle_without_optional_response_parameters() {
        let mock_http_server = MockServer::start();

        let _server = mock_http_server.mock(|when, then| {
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

                    let client_id = kvp
                        .iter()
                        .find(|(k, v)| k == &"client_id" && v == &"client");
                    let scope = kvp.iter().find(|(k, v)| k == &"scope" && v == &"openid");
                    let foo = kvp.iter().find(|(k, v)| k == &"foo" && v == &"bar");
                    client_id.is_some()
                        && scope.is_some()
                        && foo.is_some()
                        && content_length_exists
                        && no_transfer_encoding
                })
                .path("/auth/device");
            then.status(200).body(
                r#"{
                "verification_uri": "https://op.example.com/device",
                "user_code": "AAAA-AAAA",
                "device_code": "foobar",
                "expires_in": 300
              }"#,
            );
        });

        let (_, mut client) = get_client(Some(mock_http_server.port()));

        let mut params = DeviceAuthorizationParams::default();
        params.other.insert("foo".to_string(), json!("bar"));

        let handle = client
            .device_authorization_async(params, None)
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
        let mock_http_server = MockServer::start();

        let _server = mock_http_server.mock(|when, then| {
            when.method(POST).path("/auth/device");
            then.status(200).body(
                r#"{
                    "verification_uri": "https://op.example.com/device",
                    "verification_uri_complete": "https://op.example.com/device/AAAA-AAAA",
                    "user_code": "AAAA-AAAA",
                    "device_code": "foobar",
                    "expires_in": 300,
                    "interval": 0.006
                  }"#,
            );
        });

        let (_, mut client) = get_client(Some(mock_http_server.port()));

        let handle = client
            .device_authorization_async(DeviceAuthorizationParams::default(), None)
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
        assert_eq!(0.006, handle.interval());
    }

    #[tokio::test]
    async fn requires_the_issuer_to_have_device_authorization_endpoint() {
        let (mut issuer, mut client) = get_client(None);

        issuer.device_authorization_endpoint = None;

        client.issuer = Some(issuer);

        let err = client
            .device_authorization_async(DeviceAuthorizationParams::default(), None)
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
        let (mut issuer, mut client) = get_client(None);

        issuer.token_endpoint = None;

        client.issuer = Some(issuer);

        let err = client
            .device_authorization_async(DeviceAuthorizationParams::default(), None)
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
    use httpmock::{Method::POST, MockServer};

    use crate::{
        client::DeviceFlowHandle,
        types::{DeviceAuthorizationResponse, DeviceFlowGrantResponse},
    };

    use super::*;

    #[tokio::test]
    async fn calls_the_token_endpoint_and_returns_the_tokenset() {
        let mock_http_server = MockServer::start();

        let _server = mock_http_server.mock(|when, then| {
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

                    let client_id = kvp
                        .iter()
                        .find(|(k, v)| k == &"client_id" && v == &"client");
                    let grant_type = kvp.iter().find(|(k, v)| {
                        k == &"grant_type" && v == &"urn:ietf:params:oauth:grant-type:device_code"
                    });
                    let device_code = kvp
                        .iter()
                        .find(|(k, v)| k == &"device_code" && v == &"foobar");
                    client_id.is_some()
                        && grant_type.is_some()
                        && device_code.is_some()
                        && content_length_exists
                        && no_transfer_encoding
                })
                .path("/token");
            then.status(200).body(
                r#"{
                    "expires_in": 300,
                    "access_token": "at"
                  }"#,
            );
        });

        let (_, client) = get_client(Some(mock_http_server.port()));

        let mut handle = DeviceFlowHandle::new(
            client,
            DeviceAuthorizationResponse {
                verification_uri: "https://op.example.com/device".to_string(),
                user_code: "AAAA-AAAA".to_string(),
                device_code: "foobar".to_string(),
                interval: Some(0.005),
                expires_in: 300,
                verification_uri_complete: None,
            },
            None,
            None,
        );

        let res = handle.grant_async().await.unwrap();

        if let DeviceFlowGrantResponse::Successful(_) = res {
        } else {
            assert!(false);
        }
    }

    #[tokio::test]
    async fn returns_slowdown_response_when_slow_down_is_received_and_increases_the_interval_by_5_sec(
    ) {
        let mock_http_server = MockServer::start();

        let _server = mock_http_server.mock(|when, then| {
            when.method(POST)
                .header("accept", "application/json")
                .matches(|req| {
                    let decoded = urlencoding::decode(
                        std::str::from_utf8(&req.body.as_ref().unwrap()).unwrap(),
                    )
                    .unwrap();

                    let kvp = querystring::querify(&decoded);

                    let client_id = kvp
                        .iter()
                        .find(|(k, v)| k == &"client_id" && v == &"client");
                    let grant_type = kvp.iter().find(|(k, v)| {
                        k == &"grant_type" && v == &"urn:ietf:params:oauth:grant-type:device_code"
                    });
                    let device_code = kvp
                        .iter()
                        .find(|(k, v)| k == &"device_code" && v == &"foobar");
                    client_id.is_some() && grant_type.is_some() && device_code.is_some()
                })
                .path("/token");
            then.status(400).body(
                r#"{
                    "error": "slow_down"
                  }"#,
            );
        });

        let (_, client) = get_client(Some(mock_http_server.port()));

        let mut handle = DeviceFlowHandle::new(
            client,
            DeviceAuthorizationResponse {
                verification_uri: "https://op.example.com/device".to_string(),
                user_code: "AAAA-AAAA".to_string(),
                device_code: "foobar".to_string(),
                interval: Some(0.005),
                expires_in: 300,
                verification_uri_complete: None,
            },
            None,
            None,
        );

        let interval = handle.interval();

        let res = handle.grant_async().await.unwrap();

        if handle.interval() == interval + 5.0 {
            if let DeviceFlowGrantResponse::SlowDown = res {
                return;
            }
        }

        assert!(false);
    }

    #[tokio::test]
    async fn returns_auth_pending_response_when_authorization_pending_is_received_with_the_same_interval(
    ) {
        let mock_http_server = MockServer::start();

        let _server = mock_http_server.mock(|when, then| {
            when.method(POST)
                .header("accept", "application/json")
                .matches(|req| {
                    let decoded = urlencoding::decode(
                        std::str::from_utf8(&req.body.as_ref().unwrap()).unwrap(),
                    )
                    .unwrap();

                    let kvp = querystring::querify(&decoded);

                    let client_id = kvp
                        .iter()
                        .find(|(k, v)| k == &"client_id" && v == &"client");
                    let grant_type = kvp.iter().find(|(k, v)| {
                        k == &"grant_type" && v == &"urn:ietf:params:oauth:grant-type:device_code"
                    });
                    let device_code = kvp
                        .iter()
                        .find(|(k, v)| k == &"device_code" && v == &"foobar");
                    client_id.is_some() && grant_type.is_some() && device_code.is_some()
                })
                .path("/token");
            then.status(400).body(
                r#"{
                    "error": "authorization_pending"
                  }"#,
            );
        });

        let (_, client) = get_client(Some(mock_http_server.port()));

        let mut handle = DeviceFlowHandle::new(
            client,
            DeviceAuthorizationResponse {
                verification_uri: "https://op.example.com/device".to_string(),
                user_code: "AAAA-AAAA".to_string(),
                device_code: "foobar".to_string(),
                interval: Some(0.005),
                expires_in: 300,
                verification_uri_complete: None,
            },
            None,
            None,
        );

        let interval = handle.interval();

        let res = handle.grant_async().await.unwrap();

        if handle.interval() == interval {
            if let DeviceFlowGrantResponse::AuthorizationPending = res {
                return;
            }
        }

        assert!(false);
    }

    #[tokio::test]
    async fn validates_the_id_token_when_there_is_one_returned() {
        let mock_http_server = MockServer::start();

        let _server = mock_http_server.mock(|when, then| {
            when.method(POST).path("/token");
            then.status(200).body(
                r#"{
                    "id_token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdWJqZWN0In0.",
                    "refresh_token": "bar",
                    "access_token": "tokenValue"
                  }"#,
            );
        });

        let (_, client) = get_client(Some(mock_http_server.port()));

        let mut handle = DeviceFlowHandle::new(
            client,
            DeviceAuthorizationResponse {
                verification_uri: "https://op.example.com/device".to_string(),
                user_code: "AAAA-AAAA".to_string(),
                device_code: "foobar".to_string(),
                interval: Some(0.005),
                expires_in: 300,
                verification_uri_complete: None,
            },
            None,
            None,
        );

        let err = handle.grant_async().await.unwrap_err();

        assert!(err.is_rp_error());
        assert_eq!(
            "unexpected JWT alg received, expected RS256, got: none",
            err.rp_error().error.message
        );
    }

    #[tokio::test]
    async fn returns_on_other_errors_and_rejects() {
        let mock_http_server = MockServer::start();

        let _server = mock_http_server.mock(|when, then| {
            when.method(POST).path("/token");
            then.status(400).body(
                r#"{
                    "error": "server_error",
                    "error_description": "bad things are happening"
                  }"#,
            );
        });

        let (_, client) = get_client(Some(mock_http_server.port()));

        let mut handle = DeviceFlowHandle::new(
            client,
            DeviceAuthorizationResponse {
                verification_uri: "https://op.example.com/device".to_string(),
                user_code: "AAAA-AAAA".to_string(),
                device_code: "foobar".to_string(),
                interval: Some(0.005),
                expires_in: 300,
                verification_uri_complete: None,
            },
            None,
            None,
        );

        let err = handle.grant_async().await.unwrap_err();

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
        let (_, client) = get_client(None);

        let mut handle = DeviceFlowHandle::new(
            client,
            DeviceAuthorizationResponse {
                verification_uri: "https://op.example.com/device".to_string(),
                user_code: "AAAA-AAAA".to_string(),
                device_code: "foobar".to_string(),
                interval: Some(0.005),
                expires_in: 0,
                verification_uri_complete: None,
            },
            None,
            None,
        );

        let err = handle.grant_async().await.unwrap_err();

        assert!(err.is_rp_error());
        assert_eq!(
            "the device code foobar has expired and the device authorization session has concluded",
            err.rp_error().error.message
        );
    }

    #[tokio::test]
    async fn the_handle_tracks_expiration_of_the_device_code() {
        let (_, mut client) = get_client(None);

        client.now = || 1699172;

        let mut handle = DeviceFlowHandle::new(
            client,
            DeviceAuthorizationResponse {
                verification_uri: "https://op.example.com/device".to_string(),
                user_code: "AAAA-AAAA".to_string(),
                device_code: "foobar".to_string(),
                interval: Some(0.005),
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
        let mock_http_server = MockServer::start();

        let _server = mock_http_server.mock(|when, then| {
            when.method(POST).path("/token");
            then.status(400).body(
                r#"{
                    "error": "authorization_pending"
                  }"#,
            );
        });

        let (_, mut client) = get_client(Some(mock_http_server.port()));

        client.now = || 1699172;

        let mut handle = DeviceFlowHandle::new(
            client,
            DeviceAuthorizationResponse {
                verification_uri: "https://op.example.com/device".to_string(),
                user_code: "AAAA-AAAA".to_string(),
                device_code: "foobar".to_string(),
                interval: Some(5.0),
                expires_in: 300,
                verification_uri_complete: None,
            },
            None,
            None,
        );

        handle.now = || 1699172;

        let _ = handle.grant_async().await.unwrap();

        handle.now = || 1699174;

        let res = handle.grant_async().await.unwrap();

        if let DeviceFlowGrantResponse::Debounced = res {
            return;
        }

        assert!(false);
    }
}
