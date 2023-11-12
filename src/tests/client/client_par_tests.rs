use assert_json_diff::assert_json_include;
use httpmock::{Method, MockServer};
use serde_json::json;

use crate::{
    client::Client,
    issuer::Issuer,
    tests::test_interceptors::get_default_test_interceptor,
    types::{AuthorizationParameters, ClientMetadata, IssuerMetadata},
};

fn get_test_data(port: Option<u16>) -> (Issuer, Client) {
    let issuer_metadata = IssuerMetadata {
        issuer: "https://op.example.com".to_string(),
        pushed_authorization_request_endpoint: Some("https://op.example.com/par".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata, get_default_test_interceptor(port));

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        client_secret: Some("secure".to_string()),
        response_type: Some("code".to_string()),
        grant_types: Some(vec!["authrorization_code".to_string()]),
        redirect_uri: Some("https://rp.example.com/cb".to_string()),
        ..Default::default()
    };

    let client = issuer
        .client(client_metadata, None, None, None, None)
        .unwrap();

    (issuer, client)
}

#[tokio::test]
async fn requires_the_issuer_to_have_pushed_authorization_request_endpoint_declared() {
    let issuer_metadata = IssuerMetadata {
        issuer: "https://op.example.com".to_string(),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata, None);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, None, None, None, None)
        .unwrap();

    let err = client
        .pushed_authorization_request_async(None, None)
        .await
        .unwrap_err();

    assert!(err.is_type_error());

    assert_eq!(
        "pushed_authorization_request_endpoint must be configured on the issuer",
        err.type_error().error.message
    );
}

#[tokio::test]
async fn performs_an_authenticated_post_and_returns_the_response() {
    let mock_http_server = MockServer::start();

    let _par = mock_http_server.mock(|when, then| {
        when.method(Method::POST)
            .header("Accept", "application/json")
            .matches(|req| {
                let decoded =
                    urlencoding::decode(std::str::from_utf8(&req.body.as_ref().unwrap()).unwrap())
                        .unwrap();

                let kvp = querystring::querify(&decoded);

                let client_id = kvp
                    .iter()
                    .find(|(k, v)| k == &"client_id" && v == &"identifier");
                let redirect_uri = kvp
                    .iter()
                    .find(|(k, v)| k == &"redirect_uri" && v == &"https://rp.example.com/cb");
                let response_type = kvp
                    .iter()
                    .find(|(k, v)| k == &"response_type" && v == &"code");
                let scope = kvp.iter().find(|(k, v)| k == &"scope" && v == &"openid");

                client_id.is_some()
                    && redirect_uri.is_some()
                    && response_type.is_some()
                    && scope.is_some()
            })
            .path("/par");

        then.status(201)
            .body(r#"{"expires_in":60,"request_uri":"urn:ietf:params:oauth:request_uri:random"}"#);
    });

    let (_, mut client) = get_test_data(Some(mock_http_server.port()));

    let res = client
        .pushed_authorization_request_async(None, None)
        .await
        .unwrap();

    assert_json_include!(
        expected: json!({
            "expires_in": 60,
            "request_uri": "urn:ietf:params:oauth:request_uri:random"
        }),
        actual: res
    );
}

#[tokio::test]
async fn handles_incorrect_status_code() {
    let mock_http_server = MockServer::start();

    let _par = mock_http_server.mock(|when, then| {
        when.method(Method::POST)
            .header("Accept", "application/json")
            .path("/par");

        then.status(200)
            .body(r#"{"expires_in":60,"request_uri":"urn:ietf:params:oauth:request_uri:random"}"#);
    });

    let (_, mut client) = get_test_data(Some(mock_http_server.port()));

    let err = client
        .pushed_authorization_request_async(None, None)
        .await
        .unwrap_err();

    assert!(err.is_op_error());
    assert_eq!(
        "expected 201 Created, got: 200 OK",
        err.op_error().error.error_description.unwrap()
    )
}

#[tokio::test]
async fn handles_request_being_part_of_the_params() {
    let mock_http_server = MockServer::start();

    let _par = mock_http_server.mock(|when, then| {
        when.method(Method::POST)
            .header("Accept", "application/json")
            .matches(|req| {
                let decoded =
                    urlencoding::decode(std::str::from_utf8(&req.body.as_ref().unwrap()).unwrap())
                        .unwrap();

                let kvp = querystring::querify(&decoded);

                let client_id = kvp
                    .iter()
                    .find(|(k, v)| k == &"client_id" && v == &"identifier");
                let request = kvp.iter().find(|(k, v)| k == &"request" && v == &"jwt");

                client_id.is_some() && request.is_some()
            })
            .path("/par");

        then.status(201)
            .body(r#"{"expires_in":60,"request_uri":"urn:ietf:params:oauth:request_uri:random"}"#);
    });

    let (_, mut client) = get_test_data(Some(mock_http_server.port()));

    let mut params = AuthorizationParameters::default();

    params.request = Some("jwt".to_string());

    let res = client
        .pushed_authorization_request_async(Some(params), None)
        .await
        .unwrap();

    assert_json_include!(
        expected: json!({
            "expires_in": 60,
            "request_uri": "urn:ietf:params:oauth:request_uri:random"
        }),
        actual: res
    );
}

#[tokio::test]
async fn rejects_with_op_error_when_part_of_the_response() {
    let mock_http_server = MockServer::start();

    let _par = mock_http_server.mock(|when, then| {
        when.method(Method::POST)
            .header("Accept", "application/json")
            .path("/par");

        then.status(400)
            .body(r#"{"error":"invalid_request","error_description":"description"}"#);
    });

    let (_, mut client) = get_test_data(Some(mock_http_server.port()));

    let err = client
        .pushed_authorization_request_async(None, None)
        .await
        .unwrap_err();

    assert!(err.is_op_error());

    let op_error = err.op_error();

    assert_eq!("invalid_request", op_error.error.error);
    assert_eq!("description", op_error.error.error_description.unwrap());
}

#[tokio::test]
async fn rejects_with_rp_error_when_request_uri_is_missing_from_the_response() {
    let mock_http_server = MockServer::start();

    let _par = mock_http_server.mock(|when, then| {
        when.method(Method::POST)
            .header("Accept", "application/json")
            .path("/par");

        then.status(201).body(r#"{"expires_in":60}"#);
    });

    let (_, mut client) = get_test_data(Some(mock_http_server.port()));

    let err = client
        .pushed_authorization_request_async(None, None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());

    let rp_error = err.rp_error();

    assert!(rp_error.response.is_some());
    assert_eq!(
        "expected request_uri in Pushed Authorization Successful Response",
        rp_error.error.message
    );
}

#[tokio::test]
async fn rejects_with_rp_error_when_request_uri_is_not_a_string() {
    let mock_http_server = MockServer::start();

    let _par = mock_http_server.mock(|when, then| {
        when.method(Method::POST)
            .header("Accept", "application/json")
            .path("/par");

        then.status(201)
            .body(r#"{"expires_in":60,"request_uri":null}"#);
    });

    let (_, mut client) = get_test_data(Some(mock_http_server.port()));

    let err = client
        .pushed_authorization_request_async(None, None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());

    let rp_error = err.rp_error();

    assert!(rp_error.response.is_some());
    assert_eq!(
        "invalid request_uri value in Pushed Authorization Successful Response",
        rp_error.error.message
    );
}

#[tokio::test]
async fn rejects_with_rp_error_when_expires_in_is_missing_from_the_response() {
    let mock_http_server = MockServer::start();

    let _par = mock_http_server.mock(|when, then| {
        when.method(Method::POST)
            .header("Accept", "application/json")
            .path("/par");

        then.status(201)
            .body(r#"{"request_uri":"urn:ietf:params:oauth:request_uri:random"}"#);
    });

    let (_, mut client) = get_test_data(Some(mock_http_server.port()));

    let err = client
        .pushed_authorization_request_async(None, None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());

    let rp_error = err.rp_error();

    assert!(rp_error.response.is_some());
    assert_eq!(
        "expected expires_in in Pushed Authorization Successful Response",
        rp_error.error.message
    );
}

#[tokio::test]
async fn rejects_with_rp_error_when_expires_in_is_not_a_string() {
    let mock_http_server = MockServer::start();

    let _par = mock_http_server.mock(|when, then| {
        when.method(Method::POST)
            .header("Accept", "application/json")
            .path("/par");

        then.status(201).body(
            r#"{"request_uri":"urn:ietf:params:oauth:request_uri:random","expires_in":null}"#,
        );
    });

    let (_, mut client) = get_test_data(Some(mock_http_server.port()));

    let err = client
        .pushed_authorization_request_async(None, None)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());

    let rp_error = err.rp_error();

    assert!(rp_error.response.is_some());
    assert_eq!(
        "invalid expires_in value in Pushed Authorization Successful Response",
        rp_error.error.message
    );
}
