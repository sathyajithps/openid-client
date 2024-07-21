use crate::issuer::Issuer;
use crate::types::HttpMethod;

use crate::tests::test_http_client::{TestHttpClient, TestHttpReqRes};

#[tokio::test]
async fn can_discover_using_the_email_syntax() {
    let http_client = TestHttpClient::new().add(
        TestHttpReqRes::new("https://openmail.example.com/.well-known/webfinger?resource=acct%3Ajoe%40openmail.example.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer")
            .assert_request_method(HttpMethod::GET)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .set_response_body(r#"{"subject":"https://openmail.example.com/joe","links":[{"rel":"http://openid.net/specs/connect/1.0/issuer","href":"https://openmail.example.com"}]}"#)
            .set_response_content_type_header("application/json"),
    ).add(
        TestHttpReqRes::new("https://openmail.example.com/.well-known/openid-configuration")
        .assert_request_method(HttpMethod::GET)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .set_response_body(r#"{"authorization_endpoint":"https://openmail.example.com/o/oauth2/v2/auth","issuer":"https://openmail.example.com","jwks_uri":"https://openmail.example.com/oauth2/v3/certs","token_endpoint":"https://openmail.example.com/oauth2/v4/token","userinfo_endpoint":"https://openmail.example.com/oauth2/v3/userinfo"}"#)
        .set_response_content_type_header("application/json"),
    );

    let _ = Issuer::webfinger_async(&http_client, "joe@openmail.example.com").await;

    http_client.assert();
}

#[tokio::test]
async fn verifies_the_webfinger_responds_with_an_issuer() {
    let http_client = TestHttpReqRes::new(
        "https://openmail.example.com/.well-known/webfinger?resource=acct%3Ajoe%40openmail.example.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer",
    )
    .assert_request_method(HttpMethod::GET)
    .assert_request_header("accept", vec!["application/json".to_string()])
    .set_response_body(r#"{"subject":"https://openmail.example.com/joe","links":[]}"#)
    .set_response_content_type_header("application/json")
    .build();

    let error = Issuer::webfinger_async(&http_client, "joe@openmail.example.com")
        .await
        .unwrap_err();

    assert_eq!(
        "no issuer found in webfinger response",
        error.rp_error().error.message,
    );
}

#[tokio::test]
async fn verifies_the_webfinger_responds_with_an_issuer_which_is_a_valid_issuer_value_1_of_2() {
    let http_client = TestHttpClient::new().add(
        TestHttpReqRes::new(
            "https://openmail.example.com/.well-known/webfinger?resource=acct%3Ajoe%40openmail.example.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer")
        .assert_request_method(HttpMethod::GET)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .set_response_body(r#"{"subject":"https://openmail.example.com/joe","links":[{"rel":"http://openid.net/specs/connect/1.0/issuer","href":"https://openmail.example.com"}]}"#)
        .set_response_content_type_header("application/json")
    ).add(
        TestHttpReqRes::new("https://openmail.example.com/.well-known/openid-configuration")
        .assert_request_method(HttpMethod::GET)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .set_response_status_code(404)
    );

    let error = Issuer::webfinger_async(&http_client, "joe@openmail.example.com")
        .await
        .unwrap_err();

    assert_eq!(
        Some("invalid issuer location https://openmail.example.com".to_string()),
        error.op_error().error.error_description,
    );
}

#[tokio::test]
async fn verifies_the_webfinger_responds_with_an_issuer_which_is_a_valid_issuer_value_2_of_2() {
    let http_client =
        TestHttpReqRes::new(
            "https://openmail.example.com/.well-known/webfinger?resource=acct%3Ajoe%40openmail.example.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer")
        .assert_request_method(HttpMethod::GET)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .set_response_body(r#"{"subject":"https://openmail.example.com/joe","links":[{"rel":"http://openid.net/specs/connect/1.0/issuer","href":"1"}]}"#)
        .set_response_content_type_header("application/json").build();

    let error = Issuer::webfinger_async(&http_client, "joe@openmail.example.com")
        .await
        .unwrap_err();

    assert_eq!(
        Some("invalid issuer location 1".to_string()),
        error.op_error().error.error_description
    );
}

#[tokio::test]
async fn validates_the_discovered_issuer_is_the_same_as_from_webfinger() {
    let http_client = TestHttpClient::new().add(
        TestHttpReqRes::new(
            "https://openmail.example.com/.well-known/webfinger?resource=acct%3Ajoe%40openmail.example.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer")
        .assert_request_method(HttpMethod::GET)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .set_response_body(r#"{"subject":"https://openmail.example.com/joe","links":[{"rel":"http://openid.net/specs/connect/1.0/issuer","href":"https://openmail.example.com"}]}"#)
        .set_response_content_type_header("application/json")
    ).add(
        TestHttpReqRes::new("https://openmail.example.com/.well-known/openid-configuration")
        .assert_request_method(HttpMethod::GET)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .set_response_body(r#"{"authorization_endpoint":"https://openmail.example.com/o/oauth2/v2/auth","issuer":"https://another.issuer.com","jwks_uri":"https://openmail.example.com/oauth2/v3/certs","token_endpoint":"https://openmail.example.com/oauth2/v4/token","userinfo_endpoint":"https://openmail.example.com/oauth2/v3/userinfo"}"#)
        .set_response_content_type_header("application/json")
    );

    let error = Issuer::webfinger_async(&http_client, "joe@openmail.example.com")
        .await
        .unwrap_err();
    assert_eq!(
            Some(
                "discovered issuer mismatch, expected https://openmail.example.com, got: https://another.issuer.com".to_string(),
            ),
            error.op_error().error.error_description,
        );

    http_client.assert();
}

#[tokio::test]
async fn can_discover_using_the_url_syntax() {
    let http_client = TestHttpClient::new().add(
        TestHttpReqRes::new("https://opurl.example.com/.well-known/webfinger?resource=https%3A%2F%2Fopurl.example.com%2Fjoe&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer")
        .assert_request_method(HttpMethod::GET)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .set_response_body(r#"{"subject":"https://opurl.example.com/joe","links":[{"rel":"http://openid.net/specs/connect/1.0/issuer","href":"https://opurl.example.com"}]}"#)
        .set_response_content_type_header("application/json")
    ).add(
        TestHttpReqRes::new("https://opurl.example.com/.well-known/openid-configuration")
        .assert_request_method(HttpMethod::GET)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .set_response_body(r#"{"authorization_endpoint":"https://opurl.example.com/o/oauth2/v2/auth","issuer":"https://opurl.example.com","jwks_uri":"https://opurl.example.com/oauth2/v3/certs","token_endpoint":"https://opurl.example.com/oauth2/v4/token","userinfo_endpoint":"https://opurl.example.com/oauth2/v3/userinfo"}"#)
        .set_response_content_type_header("application/json")
    );

    let issuer_result =
        Issuer::webfinger_async(&http_client, "https://opurl.example.com/joe").await;

    assert!(issuer_result.is_ok());

    http_client.assert();
}

#[tokio::test]
async fn can_discover_using_the_hostname_and_port_syntax() {
    let http_client = TestHttpClient::new().add(
        TestHttpReqRes::new("https://ophp.example.com:8080/.well-known/webfinger?resource=https%3A%2F%2Fophp.example.com%3A8080&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer")
        .assert_request_method(HttpMethod::GET)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .set_response_body(r#"{"subject":"https://ophp.example.com:8080","links":[{"rel":"http://openid.net/specs/connect/1.0/issuer","href":"https://ophp.example.com"}]}"#)
        .set_response_content_type_header("application/json")
    ).add(
        TestHttpReqRes::new("https://ophp.example.com/.well-known/openid-configuration")
        .assert_request_method(HttpMethod::GET)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .set_response_body(r#"{"authorization_endpoint":"https://ophp.example.com/o/oauth2/v2/auth","issuer":"https://ophp.example.com","jwks_uri":"https://ophp.example.com/oauth2/v3/certs","token_endpoint":"https://ophp.example.com/oauth2/v4/token","userinfo_endpoint":"https://ophp.example.com/oauth2/v3/userinfo"}"#)
        .set_response_content_type_header("application/json")
    );

    let issuer_result = Issuer::webfinger_async(&http_client, "ophp.example.com:8080").await;

    assert!(issuer_result.is_ok());

    http_client.assert();
}

#[tokio::test]
async fn can_discover_using_the_acct_syntax() {
    let http_client = TestHttpClient::new().add(
        TestHttpReqRes::new("https://opacct.example.com/.well-known/webfinger?resource=acct%3Ajuliet%40capulet.example%40opacct.example.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer")
        .assert_request_method(HttpMethod::GET)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .set_response_body(r#"{"subject":"acct:juliet@capulet.example@opacct.example.com","links":[{"rel":"http://openid.net/specs/connect/1.0/issuer","href":"https://opacct.example.com"}]}"#)
        .set_response_content_type_header("application/json")
    ).add(
        TestHttpReqRes::new("https://opacct.example.com/.well-known/openid-configuration")
        .assert_request_method(HttpMethod::GET)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .set_response_body(r#"{"authorization_endpoint":"https://opacct.example.com/o/oauth2/v2/auth","issuer":"https://opacct.example.com","jwks_uri":"https://opacct.example.com/oauth2/v3/certs","token_endpoint":"https://opacct.example.com/oauth2/v4/token","userinfo_endpoint":"https://opacct.example.com/oauth2/v3/userinfo"}"#)
        .set_response_content_type_header("application/json")
    );

    let issuer_result = Issuer::webfinger_async(
        &http_client,
        "acct:juliet@capulet.example@opacct.example.com",
    )
    .await;

    assert!(issuer_result.is_ok());

    http_client.assert();
}
