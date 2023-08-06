use httpmock::Method::GET;
use httpmock::MockServer;

use crate::issuer::Issuer;
use crate::tests::test_interceptors::get_default_test_interceptor;

#[tokio::test]
async fn can_discover_using_the_email_syntax() {
    let mock_http_server = MockServer::start();

    let webfinger_response_body = "{\"subject\":\"https://opemail.example.com/joe\",\"links\":[{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://opemail.example.com\"}]}";
    let discovery_document_response_body = "{\"authorization_endpoint\":\"https://opemail.example.com/o/oauth2/v2/auth\",\"issuer\":\"https://opemail.example.com\",\"jwks_uri\":\"https://opemail.example.com/oauth2/v3/certs\",\"token_endpoint\":\"https://opemail.example.com/oauth2/v4/token\",\"userinfo_endpoint\":\"https://opemail.example.com/oauth2/v3/userinfo\"}";

    let resource = "joe@opemail.example.com";

    let webfinger_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET)
            .path("/.well-known/webfinger")
            .query_param("resource", format!("acct:{}", &resource));
        then.status(200).body(webfinger_response_body);
    });

    let issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET).path("/.well-known/openid-configuration");
        then.status(200).body(discovery_document_response_body);
    });

    let _ = Issuer::webfinger_async(
        &resource,
        get_default_test_interceptor(mock_http_server.port()),
    )
    .await;

    webfinger_mock_server.assert_hits(1);
    issuer_discovery_mock_server.assert_hits(1);
}

#[tokio::test]
async fn verifies_the_webfinger_responds_with_an_issuer() {
    let mock_http_server = MockServer::start();
    let webfinger_response_body = "{\"subject\":\"https://opemail.example.com/joe\",\"links\":[]}";

    let _webfinger_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET)
            .path("/.well-known/webfinger")
            .header("Accept", "application/json");
        then.status(200).body(webfinger_response_body);
    });

    let resource = "joe@opemail.example.com";

    let error = Issuer::webfinger_async(
        &resource,
        get_default_test_interceptor(mock_http_server.port()),
    )
    .await
    .unwrap_err();

    assert_eq!(
        "no issuer found in webfinger response",
        error.rp_error().error.message,
    );
}

#[tokio::test]
async fn verifies_the_webfinger_responds_with_an_issuer_which_is_a_valid_issuer_value_1_of_2() {
    let mock_http_server = MockServer::start();

    let webfinger_response_body = "{\"subject\":\"https://opemail.example.com/joe\",\"links\":[{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://opemail.example.com\"}]}";

    let _webfinger_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET).path("/.well-known/webfinger");
        then.status(200).body(webfinger_response_body);
    });

    let resource = "joe@opemail.example.com";

    let error = Issuer::webfinger_async(
        &resource,
        get_default_test_interceptor(mock_http_server.port()),
    )
    .await
    .unwrap_err();

    assert_eq!(
        Some("invalid issuer location https://opemail.example.com".to_string()),
        error.op_error().error.error_description,
    );
}

#[tokio::test]
async fn verifies_the_webfinger_responds_with_an_issuer_which_is_a_valid_issuer_value_2_of_2() {
    let mock_http_server = MockServer::start();

    let webfinger_response_body = "{\"subject\":\"https://opemail.example.com/joe\",\"links\":[{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"1\"}]}";

    let _webfinger = mock_http_server.mock(|when, then| {
        when.method(GET).path("/.well-known/webfinger");
        then.status(200).body(webfinger_response_body);
    });

    let resource = "joe@opemail.example.com";

    let error = Issuer::webfinger_async(
        &resource,
        get_default_test_interceptor(mock_http_server.port()),
    )
    .await
    .unwrap_err();

    assert_eq!(
        Some("invalid issuer location 1".to_string()),
        error.op_error().error.error_description
    );
}

#[tokio::test]
async fn validates_the_discovered_issuer_is_the_same_as_from_webfinger() {
    let mock_http_server = MockServer::start();

    let webfinger_response_body ="{\"subject\":\"https://opemail.example.com/joe\",\"links\":[{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://opemail.example.com\"}]}";
    let discovery_document_response_body = "{\"authorization_endpoint\":\"https://opemail.example.com/o/oauth2/v2/auth\",\"issuer\":\"https://another.issuer.com\",\"jwks_uri\":\"https://opemail.example.com/oauth2/v3/certs\",\"token_endpoint\":\"https://opemail.example.com/oauth2/v4/token\",\"userinfo_endpoint\":\"https://opemail.example.com/oauth2/v3/userinfo\"}";

    let webfinger_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET).path("/.well-known/webfinger");
        then.status(200).body(webfinger_response_body);
    });

    let issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET).path("/.well-known/openid-configuration");
        then.status(200).body(discovery_document_response_body);
    });

    let resource = "joe@opemail.example.com";

    let error = Issuer::webfinger_async(
        &resource,
        get_default_test_interceptor(mock_http_server.port()),
    )
    .await
    .unwrap_err();
    assert_eq!(
            Some(
                "discovered issuer mismatch, expected https://opemail.example.com, got: https://another.issuer.com".to_string(),
            ),
            error.op_error().error.error_description,
        );

    webfinger_mock_server.assert_hits(1);
    issuer_discovery_mock_server.assert_hits(1);
}

#[tokio::test]
async fn can_discover_using_the_url_syntax() {
    let mock_http_server = MockServer::start();

    let webfinger_response_body = "{\"subject\":\"https://opurl.example.com/joe\",\"links\":[{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://opurl.example.com\"}]}";
    let discovery_document_response_body = "{\"authorization_endpoint\":\"https://opurl.example.com/o/oauth2/v2/auth\",\"issuer\":\"https://opurl.example.com\",\"jwks_uri\":\"https://opurl.example.com/oauth2/v3/certs\",\"token_endpoint\":\"https://opurl.example.com/oauth2/v4/token\",\"userinfo_endpoint\":\"https://opurl.example.com/oauth2/v3/userinfo\"}";

    let webfinger_url = "https://opurl.example.com/joe";

    let webfinger_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET)
            .path("/.well-known/webfinger")
            .query_param("resource", webfinger_url);
        then.status(200).body(webfinger_response_body);
    });

    let issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET).path("/.well-known/openid-configuration");
        then.status(200).body(discovery_document_response_body);
    });

    let issuer_result = Issuer::webfinger_async(
        &webfinger_url,
        get_default_test_interceptor(mock_http_server.port()),
    )
    .await;

    assert!(issuer_result.is_ok());

    webfinger_mock_server.assert_hits(1);
    issuer_discovery_mock_server.assert_hits(1);
}

#[tokio::test]
async fn can_discover_using_the_hostname_and_port_syntax() {
    let mock_http_server = MockServer::start();

    let auth_server_domain_with_port = "ophp.example.com:8080";

    let webfinger_response_body = "{\"subject\":\"https://ophp.example.com:8080\",\"links\":[{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://ophp.example.com\"}]}";
    let discovery_document_response_body = "{\"authorization_endpoint\":\"https://ophp.example.com/o/oauth2/v2/auth\",\"issuer\":\"https://ophp.example.com\",\"jwks_uri\":\"https://ophp.example.com/oauth2/v3/certs\",\"token_endpoint\":\"https://ophp.example.com/oauth2/v4/token\",\"userinfo_endpoint\":\"https://ophp.example.com/oauth2/v3/userinfo\"}";

    let webfinger_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET).path("/.well-known/webfinger").query_param(
            "resource",
            format!("https://{}", auth_server_domain_with_port),
        );
        then.status(200).body(webfinger_response_body);
    });

    let issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET).path("/.well-known/openid-configuration");
        then.status(200).body(discovery_document_response_body);
    });

    let issuer_result = Issuer::webfinger_async(
        &auth_server_domain_with_port,
        get_default_test_interceptor(mock_http_server.port()),
    )
    .await;

    assert!(issuer_result.is_ok());

    webfinger_mock_server.assert_hits(1);
    issuer_discovery_mock_server.assert_hits(1);
}

#[tokio::test]
async fn can_discover_using_the_acct_syntax() {
    let mock_http_server = MockServer::start();

    let resource = "acct:juliet%40capulet.example@opacct.example.com";

    let webfinger_response_body = "{\"subject\":\"acct:juliet%40capulet.example@opacct.example.com\",\"links\":[{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://opacct.example.com\"}]}";
    let discovery_document_response_body = "{\"authorization_endpoint\":\"https://opacct.example.com/o/oauth2/v2/auth\",\"issuer\":\"https://opacct.example.com\",\"jwks_uri\":\"https://opacct.example.com/oauth2/v3/certs\",\"token_endpoint\":\"https://opacct.example.com/oauth2/v4/token\",\"userinfo_endpoint\":\"https://opacct.example.com/oauth2/v3/userinfo\"}";

    let webfinger_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET)
            .path("/.well-known/webfinger")
            .query_param("resource", resource);
        then.status(200).body(webfinger_response_body);
    });

    let issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET).path("/.well-known/openid-configuration");
        then.status(200).body(discovery_document_response_body);
    });

    let issuer_result = Issuer::webfinger_async(
        &resource,
        get_default_test_interceptor(mock_http_server.port()),
    )
    .await;

    assert!(issuer_result.is_ok());

    webfinger_mock_server.assert_hits(1);
    issuer_discovery_mock_server.assert_hits(1);
}

#[cfg(test)]
mod http_options {

    use httpmock::{Method::GET, MockServer};

    use crate::{issuer::Issuer, tests::test_interceptors::TestInterceptor};

    #[tokio::test]
    async fn allows_for_http_options_to_be_defined_for_issuer_webfinger_calls() {
        let mock_http_server = MockServer::start();

        let resource = "acct:juliet@op.example.com";

        let webfinger_response_body = "{\"subject\":\"acct:juliet@op.example.com\",\"links\":[{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://op.example.com\"}]}";
        let discovery_document_response_body = "{\"authorization_endpoint\":\"https://op.example.com/o/oauth2/v2/auth\",\"issuer\":\"https://op.example.com\",\"jwks_uri\":\"https://op.example.com/oauth2/v3/certs\",\"token_endpoint\":\"https://op.example.com/oauth2/v4/token\",\"userinfo_endpoint\":\"https://op.example.com/oauth2/v3/userinfo\"}";

        let webfinger_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .path("/.well-known/webfinger")
                .header("custom", "foo")
                .query_param("resource", resource);
            then.status(200).body(webfinger_response_body);
        });

        let issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .path("/.well-known/openid-configuration")
                .header("custom", "foo");
            then.status(200).body(discovery_document_response_body);
        });

        let issuer_result = Issuer::webfinger_async(
            &resource,
            Some(Box::new(TestInterceptor {
                test_header: Some("custom".to_string()),
                test_header_value: Some("foo".to_string()),
                test_server_port: Some(mock_http_server.port()),
            })),
        )
        .await;

        webfinger_mock_server.assert();
        issuer_discovery_mock_server.assert();
        assert!(issuer_result.is_ok());
    }
}
