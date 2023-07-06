use httpmock::Method::GET;
use httpmock::MockServer;

use crate::issuer::Issuer;
use crate::tests::test_interceptors::get_default_test_interceptor;
use crate::types::OidcClientError;

pub fn get_async_webfinger_discovery(input: &str, port: u16) -> Result<Issuer, OidcClientError> {
    let async_runtime = tokio::runtime::Runtime::new().unwrap();

    let result: Result<Issuer, OidcClientError> = async_runtime.block_on(async {
        let iss = Issuer::webfinger_async(input, get_default_test_interceptor(port)).await;
        return iss;
    });
    result
}

#[test]
fn can_discover_using_the_email_syntax() {
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

    let _ = Issuer::webfinger(
        &resource,
        get_default_test_interceptor(mock_http_server.port()),
    );

    let _ = get_async_webfinger_discovery(&resource, mock_http_server.port());

    webfinger_mock_server.assert_hits(2);
    issuer_discovery_mock_server.assert_hits(2);
}

#[test]
fn verifies_the_webfinger_responds_with_an_issuer() {
    let mock_http_server = MockServer::start();
    let webfinger_response_body = "{\"subject\":\"https://opemail.example.com/joe\",\"links\":[]}";

    let _webfinger_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET)
            .path("/.well-known/webfinger")
            .header("Accept", "application/json");
        then.status(200).body(webfinger_response_body);
    });

    let resource = "joe@opemail.example.com";

    let error = Issuer::webfinger(
        &resource,
        get_default_test_interceptor(mock_http_server.port()),
    )
    .unwrap_err();
    let error_async =
        get_async_webfinger_discovery(&resource, mock_http_server.port()).unwrap_err();

    assert_eq!(
        "no issuer found in webfinger response",
        error.rp_error().error.message,
    );
    assert_eq!(
        "no issuer found in webfinger response",
        error_async.rp_error().error.message,
    );
}

#[test]
fn verifies_the_webfinger_responds_with_an_issuer_which_is_a_valid_issuer_value_1_of_2() {
    let mock_http_server = MockServer::start();

    let webfinger_response_body = "{\"subject\":\"https://opemail.example.com/joe\",\"links\":[{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://opemail.example.com\"}]}";

    let _webfinger_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET).path("/.well-known/webfinger");
        then.status(200).body(webfinger_response_body);
    });

    let resource = "joe@opemail.example.com";

    let error = Issuer::webfinger(
        &resource,
        get_default_test_interceptor(mock_http_server.port()),
    )
    .unwrap_err();
    let error_async =
        get_async_webfinger_discovery(&resource, mock_http_server.port()).unwrap_err();

    assert_eq!(
        Some("invalid issuer location https://opemail.example.com".to_string()),
        error.op_error().error.error_description,
    );

    assert_eq!(
        Some("invalid issuer location https://opemail.example.com".to_string()),
        error_async.op_error().error.error_description,
    );
}

#[test]
fn verifies_the_webfinger_responds_with_an_issuer_which_is_a_valid_issuer_value_2_of_2() {
    let mock_http_server = MockServer::start();

    let webfinger_response_body = "{\"subject\":\"https://opemail.example.com/joe\",\"links\":[{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"1\"}]}";

    let _webfinger = mock_http_server.mock(|when, then| {
        when.method(GET).path("/.well-known/webfinger");
        then.status(200).body(webfinger_response_body);
    });

    let resource = "joe@opemail.example.com";

    let error = Issuer::webfinger(
        &resource,
        get_default_test_interceptor(mock_http_server.port()),
    )
    .unwrap_err();
    let error_async =
        get_async_webfinger_discovery(&resource, mock_http_server.port()).unwrap_err();

    assert_eq!(
        Some("invalid issuer location 1".to_string()),
        error.op_error().error.error_description
    );

    assert_eq!(
        Some("invalid issuer location 1".to_string()),
        error_async.op_error().error.error_description,
    );
}

// Todo: not implementing cache right now
// #[test]
// fn uses_cached_issuer_if_it_has_one() {
//  mock_http_server server = MockServer::start();

//     let auth_server_domain = get_url_with_count("opemail.example<>.com");

//     let webfinger_response_body = format!("{{\"subject\":\"https://{0}/joe\",\"links\":[{{\"rel\":\"http://openid.net/specs/connect/1.0/issuer\",\"href\":\"https://{0}\"}}]}}", auth_server_domain);
//     let discovery_document_response_body = format!("{{\"authorization_endpoint\":\"https://{0}/o/oauth2/v2/auth\",\"issuer\":\"https://{0}\",\"jwks_uri\":\"https://{0}/oauth2/v3/certs\",\"token_endpoint\":\"https://{0}/oauth2/v4/token\",\"userinfo_endpoint\":\"https://{0}/oauth2/v3/userinfo\"}}", auth_server_domain);

//     let resource = format!("joe@{}", auth_server_domain);

//

//     let webfinger_mock_server = mock_http_server.mock(|when, then| {
//         when.method(GET).path("/.well-known/webfinger");
//         then.status(200).body(webfinger_response_body);
//     });

//     let issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
//         when.method(GET).path("/.well-known/openid-configuration");
//         then.status(200).body(discovery_document_response_body);
//     });

//     let _ = Issuer::webfinger(&resource, None);
//     let __ = Issuer::webfinger(&resource, None);

//     webfinger_mock_server.assert_hits(2);
//     issuer_discovery_mock_server.assert_hits(1);
// }

#[test]
fn validates_the_discovered_issuer_is_the_same_as_from_webfinger() {
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

    let error = Issuer::webfinger(
        &resource,
        get_default_test_interceptor(mock_http_server.port()),
    )
    .unwrap_err();
    let error_async =
        get_async_webfinger_discovery(&resource, mock_http_server.port()).unwrap_err();

    assert_eq!(
            Some(
                "discovered issuer mismatch, expected https://opemail.example.com, got: https://another.issuer.com".to_string(),
            ),
            error.op_error().error.error_description,
        );
    assert_eq!(
            Some(
                "discovered issuer mismatch, expected https://opemail.example.com, got: https://another.issuer.com".to_string(),
            ),
            error_async.op_error().error.error_description,
        );

    webfinger_mock_server.assert_hits(2);
    issuer_discovery_mock_server.assert_hits(2);
}

#[test]
fn can_discover_using_the_url_syntax() {
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

    let issuer_result = Issuer::webfinger(
        &webfinger_url,
        get_default_test_interceptor(mock_http_server.port()),
    );
    let async_issuer_result =
        get_async_webfinger_discovery(&webfinger_url, mock_http_server.port());

    assert!(issuer_result.is_ok());
    assert!(async_issuer_result.is_ok());

    webfinger_mock_server.assert_hits(2);
    issuer_discovery_mock_server.assert_hits(2);
}

#[test]
fn can_discover_using_the_hostname_and_port_syntax() {
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

    let issuer_result = Issuer::webfinger(
        &auth_server_domain_with_port,
        get_default_test_interceptor(mock_http_server.port()),
    );
    let async_issuer_result =
        get_async_webfinger_discovery(&auth_server_domain_with_port, mock_http_server.port());

    assert!(issuer_result.is_ok());
    assert!(async_issuer_result.is_ok());

    webfinger_mock_server.assert_hits(2);
    issuer_discovery_mock_server.assert_hits(2);
}

#[test]
fn can_discover_using_the_acct_syntax() {
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

    let issuer_result = Issuer::webfinger(
        &resource,
        get_default_test_interceptor(mock_http_server.port()),
    );
    let async_issuer_result = get_async_webfinger_discovery(&resource, mock_http_server.port());

    assert!(issuer_result.is_ok());
    assert!(async_issuer_result.is_ok());

    webfinger_mock_server.assert_hits(2);
    issuer_discovery_mock_server.assert_hits(2);
}

#[cfg(test)]
mod http_options {

    use httpmock::{Method::GET, MockServer};

    use crate::{
        issuer::Issuer, tests::test_interceptors::TestInterceptor, types::OidcClientError,
    };

    #[test]
    fn allows_for_http_options_to_be_defined_for_issuer_webfinger_calls() {
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

        let issuer_result = Issuer::webfinger(
            &resource,
            Some(Box::new(TestInterceptor {
                test_header: Some("custom".to_string()),
                test_header_value: Some("foo".to_string()),
                test_server_port: Some(mock_http_server.port()),
            })),
        );

        webfinger_mock_server.assert();
        issuer_discovery_mock_server.assert();
        assert!(issuer_result.is_ok());
    }

    #[test]
    fn allows_for_http_options_to_be_defined_for_issuer_webfinger_calls_async() {
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

        let async_runtime = tokio::runtime::Runtime::new().unwrap();

        let issuer_result: Result<Issuer, OidcClientError> = async_runtime.block_on(async {
            Issuer::webfinger_async(
                &resource,
                Some(Box::new(TestInterceptor {
                    test_header: Some("custom".to_string()),
                    test_header_value: Some("foo".to_string()),
                    test_server_port: Some(mock_http_server.port()),
                })),
            )
            .await
        });

        webfinger_mock_server.assert();
        issuer_discovery_mock_server.assert();
        assert!(issuer_result.is_ok());
    }
}
