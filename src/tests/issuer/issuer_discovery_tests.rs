use crate::issuer::Issuer;
use crate::tests::test_interceptors::get_default_test_interceptor;
pub use httpmock::Method::GET;
pub use httpmock::MockServer;

pub fn get_default_expected_discovery_document() -> String {
    "{\"authorization_endpoint\":\"https://op.example.com/o/oauth2/v2/auth\",\"issuer\":\"https://op.example.com\",\"jwks_uri\":\"https://op.example.com/oauth2/v3/certs\",\"token_endpoint\":\"https://op.example.com/oauth2/v4/token\",\"userinfo_endpoint\":\"https://op.example.com/oauth2/v3/userinfo\"}".to_string()
}

#[cfg(test)]
mod custom_well_known {

    use super::*;

    #[tokio::test]
    async fn accepts_and_assigns_the_discovered_metadata() {
        let mock_http_server = MockServer::start();

        let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/custom-configuration");
            then.status(200)
                .header("content-type", "application/json")
                .body(get_default_expected_discovery_document());
        });

        let issuer_discovery_url = "https://op.example.com/.well-known/custom-configuration";

        let issuer = Issuer::discover_async(
            &issuer_discovery_url,
            get_default_test_interceptor(Some(mock_http_server.port())),
        )
        .await
        .unwrap();

        assert_eq!("https://op.example.com", issuer.issuer);

        assert_eq!(
            "https://op.example.com/oauth2/v3/certs",
            issuer.jwks_uri.unwrap(),
        );

        assert_eq!(
            "https://op.example.com/oauth2/v4/token",
            issuer.token_endpoint.unwrap(),
        );

        assert_eq!(
            "https://op.example.com/oauth2/v3/userinfo",
            issuer.userinfo_endpoint.unwrap(),
        );

        assert_eq!(
            "https://op.example.com/o/oauth2/v2/auth",
            issuer.authorization_endpoint.unwrap(),
        );
    }
}

#[cfg(test)]
mod well_known {

    use super::*;

    #[tokio::test]
    async fn accepts_and_assigns_the_discovered_metadata() {
        let mock_http_server = MockServer::start();

        let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200)
                .header("content-type", "application/json")
                .body(get_default_expected_discovery_document());
        });

        let issuer_discovery_url = "https://op.example.com/.well-known/openid-configuration";

        let issuer = Issuer::discover_async(
            &issuer_discovery_url,
            get_default_test_interceptor(Some(mock_http_server.port())),
        )
        .await
        .unwrap();

        assert_eq!("https://op.example.com", issuer.issuer);

        assert_eq!(
            "https://op.example.com/oauth2/v3/certs",
            issuer.jwks_uri.unwrap(),
        );

        assert_eq!(
            "https://op.example.com/oauth2/v4/token",
            issuer.token_endpoint.unwrap(),
        );

        assert_eq!(
            "https://op.example.com/oauth2/v3/userinfo",
            issuer.userinfo_endpoint.unwrap(),
        );

        assert_eq!(
            "https://op.example.com/o/oauth2/v2/auth",
            issuer.authorization_endpoint.unwrap(),
        );
    }

    #[tokio::test]
    async fn can_be_discovered_by_omitting_well_known() {
        let mock_http_server = MockServer::start();

        let expected_discovery_document = "{\"issuer\":\"https://op.example.com\"}";

        let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200)
                .header("content-type", "application/json")
                .body(expected_discovery_document);
        });

        let issuer_discovery_url = "https://op.example.com";

        let issuer = Issuer::discover_async(
            &issuer_discovery_url,
            get_default_test_interceptor(Some(mock_http_server.port())),
        )
        .await
        .unwrap();

        assert_eq!(issuer_discovery_url, issuer.issuer);
    }

    #[tokio::test]
    async fn discovers_issuers_with_path_components_with_trailing_slash() {
        let mock_http_server = MockServer::start();

        let expected_discovery_document = "{\"issuer\":\"https://op.example.com/oidc\"}";

        let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .path("/oidc/.well-known/openid-configuration");
            then.status(200)
                .header("content-type", "application/json")
                .body(expected_discovery_document);
        });

        let issuer_discovery_url = "https://op.example.com/oidc/";

        let issuer = Issuer::discover_async(
            &issuer_discovery_url,
            get_default_test_interceptor(Some(mock_http_server.port())),
        )
        .await
        .unwrap();

        assert_eq!("https://op.example.com/oidc", issuer.issuer,);
    }

    #[tokio::test]
    async fn discovers_issuers_with_path_components_without_trailing_slash() {
        let mock_http_server = MockServer::start();

        let expected_discovery_document = "{\"issuer\":\"https://op.example.com/oidc\"}";

        let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .path("/oidc/.well-known/openid-configuration");
            then.status(200)
                .header("content-type", "application/json")
                .body(&expected_discovery_document);
        });

        let issuer_discovery_url = "https://op.example.com/oidc";

        let issuer = Issuer::discover_async(
            &issuer_discovery_url,
            get_default_test_interceptor(Some(mock_http_server.port())),
        )
        .await
        .unwrap();

        assert_eq!("https://op.example.com/oidc", issuer.issuer,);
    }

    #[tokio::test]
    async fn discovering_issuers_with_well_known_uri_including_path_and_query() {
        let mock_http_server = MockServer::start();

        let expected_discovery_document = "{\"issuer\":\"https://op.example.com/oidc\"}";

        let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .path("/oidc/.well-known/openid-configuration");
            then.status(200)
                .header("content-type", "application/json")
                .body(&expected_discovery_document);
        });

        let issuer_discovery_url =
            "https://op.example.com/oidc/.well-known/openid-configuration?foo=bar";

        let issuer = Issuer::discover_async(
            &issuer_discovery_url,
            get_default_test_interceptor(Some(mock_http_server.port())),
        )
        .await
        .unwrap();

        assert_eq!("https://op.example.com/oidc", issuer.issuer,);
    }
}

mod well_known_oauth_authorization_server {

    use super::*;

    #[tokio::test]
    async fn accepts_and_assigns_the_discovered_metadata() {
        let mock_http_server = MockServer::start();

        let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .path("/.well-known/oauth-authorization-server");
            then.status(200)
                .header("content-type", "application/json")
                .body(get_default_expected_discovery_document());
        });

        let issuer_discovery_url = "https://op.example.com/.well-known/oauth-authorization-server";

        let issuer = Issuer::discover_async(
            &issuer_discovery_url,
            get_default_test_interceptor(Some(mock_http_server.port())),
        )
        .await
        .unwrap();

        assert_eq!("https://op.example.com", issuer.issuer);

        assert_eq!(
            "https://op.example.com/oauth2/v3/certs",
            issuer.jwks_uri.unwrap(),
        );

        assert_eq!(
            "https://op.example.com/oauth2/v4/token",
            issuer.token_endpoint.unwrap(),
        );

        assert_eq!(
            "https://op.example.com/oauth2/v3/userinfo",
            issuer.userinfo_endpoint.unwrap(),
        );

        assert_eq!(
            "https://op.example.com/o/oauth2/v2/auth",
            issuer.authorization_endpoint.unwrap(),
        );
    }

    #[tokio::test]
    async fn discovering_issuers_with_well_known_uri_including_path_and_query() {
        let mock_http_server = MockServer::start();

        let expected_discovery_document = "{\"issuer\":\"https://op.example.com/oauth2\"}";

        let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .path("/.well-known/oauth-authorization-server/oauth2");
            then.status(200)
                .header("content-type", "application/json")
                .body(&expected_discovery_document);
        });

        let issuer_discovery_url =
            "https://op.example.com/.well-known/oauth-authorization-server/oauth2?foo=bar";

        let issuer = Issuer::discover_async(
            &issuer_discovery_url,
            get_default_test_interceptor(Some(mock_http_server.port())),
        )
        .await
        .unwrap();

        assert_eq!("https://op.example.com/oauth2", issuer.issuer,);
    }
}

#[tokio::test]
async fn assigns_discovery_1_0_defaults_1_of_2() {
    let mock_http_server = MockServer::start();

    let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET).path("/.well-known/openid-configuration");
        then.status(200)
            .header("content-type", "application/json")
            .body(get_default_expected_discovery_document());
    });

    let issuer_discovery_url = "https://op.example.com/.well-known/openid-configuration";

    let issuer = Issuer::discover_async(
        &issuer_discovery_url,
        get_default_test_interceptor(Some(mock_http_server.port())),
    )
    .await
    .unwrap();

    assert_eq!(false, issuer.claims_parameter_supported.unwrap());

    assert_eq!(
        vec!["authorization_code".to_string(), "implicit".to_string(),],
        issuer.grant_types_supported.unwrap(),
    );

    assert_eq!(false, issuer.request_parameter_supported.unwrap());

    assert_eq!(true, issuer.request_uri_parameter_supported.unwrap());

    assert_eq!(false, issuer.require_request_uri_registration.unwrap());

    assert_eq!(
        vec!["query".to_string(), "fragment".to_string()],
        issuer.response_modes_supported.unwrap(),
    );

    assert_eq!(vec!["normal".to_string()], issuer.claim_types_supported);

    assert_eq!(
        vec!["client_secret_basic".to_string()],
        issuer.token_endpoint_auth_methods_supported.unwrap(),
    );
}

#[tokio::test]
async fn assigns_discovery_1_0_defaults_2_of_2() {
    let mock_http_server = MockServer::start();

    let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET).path("/.well-known/openid-configuration");
        then.status(200)
            .header("content-type", "application/json")
            .body(get_default_expected_discovery_document());
    });

    let issuer_discovery_url = "https://op.example.com";

    let issuer = Issuer::discover_async(
        &issuer_discovery_url,
        get_default_test_interceptor(Some(mock_http_server.port())),
    )
    .await
    .unwrap();

    assert_eq!(false, issuer.claims_parameter_supported.unwrap());

    assert_eq!(
        vec!["authorization_code".to_string(), "implicit".to_string(),],
        issuer.grant_types_supported.unwrap(),
    );

    assert_eq!(false, issuer.request_parameter_supported.unwrap());

    assert_eq!(true, issuer.request_uri_parameter_supported.unwrap());

    assert_eq!(false, issuer.require_request_uri_registration.unwrap());

    assert_eq!(
        vec!["query".to_string(), "fragment".to_string()],
        issuer.response_modes_supported.unwrap(),
    );

    assert_eq!(vec!["normal".to_string()], issuer.claim_types_supported);

    assert_eq!(
        vec!["client_secret_basic".to_string()],
        issuer.token_endpoint_auth_methods_supported.unwrap(),
    );
}

#[tokio::test]
async fn is_rejected_with_op_error_upon_oidc_error() {
    let mock_http_server = MockServer::start();

    let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET).path("/.well-known/openid-configuration");
        then.status(500).body(
            "{\"error\":\"server_error\",\"error_description\":\"bad things are happening\"}",
        );
    });

    let issuer_discovery_url = "https://op.example.com";

    let error = Issuer::discover_async(
        &issuer_discovery_url,
        get_default_test_interceptor(Some(mock_http_server.port())),
    )
    .await
    .unwrap_err();

    assert!(error.is_op_error());

    let err = error.op_error().error;

    assert_eq!(err.error, "server_error");

    assert_eq!(
        Some("bad things are happening".to_string()),
        err.error_description
    );
}

#[tokio::test]
async fn is_rejected_with_error_when_no_absolute_url_is_provided() {
    let error = Issuer::discover_async("op.example.com/.well-known/foobar", None)
        .await
        .unwrap_err();

    assert!(error.is_type_error());

    let err = error.type_error().error;

    assert_eq!("only valid absolute URLs can be requested", err.message,);
}

#[tokio::test]
async fn is_rejected_with_rp_error_when_error_is_not_a_string() {
    let mock_http_server = MockServer::start();

    let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET).path("/.well-known/openid-configuration");
        then.status(400)
            .body("{\"error\": {},\"error_description\":\"bad things are happening\"}");
    });

    let issuer_discovery_url = "https://op.example.com";

    let error = Issuer::discover_async(
        &issuer_discovery_url,
        get_default_test_interceptor(Some(mock_http_server.port())),
    )
    .await
    .unwrap_err();

    assert!(error.is_op_error());

    let err = error.op_error().error;

    assert_eq!("server_error", err.error);

    assert_eq!(
        Some("expected 200 OK, got: 400 Bad Request".to_string()),
        err.error_description,
    );
}

#[tokio::test]
async fn is_rejected_with_when_non_200_is_returned() {
    let mock_http_server = MockServer::start();

    let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET).path("/.well-known/openid-configuration");
        then.status(500);
    });

    let issuer_discovery_url = "https://op.example.com";

    let error = Issuer::discover_async(
        &issuer_discovery_url,
        get_default_test_interceptor(Some(mock_http_server.port())),
    )
    .await
    .unwrap_err();

    assert!(error.is_op_error());

    let err = error.op_error();

    assert_eq!("server_error", err.error.error);

    assert_eq!(
        Some("expected 200 OK, got: 500 Internal Server Error".to_string()),
        err.error.error_description,
    );

    assert!(err.response.is_some());
}

#[tokio::test]
async fn is_rejected_with_json_parse_error_upon_invalid_response() {
    let mock_http_server = MockServer::start();

    let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET).path("/.well-known/openid-configuration");
        then.status(200).body("{\"notavalid\"}");
    });

    let issuer_discovery_url = "https://op.example.com";

    let error = Issuer::discover_async(
        &issuer_discovery_url,
        get_default_test_interceptor(Some(mock_http_server.port())),
    )
    .await
    .unwrap_err();

    assert!(error.is_type_error());

    let err = error.type_error();

    assert_eq!("unexpected body type", err.error.message);

    assert!(err.response.is_some());
}

#[tokio::test]
async fn is_rejected_when_no_body_is_returned() {
    let mock_http_server = MockServer::start();

    let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET).path("/.well-known/openid-configuration");
        then.status(200);
    });

    let issuer_discovery_url = "https://op.example.com";

    let error = Issuer::discover_async(
        &issuer_discovery_url,
        get_default_test_interceptor(Some(mock_http_server.port())),
    )
    .await
    .unwrap_err();

    assert!(error.is_op_error());

    let err = error.op_error().error;

    assert_eq!("server_error", err.error);

    assert_eq!(
        Some("expected 200 OK with body but no body was returned".to_string()),
        err.error_description,
    );
}

#[tokio::test]
async fn is_rejected_when_unepexted_status_code_is_returned() {
    let mock_http_server = MockServer::start();

    let _issuer_discovery_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET).path("/.well-known/openid-configuration");
        then.status(301);
    });

    let issuer_discovery_url = "https://op.example.com";

    let error = Issuer::discover_async(
        &issuer_discovery_url,
        get_default_test_interceptor(Some(mock_http_server.port())),
    )
    .await
    .unwrap_err();

    assert!(error.is_op_error());

    let err = error.op_error().error;

    assert_eq!("server_error", err.error);

    assert_eq!(
        Some("expected 200 OK, got: 301 Moved Permanently".to_string()),
        err.error_description,
    );
}

#[cfg(test)]
mod http_options {

    use crate::tests::test_interceptors::TestInterceptor;

    use super::*;

    #[tokio::test]
    async fn allows_for_http_options_to_be_defined_for_issuer_discover_calls() {
        let mock_http_server = MockServer::start();

        let auth_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .header("testHeader", "testHeaderValue")
                .path("/.well-known/custom-configuration");
            then.status(200)
                .header("content-type", "application/json")
                .body(get_default_expected_discovery_document());
        });

        let _ = Issuer::discover_async(
            "https://op.example.com/.well-known/custom-configuration",
            Some(Box::new(TestInterceptor {
                test_header: Some("testHeader".to_string()),
                test_header_value: Some("testHeaderValue".to_string()),
                test_server_port: Some(mock_http_server.port()),
                crt: None,
                key: None,
                pfx: None,
            })),
        )
        .await;

        auth_mock_server.assert_hits(1);
    }
}
