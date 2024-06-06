use crate::http_client::DefaultHttpClient;
use crate::issuer::Issuer;
use crate::types::HttpMethod;

use crate::tests::test_http_client::TestHttpReqRes;

static DEFAULT_DISCOVERY: &str = r#"{"authorization_endpoint":"https://op.example.com/o/oauth2/v2/auth","issuer":"https://op.example.com","jwks_uri":"https://op.example.com/oauth2/v3/certs","token_endpoint":"https://op.example.com/oauth2/v4/token","userinfo_endpoint":"https://op.example.com/oauth2/v3/userinfo"}"#;

#[cfg(test)]
mod custom_well_known {

    use super::*;

    #[tokio::test]
    async fn accepts_and_assigns_the_discovered_metadata() {
        let issuer_discovery_url = "https://op.example.com/.well-known/custom-configuration";

        let http_client = TestHttpReqRes::new(issuer_discovery_url)
            .assert_request_method(HttpMethod::GET)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .set_response_body(DEFAULT_DISCOVERY)
            .set_response_content_type_header("application/json")
            .build();

        let issuer = Issuer::discover_async(&issuer_discovery_url, &http_client)
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
        let issuer_discovery_url = "https://op.example.com/.well-known/openid-configuration";

        let http_client = TestHttpReqRes::new(issuer_discovery_url)
            .assert_request_method(HttpMethod::GET)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .set_response_body(DEFAULT_DISCOVERY)
            .set_response_content_type_header("application/json")
            .build();

        let issuer = Issuer::discover_async(&issuer_discovery_url, &http_client)
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
        let issuer_discovery_url = "https://op.example.com";

        let http_client =
            TestHttpReqRes::new("https://op.example.com/.well-known/openid-configuration")
                .assert_request_method(HttpMethod::GET)
                .assert_request_header("accept", vec!["application/json".to_string()])
                .set_response_body(r#"{"issuer":"https://op.example.com"}"#)
                .set_response_content_type_header("application/json")
                .build();

        let issuer = Issuer::discover_async(&issuer_discovery_url, &http_client)
            .await
            .unwrap();

        assert_eq!(issuer_discovery_url, issuer.issuer);
    }

    #[tokio::test]
    async fn discovers_issuers_with_path_components_with_trailing_slash() {
        let http_client =
            TestHttpReqRes::new("https://op.example.com/oidc/.well-known/openid-configuration")
                .assert_request_method(HttpMethod::GET)
                .assert_request_header("accept", vec!["application/json".to_string()])
                .set_response_body(r#"{"issuer":"https://op.example.com/oidc"}"#)
                .set_response_content_type_header("application/json")
                .build();

        let issuer = Issuer::discover_async("https://op.example.com/oidc/", &http_client)
            .await
            .unwrap();

        assert_eq!("https://op.example.com/oidc", issuer.issuer,);
    }

    #[tokio::test]
    async fn discovers_issuers_with_path_components_without_trailing_slash() {
        let issuer_discovery_url = "https://op.example.com/oidc";

        let http_client =
            TestHttpReqRes::new("https://op.example.com/oidc/.well-known/openid-configuration")
                .assert_request_method(HttpMethod::GET)
                .assert_request_header("accept", vec!["application/json".to_string()])
                .set_response_body(r#"{"issuer":"https://op.example.com/oidc"}"#)
                .set_response_content_type_header("application/json")
                .build();

        let issuer = Issuer::discover_async(&issuer_discovery_url, &http_client)
            .await
            .unwrap();

        assert_eq!(issuer_discovery_url, issuer.issuer,);
    }

    #[tokio::test]
    async fn discovering_issuers_with_well_known_uri_including_path_and_query() {
        let issuer_discovery_url =
            "https://op.example.com/oidc/.well-known/openid-configuration?foo=bar";

        let http_client = TestHttpReqRes::new(issuer_discovery_url)
            .assert_request_method(HttpMethod::GET)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .set_response_body(r#"{"issuer":"https://op.example.com/oidc"}"#)
            .set_response_content_type_header("application/json")
            .build();

        let issuer = Issuer::discover_async(&issuer_discovery_url, &http_client)
            .await
            .unwrap();

        assert_eq!("https://op.example.com/oidc", issuer.issuer,);
    }
}

mod well_known_oauth_authorization_server {

    use super::*;

    #[tokio::test]
    async fn accepts_and_assigns_the_discovered_metadata() {
        let issuer_discovery_url = "https://op.example.com/.well-known/oauth-authorization-server";

        let http_client = TestHttpReqRes::new(issuer_discovery_url)
            .assert_request_method(HttpMethod::GET)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .set_response_body(DEFAULT_DISCOVERY)
            .set_response_content_type_header("application/json")
            .build();

        let issuer = Issuer::discover_async(&issuer_discovery_url, &http_client)
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
        let issuer_discovery_url =
            "https://op.example.com/.well-known/oauth-authorization-server/oauth2?foo=bar";

        let http_client = TestHttpReqRes::new(issuer_discovery_url)
            .assert_request_method(HttpMethod::GET)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .set_response_body(r#"{"issuer":"https://op.example.com/oauth2"}"#)
            .set_response_content_type_header("application/json")
            .build();

        let issuer = Issuer::discover_async(&issuer_discovery_url, &http_client)
            .await
            .unwrap();

        assert_eq!("https://op.example.com/oauth2", issuer.issuer,);
    }
}

#[tokio::test]
async fn assigns_discovery_1_0_defaults_1_of_2() {
    let issuer_discovery_url = "https://op.example.com/.well-known/openid-configuration";

    let http_client = TestHttpReqRes::new(issuer_discovery_url)
        .assert_request_method(HttpMethod::GET)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .set_response_body(DEFAULT_DISCOVERY)
        .set_response_content_type_header("application/json")
        .build();

    let issuer = Issuer::discover_async(&issuer_discovery_url, &http_client)
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
    let http_client =
        TestHttpReqRes::new("https://op.example.com/.well-known/openid-configuration")
            .assert_request_method(HttpMethod::GET)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .set_response_body(DEFAULT_DISCOVERY)
            .set_response_content_type_header("application/json")
            .build();

    let issuer = Issuer::discover_async("https://op.example.com", &http_client)
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
    let http_client =
        TestHttpReqRes::new("https://op.example.com/.well-known/openid-configuration")
            .assert_request_method(HttpMethod::GET)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .set_response_body(
                r#"{"error":"server_error","error_description":"bad things are happening"}"#,
            )
            .set_response_status_code(500)
            .build();

    let error = Issuer::discover_async("https://op.example.com", &http_client)
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
    let error = Issuer::discover_async("op.example.com/.well-known/foobar", &mut DefaultHttpClient)
        .await
        .unwrap_err();

    assert!(error.is_type_error());

    let err = error.type_error().error;

    assert_eq!("only valid absolute URLs can be requested", err.message,);
}

#[tokio::test]
async fn is_rejected_with_rp_error_when_error_is_not_a_string() {
    let http_client =
        TestHttpReqRes::new("https://op.example.com/.well-known/openid-configuration")
            .assert_request_method(HttpMethod::GET)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .set_response_body(r#"{"error": {},"error_description":"bad things are happening"}"#)
            .set_response_status_code(400)
            .build();

    let error = Issuer::discover_async("https://op.example.com", &http_client)
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
    let http_client =
        TestHttpReqRes::new("https://op.example.com/.well-known/openid-configuration")
            .assert_request_method(HttpMethod::GET)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .set_response_status_code(500)
            .build();

    let error = Issuer::discover_async("https://op.example.com", &http_client)
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
    let http_client =
        TestHttpReqRes::new("https://op.example.com/.well-known/openid-configuration")
            .assert_request_method(HttpMethod::GET)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .set_response_body(r#"{"notavalid"}"#)
            .set_response_status_code(200)
            .build();

    let error = Issuer::discover_async("https://op.example.com", &http_client)
        .await
        .unwrap_err();

    assert!(error.is_type_error());

    let err = error.type_error();

    assert_eq!("unexpected body type", err.error.message);

    assert!(err.response.is_some());
}

#[tokio::test]
async fn is_rejected_when_no_body_is_returned() {
    let http_client =
        TestHttpReqRes::new("https://op.example.com/.well-known/openid-configuration")
            .assert_request_method(HttpMethod::GET)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .set_response_status_code(200)
            .build();

    let error = Issuer::discover_async("https://op.example.com", &http_client)
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
    let http_client =
        TestHttpReqRes::new("https://op.example.com/.well-known/openid-configuration")
            .assert_request_method(HttpMethod::GET)
            .assert_request_header("accept", vec!["application/json".to_string()])
            .set_response_status_code(301)
            .build();

    let error = Issuer::discover_async("https://op.example.com", &http_client)
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
