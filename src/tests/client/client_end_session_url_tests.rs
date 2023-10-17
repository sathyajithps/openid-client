use std::collections::HashMap;

use serde_json::{json, Value};

use crate::{
    client::{client::client_test::helpers::get_query, Client},
    issuer::Issuer,
    types::{ClientMetadata, EndSessionParameters, IssuerMetadata},
};

struct TestClients {
    pub client: Client,
    pub client_with_uris: Client,
    pub client_without_meta: Client,
    pub client_with_query: Client,
}

fn setup_clients() -> TestClients {
    let issuer_metadata = IssuerMetadata {
        end_session_endpoint: Some("https://op.example.com/session/end".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata, None);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        ..Default::default()
    };

    let client = issuer
        .client(client_metadata, None, None, None, false)
        .unwrap();

    let client_with_uri_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        post_logout_redirect_uris: Some(vec!["https://rp.example.com/logout/cb".to_string()]),
        ..Default::default()
    };

    let client_with_uris = issuer
        .client(client_with_uri_metadata, None, None, None, false)
        .unwrap();

    let issuer_metadata_with_query = IssuerMetadata {
        end_session_endpoint: Some("https://op.example.com/session/end?foo=bar".to_string()),
        ..Default::default()
    };

    let issuer_with_query = Issuer::new(issuer_metadata_with_query, None);

    let client_with_query_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        ..Default::default()
    };

    let client_with_query = issuer_with_query
        .client(client_with_query_metadata, None, None, None, false)
        .unwrap();

    let issuer_without_meta = Issuer::new(IssuerMetadata::default(), None);

    let client_without_meta = ClientMetadata {
        client_id: Some("identifier".to_string()),
        ..Default::default()
    };

    let client_without_meta = issuer_without_meta
        .client(client_without_meta, None, None, None, false)
        .unwrap();

    TestClients {
        client,
        client_with_uris,
        client_without_meta,
        client_with_query,
    }
}

#[test]
fn returns_error_if_the_issuer_doesnt_have_end_session_endpoint_configured() {
    let client = setup_clients().client_without_meta;

    let error = client
        .end_session_url(EndSessionParameters::default())
        .unwrap_err();

    assert!(error.is_type_error());
    assert_eq!(
        "end_session_endpoint must be configured on the issuer",
        error.type_error().error.message
    );
}

#[test]
fn returns_the_end_session_endpoint_with_client_id_if_nothing_is_passed_1() {
    let client = setup_clients().client;

    let url = client
        .end_session_url(EndSessionParameters::default())
        .unwrap();

    assert_eq!(
        "https://op.example.com/session/end?client_id=identifier",
        url.to_string()
    );
}

#[test]
fn returns_the_end_session_endpoint_with_client_id_if_nothing_is_passed_2() {
    let client = setup_clients().client_with_query;

    let url = client
        .end_session_url(EndSessionParameters::default())
        .unwrap();

    assert_eq!(
        "https://op.example.com/session/end",
        format!("{}://{}{}", url.scheme(), url.host().unwrap(), url.path())
    );

    assert_eq!(Some("bar".to_string()), get_query(&url, "foo"));
    assert_eq!(Some("identifier".to_string()), get_query(&url, "client_id"));
}

#[test]
fn defaults_the_post_logout_redirect_uri_if_client_has_some() {
    let client = setup_clients().client_with_uris;

    let url = client
        .end_session_url(EndSessionParameters::default())
        .unwrap();

    assert_eq!(
        Some("https://rp.example.com/logout/cb".to_string()),
        get_query(&url, "post_logout_redirect_uri")
    );
    assert_eq!(Some("identifier".to_string()), get_query(&url, "client_id"));
}

#[test]
fn allows_to_override_default_applied_values() {
    let client = setup_clients().client;

    let url = client
        .end_session_url(EndSessionParameters {
            client_id: Some("override".to_string()),
            post_logout_redirect_uri: Some("override".to_string()),
            ..Default::default()
        })
        .unwrap();

    assert_eq!(
        Some("override".to_string()),
        get_query(&url, "post_logout_redirect_uri")
    );
    assert_eq!(Some("override".to_string()), get_query(&url, "client_id"));
}

#[test]
fn allows_for_recommended_and_optional_query_params_to_be_passed_in_1() {
    let client = setup_clients().client;

    let url = client
        .end_session_url(EndSessionParameters {
            post_logout_redirect_uri: Some("https://rp.example.com/logout/cb".to_string()),
            state: Some("foo".to_string()),
            id_token_hint: Some("idtoken".to_string()),
            ..Default::default()
        })
        .unwrap();

    assert_eq!(
        Some("https://rp.example.com/logout/cb".to_string()),
        get_query(&url, "post_logout_redirect_uri")
    );
    assert_eq!(Some("identifier".to_string()), get_query(&url, "client_id"));
    assert_eq!(Some("foo".to_string()), get_query(&url, "state"));
    assert_eq!(
        Some("idtoken".to_string()),
        get_query(&url, "id_token_hint")
    );
}

#[test]
fn allows_for_recommended_and_optional_query_params_to_be_passed_in_2() {
    let client = setup_clients().client_with_query;

    let mut other: HashMap<String, Value> = HashMap::new();

    other.insert("foo".to_string(), json!("this will be ignored"));

    let url = client
        .end_session_url(EndSessionParameters {
            post_logout_redirect_uri: Some("https://rp.example.com/logout/cb".to_string()),
            state: Some("foo".to_string()),
            id_token_hint: Some("idtoken".to_string()),
            other: Some(other),
            ..Default::default()
        })
        .unwrap();

    assert_eq!(
        Some("https://rp.example.com/logout/cb".to_string()),
        get_query(&url, "post_logout_redirect_uri")
    );
    assert_eq!(Some("identifier".to_string()), get_query(&url, "client_id"));
    assert_eq!(Some("foo".to_string()), get_query(&url, "state"));
    assert_eq!(Some("bar".to_string()), get_query(&url, "foo"));
    assert_eq!(
        Some("idtoken".to_string()),
        get_query(&url, "id_token_hint")
    );
}
