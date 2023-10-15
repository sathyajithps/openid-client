use std::collections::HashMap;

use crate::{
    client::client::client_test::helpers::get_query,
    issuer::Issuer,
    types::{
        AuthorizationParameters, ClaimParam, ClaimParamValue, ClientMetadata, IssuerMetadata,
        ResourceParam,
    },
};

use crate::client::Client;
struct TestClients {
    pub client: Client,
    pub client_with_meta: Client,
    pub client_with_multiple_metas: Client,
    pub client_with_query: Client,
}

fn setup_clients() -> TestClients {
    let issuer_metadata = IssuerMetadata {
        issuer: "https://op.example.com".to_string(),
        authorization_endpoint: Some("https://op.example.com/auth".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata, None);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        ..Default::default()
    };

    let client = issuer.client(client_metadata, None, None, None).unwrap();

    let client_with_meta_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        response_types: Some(vec!["code id_token".to_string()]),
        redirect_uris: Some(vec!["https://rp.example.com/cb".to_string()]),
        ..Default::default()
    };

    let client_with_meta = issuer
        .client(client_with_meta_metadata, None, None, None)
        .unwrap();

    let client_with_multiple_metas_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        response_types: Some(vec!["code id_token".to_string(), "id_token".to_string()]),
        redirect_uris: Some(vec![
            "https://rp.example.com/cb".to_string(),
            "https://rp.example.com/cb2".to_string(),
        ]),
        ..Default::default()
    };

    let client_with_multiple_metas = issuer
        .client(client_with_multiple_metas_metadata, None, None, None)
        .unwrap();

    let issuer_metadata_with_query = IssuerMetadata {
        issuer: "https://op.example.com".to_string(),
        authorization_endpoint: Some("https://op.example.com/auth?foo=bar".to_string()),
        ..Default::default()
    };

    let issuer_with_query = Issuer::new(issuer_metadata_with_query, None);

    let client_with_query_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        ..Default::default()
    };

    let client_with_query = issuer_with_query
        .client(client_with_query_metadata, None, None, None)
        .unwrap();

    TestClients {
        client,
        client_with_meta,
        client_with_multiple_metas,
        client_with_query,
    }
}

#[test]
fn auto_stringifies_claims_parameter() {
    let clients = setup_clients();

    let mut id_token: HashMap<String, ClaimParamValue> = HashMap::new();

    id_token.insert("email".to_string(), ClaimParamValue::Null);

    let auth_params = AuthorizationParameters {
        claims: Some(ClaimParam {
            userinfo: None,
            id_token: Some(id_token),
        }),
        ..Default::default()
    };

    let url = clients.client.authorization_url(auth_params).unwrap();

    assert_eq!(
        Some(r#"{"id_token":{"email":null}}"#.to_string()),
        get_query(&url, "claims")
    );
}

#[test]
fn returns_a_string_with_the_url_with_some_basic_defaults() {
    let clients = setup_clients();

    let auth_params = AuthorizationParameters {
        redirect_uri: Some("https://rp.example.com/cb".to_string()),
        ..Default::default()
    };

    let url = clients.client.authorization_url(auth_params).unwrap();

    assert_eq!(Some("identifier".to_string()), get_query(&url, "client_id"));
    assert_eq!(
        Some("https://rp.example.com/cb".to_string()),
        get_query(&url, "redirect_uri")
    );
    assert_eq!(Some("code".to_string()), get_query(&url, "response_type"));
    assert_eq!(Some("openid".to_string()), get_query(&url, "scope"));
}

#[test]
fn returns_a_string_with_the_url_and_client_meta_specific_defaults() {
    let clients = setup_clients();

    let auth_params = AuthorizationParameters {
        nonce: Some("foo".to_string()),
        ..Default::default()
    };

    let url = clients
        .client_with_meta
        .authorization_url(auth_params)
        .unwrap();

    assert_eq!(Some("identifier".to_string()), get_query(&url, "client_id"));
    assert_eq!(
        Some("https://rp.example.com/cb".to_string()),
        get_query(&url, "redirect_uri")
    );
    assert_eq!(Some("foo".to_string()), get_query(&url, "nonce"));
    assert_eq!(
        Some("code id_token".to_string()),
        get_query(&url, "response_type")
    );
    assert_eq!(Some("openid".to_string()), get_query(&url, "scope"));
}

#[test]
fn returns_a_string_with_the_url_and_no_defaults_if_client_has_more_metas() {
    let clients = setup_clients();

    let auth_params = AuthorizationParameters {
        nonce: Some("foo".to_string()),
        ..Default::default()
    };

    let url = clients
        .client_with_multiple_metas
        .authorization_url(auth_params)
        .unwrap();

    assert_eq!(Some("identifier".to_string()), get_query(&url, "client_id"));

    assert_eq!(Some("openid".to_string()), get_query(&url, "scope"));
}

#[test]
fn keeps_original_query_parameters() {
    let clients = setup_clients();

    let auth_params = AuthorizationParameters {
        redirect_uri: Some("https://rp.example.com/cb".to_string()),
        ..Default::default()
    };

    let url = clients
        .client_with_query
        .authorization_url(auth_params)
        .unwrap();

    assert_eq!(Some("identifier".to_string()), get_query(&url, "client_id"));
    assert_eq!(
        Some("https://rp.example.com/cb".to_string()),
        get_query(&url, "redirect_uri")
    );
    assert_eq!(Some("code".to_string()), get_query(&url, "response_type"));
    assert_eq!(Some("openid".to_string()), get_query(&url, "scope"));
    assert_eq!(Some("bar".to_string()), get_query(&url, "foo"));
}

#[test]
fn allows_to_overwrite_the_defaults() {
    let clients = setup_clients();

    let auth_params = AuthorizationParameters {
        scope: Some("openid offline_access".to_string()),
        response_type: Some("id_token".to_string()),
        nonce: Some("foobar".to_string()),
        redirect_uri: Some("https://rp.example.com/cb".to_string()),
        ..Default::default()
    };

    let url = clients.client.authorization_url(auth_params).unwrap();

    assert_eq!(Some("identifier".to_string()), get_query(&url, "client_id"));
    assert_eq!(
        Some("https://rp.example.com/cb".to_string()),
        get_query(&url, "redirect_uri")
    );
    assert_eq!(Some("foobar".to_string()), get_query(&url, "nonce"));
    assert_eq!(
        Some("id_token".to_string()),
        get_query(&url, "response_type")
    );
    assert_eq!(
        Some("openid offline_access".to_string()),
        get_query(&url, "scope")
    );
}

#[test]
fn allows_any_other_params_to_be_provide_too() {
    let clients = setup_clients();

    let mut other: HashMap<String, String> = HashMap::new();

    other.insert("custom".to_string(), "property".to_string());

    let auth_params = AuthorizationParameters {
        state: Some("state".to_string()),
        other: Some(other),
        ..Default::default()
    };

    let url = clients.client.authorization_url(auth_params).unwrap();

    assert_eq!(Some("state".to_string()), get_query(&url, "state"));
    assert_eq!(Some("property".to_string()), get_query(&url, "custom"));
}

#[test]
fn allows_resource_to_passed_as_an_array() {
    let clients = setup_clients();

    let auth_params = AuthorizationParameters {
        resource: Some(ResourceParam::Array(vec![
            "urn:example:com".to_string(),
            "urn:example-2:com".to_string(),
        ])),
        ..Default::default()
    };

    let url = clients.client.authorization_url(auth_params).unwrap();

    assert!(url
        .query()
        .unwrap()
        .contains("resource=urn%3Aexample%3Acom&resource=urn%3Aexample-2%3Acom"));
}

#[test]
fn returns_error_if_authorization_endpoint_is_not_configured() {
    let issuer_metadata = IssuerMetadata {
        issuer: "https://op.example.com".to_string(),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata, None);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        ..Default::default()
    };

    let client = issuer.client(client_metadata, None, None, None).unwrap();

    let err = client
        .authorization_url(AuthorizationParameters::default())
        .unwrap_err();

    assert!(err.is_type_error());

    assert_eq!(
        "authorization_endpiont must be configured on the issuer",
        err.type_error().error.message
    );
}
