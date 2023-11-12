use std::collections::HashMap;

use lazy_static::lazy_static;
use regex::Regex;

use crate::{
    client::Client,
    issuer::Issuer,
    types::{AuthorizationParameters, ClaimParam, ClaimParamValue, ClientMetadata, IssuerMetadata},
};

lazy_static! {
    static ref ERR_REGEX: Regex = Regex::new(r#"name="(.+)" value="(.+)""#).unwrap();
}

fn params_from_html(html: String) -> HashMap<String, String> {
    let mut params: HashMap<String, String> = HashMap::new();

    for capture in ERR_REGEX.captures_iter(&html) {
        if let (Some(name), Some(value)) = (capture.get(1), capture.get(2)) {
            params.insert(name.as_str().to_string(), value.as_str().to_string());
        }
    }

    params
}

fn setup_client() -> Client {
    let issuer_metadata = IssuerMetadata {
        authorization_endpoint: Some("https://op.example.com/auth".to_string()),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata, None);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        ..Default::default()
    };

    issuer
        .client(client_metadata, None, None, None, None)
        .unwrap()
}

#[test]
fn returns_a_string_with_the_url_with_some_basic_defaults() {
    let client = setup_client();

    let auth_params = AuthorizationParameters {
        redirect_uri: Some("https://rp.example.com/cb".to_string()),
        ..Default::default()
    };

    let params = params_from_html(client.authorization_post(auth_params).unwrap());

    let mut expected: HashMap<String, String> = HashMap::new();

    expected.insert("client_id".to_string(), "identifier".to_string());
    expected.insert(
        "redirect_uri".to_string(),
        "https://rp.example.com/cb".to_string(),
    );
    expected.insert("response_type".to_string(), "code".to_string());
    expected.insert("scope".to_string(), "openid".to_string());

    assert_eq!(expected, params);
}

#[test]
fn allows_to_overwrite_the_defaults() {
    let client = setup_client();

    let auth_params = AuthorizationParameters {
        scope: Some(vec!["openid".to_string(), "offline_access".to_string()]),
        redirect_uri: Some("https://rp.example.com/cb".to_string()),
        response_type: Some(vec!["id_token".to_string()]),
        nonce: Some("foobar".to_string()),
        ..Default::default()
    };

    let params = params_from_html(client.authorization_post(auth_params).unwrap());

    let mut expected: HashMap<String, String> = HashMap::new();

    expected.insert("client_id".to_string(), "identifier".to_string());
    expected.insert(
        "redirect_uri".to_string(),
        "https://rp.example.com/cb".to_string(),
    );
    expected.insert("response_type".to_string(), "id_token".to_string());
    expected.insert("scope".to_string(), "openid offline_access".to_string());
    expected.insert("nonce".to_string(), "foobar".to_string());

    assert_eq!(expected, params);
}

#[test]
fn allows_any_other_params_to_be_provide_too() {
    let client = setup_client();

    let mut other: HashMap<String, String> = HashMap::new();

    other.insert("custom".to_string(), "property".to_string());

    let auth_params = AuthorizationParameters {
        state: Some("state".to_string()),
        other,
        ..Default::default()
    };

    let params = params_from_html(client.authorization_post(auth_params).unwrap());

    assert_eq!(Some(&"state".to_string()), params.get("state"));
    assert_eq!(Some(&"property".to_string()), params.get("custom"));
}

#[test]
fn auto_stringifies_claims_parameter() {
    let client = setup_client();

    let mut id_token: HashMap<String, ClaimParamValue> = HashMap::new();

    id_token.insert("email".to_string(), ClaimParamValue::Null);

    let auth_params = AuthorizationParameters {
        state: Some("state".to_string()),
        claims: Some(ClaimParam {
            userinfo: None,
            id_token: Some(id_token),
        }),
        ..Default::default()
    };

    let params = params_from_html(client.authorization_post(auth_params).unwrap());

    assert_eq!(
        Some(&r#"{"id_token":{"email":null}}"#.to_string()),
        params.get("claims")
    );
}
