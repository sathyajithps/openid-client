use url::Url;

use crate::{
    client::Client,
    issuer::Issuer,
    types::{ClientMetadata, IssuerMetadata},
};

fn get_client() -> Client {
    let issuer_metadata = IssuerMetadata {
        issuer: "http://localhost:3000/op".to_string(),
        ..Default::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        ..Default::default()
    };

    issuer.client(client_metadata, None, None, None).unwrap()
}

#[test]
fn when_uri_is_passed() {
    let client = get_client();

    let url = Url::parse("https://oidc-client.dev/cb?code=code").unwrap();

    let callback_params = client.callback_params(Some(&url), None).unwrap();

    assert_eq!("code", callback_params.code.unwrap())
}

#[test]
fn when_body_is_passed() {
    let client = get_client();

    let body = "code=code".to_string();

    let callback_params = client.callback_params(None, Some(body)).unwrap();

    assert_eq!("code", callback_params.code.unwrap())
}

#[test]
fn parses_url_encoded_string_from_uri() {
    let client = get_client();

    let url = Url::parse("https://oidc-client.dev/cb?error_description=error%20is%20bad").unwrap();

    let callback_params = client.callback_params(Some(&url), None).unwrap();

    assert_eq!("error is bad", callback_params.error_description.unwrap())
}

#[test]
fn parses_url_encoded_string_from_body() {
    let client = get_client();

    let body = "error_description=error%20is%20bad".to_string();

    let callback_params = client.callback_params(None, Some(body)).unwrap();

    assert_eq!("error is bad", callback_params.error_description.unwrap())
}

#[test]
fn returns_error_if_no_args() {
    let err = get_client().callback_params(None, None).unwrap_err();
    assert!(err.is_error());
    assert_eq!("could not parse the request", err.error().error.message);
}
