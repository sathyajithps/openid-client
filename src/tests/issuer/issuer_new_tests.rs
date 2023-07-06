use crate::issuer::Issuer;
use crate::types::IssuerMetadata;
use std::collections::HashMap;

#[test]
fn accepts_the_recognized_metadata() {
    let authorization_endpoint = || "https://accounts.google.com/o/oauth2/v2/auth".to_string();
    let token_endpoint = || "https://www.googleapis.com/oauth2/v4/token".to_string();
    let userinfo_endpoint = || "https://www.googleapis.com/oauth2/v3/userinfo".to_string();
    let jwks_uri = || "https://www.googleapis.com/oauth2/v3/certs".to_string();

    let metadata = IssuerMetadata {
        issuer: "https://accounts.google.com".to_string(),
        authorization_endpoint: Some(authorization_endpoint()),
        token_endpoint: Some(token_endpoint()),
        userinfo_endpoint: Some(userinfo_endpoint()),
        jwks_uri: Some(jwks_uri()),
        ..IssuerMetadata::default()
    };

    let issuer = Issuer::new(metadata, None);

    assert_eq!(
        authorization_endpoint(),
        issuer.authorization_endpoint.unwrap()
    );
    assert_eq!(token_endpoint(), issuer.token_endpoint.unwrap());
    assert_eq!(userinfo_endpoint(), issuer.userinfo_endpoint.unwrap());
    assert_eq!(jwks_uri(), issuer.jwks_uri.unwrap());
}

#[test]
fn does_not_assign_discovery_1_0_defaults_when_instantiating_manually() {
    let issuer = Issuer::new(IssuerMetadata::default(), None);

    assert!(issuer.claims_parameter_supported.is_none());
    assert!(issuer.grant_types_supported.is_none());
    assert!(issuer.request_parameter_supported.is_none());
    assert!(issuer.request_uri_parameter_supported.is_none());
    assert!(issuer.require_request_uri_registration.is_none());
    assert!(issuer.response_modes_supported.is_none());
    assert!(issuer.token_endpoint_auth_methods_supported.is_none());
}

#[test]
fn assigns_introspection_and_revocation_auth_method_meta_from_token_if_both_are_not_defined() {
    let token_endpoint = || "https://op.example.com/token".to_string();
    let token_endpoint_auth_methods_supported = || {
        vec![
            "client_secret_basic".to_string(),
            "client_secret_post".to_string(),
            "client_secret_jwt".to_string(),
        ]
    };

    let token_endpoint_auth_signing_alg_values_supported =
        || vec!["RS256".to_string(), "HS256".to_string()];

    let metadata = IssuerMetadata {
        token_endpoint: Some(token_endpoint()),
        token_endpoint_auth_methods_supported: Some(token_endpoint_auth_methods_supported()),
        token_endpoint_auth_signing_alg_values_supported: Some(
            token_endpoint_auth_signing_alg_values_supported(),
        ),
        ..IssuerMetadata::default()
    };

    let issuer = Issuer::new(metadata, None);

    assert_eq!(
        token_endpoint_auth_methods_supported(),
        issuer
            .introspection_endpoint_auth_methods_supported
            .unwrap(),
    );
    assert_eq!(
        token_endpoint_auth_methods_supported(),
        issuer.revocation_endpoint_auth_methods_supported.unwrap(),
    );

    assert_eq!(
        token_endpoint_auth_signing_alg_values_supported(),
        issuer
            .revocation_endpoint_auth_signing_alg_values_supported
            .unwrap(),
    );
    assert_eq!(
        token_endpoint_auth_signing_alg_values_supported(),
        issuer
            .introspection_endpoint_auth_signing_alg_values_supported
            .unwrap(),
    );
}

#[test]
fn is_able_to_discover_custom_or_non_recognized_properties() {
    let mut other_fields: HashMap<String, serde_json::Value> = HashMap::new();
    other_fields.insert(
        "foo".to_string(),
        serde_json::Value::String("bar".to_string()),
    );

    let metadata = IssuerMetadata {
        issuer: "https://op.example.com".to_string(),
        other_fields,
        ..IssuerMetadata::default()
    };

    let issuer = Issuer::new(metadata, None);

    assert_eq!("https://op.example.com".to_string(), issuer.issuer);
    assert!(issuer.other_fields.contains_key("foo"));
    assert_eq!(
        Some(&serde_json::Value::String("bar".to_string())),
        issuer.other_fields.get("foo"),
    );
}
