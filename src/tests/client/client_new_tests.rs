use std::collections::HashMap;

use josekit::jwk::Jwk;
use serde_json::{json, Value};

use crate::issuer::Issuer;
use crate::jwks::Jwks;
use crate::types::{ClientMetadata, Fapi, IssuerMetadata};

#[test]
fn requires_client_id() {
    let issuer_metadata = IssuerMetadata::default();
    let issuer = Issuer::new(issuer_metadata);
    let client_result = issuer.client(ClientMetadata::default(), None, None, None);

    assert!(client_result.is_err());

    let error = client_result.unwrap_err();

    assert_eq!("client_id is required", error.type_error().error.message);
}

#[test]
fn accepts_the_recognized_metadata() {
    let issuer_metadata = IssuerMetadata::default();
    let issuer = Issuer::new(issuer_metadata);

    let client_id = "identifier".to_string();
    let client_secret = Some("secure".to_string());

    let client_metadata = ClientMetadata {
        client_id: Some(client_id.clone()),
        client_secret: client_secret.clone(),
        ..ClientMetadata::default()
    };
    let client_result = issuer.client(client_metadata, None, None, None);

    assert!(client_result.is_ok());

    let client = client_result.unwrap();

    assert_eq!(client_id, client.client_id.clone());
    assert_eq!(client_secret.unwrap(), client.client_secret.unwrap());
}

#[test]
fn assigns_defaults_to_some_properties() {
    let issuer_metadata = IssuerMetadata::default();
    let issuer = Issuer::new(issuer_metadata);

    let client_id = "identifier".to_string();

    let client_metadata = ClientMetadata {
        client_id: Some(client_id.clone()),
        ..ClientMetadata::default()
    };

    let client_result = issuer.client(client_metadata, None, None, None);

    assert!(client_result.is_ok());

    let client = client_result.unwrap();

    assert_eq!(client_id, client.client_id);
    assert_eq!(vec!["authorization_code"], client.grant_types);
    assert_eq!("RS256".to_string(), client.id_token_signed_response_alg);
    assert_eq!(vec!["code".to_string()], client.response_types);
    assert_eq!(
        "client_secret_basic".to_string(),
        client.token_endpoint_auth_method.unwrap()
    );
}

#[test]
fn autofills_introspection_endpoint_auth_method() {
    let issuer_metadata = IssuerMetadata {
        introspection_endpoint: Some("https://op.example.com/token/introspection".to_string()),
        ..IssuerMetadata::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let token_endpoint_auth_method = || "client_secret_jwt".to_string();
    let token_endpoint_auth_signing_alg = || "HS512".to_string();

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        token_endpoint_auth_method: Some(token_endpoint_auth_method()),
        token_endpoint_auth_signing_alg: Some(token_endpoint_auth_signing_alg()),
        ..ClientMetadata::default()
    };

    let client = issuer.client(client_metadata, None, None, None).unwrap();

    assert_eq!(
        token_endpoint_auth_method(),
        client.introspection_endpoint_auth_method.unwrap()
    );

    assert_eq!(
        token_endpoint_auth_signing_alg(),
        client.introspection_endpoint_auth_signing_alg.unwrap()
    );
}

#[test]
fn autofills_revocation_endpoint_auth_method() {
    let issuer_metadata = IssuerMetadata {
        revocation_endpoint: Some("https://op.example.com/token/revocation".to_string()),
        ..IssuerMetadata::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let token_endpoint_auth_method = || "client_secret_jwt".to_string();
    let token_endpoint_auth_signing_alg = || "HS512".to_string();

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        token_endpoint_auth_method: Some(token_endpoint_auth_method()),
        token_endpoint_auth_signing_alg: Some(token_endpoint_auth_signing_alg()),
        ..ClientMetadata::default()
    };

    let client = issuer.client(client_metadata, None, None, None).unwrap();

    assert_eq!(
        token_endpoint_auth_method(),
        client.revocation_endpoint_auth_method.unwrap()
    );

    assert_eq!(
        token_endpoint_auth_signing_alg(),
        client.revocation_endpoint_auth_signing_alg.unwrap()
    );
}

#[test]
fn validates_the_issuer_has_supported_algs_announced_if_token_endpoint_signing_alg_is_not_defined_on_the_client(
) {
    let issuer_metadata = IssuerMetadata {
        token_endpoint: Some("https://op.example.com/token".to_string()),
        ..IssuerMetadata::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        token_endpoint_auth_method: Some("_jwt".to_string()),
        ..ClientMetadata::default()
    };

    let client_error = issuer
        .client(client_metadata, None, None, None)
        .unwrap_err();

    let expected_error = "token_endpoint_auth_signing_alg_values_supported must be configured on the issuer if token_endpoint_auth_signing_alg is not defined on a client";

    assert_eq!(expected_error, client_error.type_error().error.message);
}

#[test]
fn validates_the_issuer_has_supported_algs_announced_if_introspection_endpoint_signing_alg_is_not_defined_on_the_client(
) {
    let issuer_metadata = IssuerMetadata {
        introspection_endpoint: Some("https://op.example.com/token/introspection".to_string()),
        ..IssuerMetadata::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        introspection_endpoint_auth_method: Some("_jwt".to_string()),
        ..ClientMetadata::default()
    };

    let client_error = issuer
        .client(client_metadata, None, None, None)
        .unwrap_err();

    let expected_error = "introspection_endpoint_auth_signing_alg_values_supported must be configured on the issuer if introspection_endpoint_auth_signing_alg is not defined on a client";

    assert_eq!(expected_error, client_error.type_error().error.message);
}

#[test]
fn validates_the_issuer_has_supported_algs_announced_if_revocation_endpoint_signing_alg_is_not_defined_on_the_client(
) {
    let issuer_metadata = IssuerMetadata {
        revocation_endpoint: Some("https://op.example.com/token/revocation".to_string()),
        ..IssuerMetadata::default()
    };

    let issuer = Issuer::new(issuer_metadata);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        revocation_endpoint_auth_method: Some("_jwt".to_string()),
        ..ClientMetadata::default()
    };

    let client_error = issuer
        .client(client_metadata, None, None, None)
        .unwrap_err();

    let expected_error = "revocation_endpoint_auth_signing_alg_values_supported must be configured on the issuer if revocation_endpoint_auth_signing_alg is not defined on a client";

    assert_eq!(expected_error, client_error.type_error().error.message);
}

#[test]
fn is_able_to_assign_custom_or_non_recognized_properties() {
    let issuer = Issuer::new(IssuerMetadata::default());

    let mut other_fields: HashMap<String, Value> = HashMap::new();

    other_fields.insert("foo".to_string(), json!("bar"));

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        other_fields,
        ..ClientMetadata::default()
    };

    let client = issuer.client(client_metadata, None, None, None).unwrap();

    assert!(client.other_fields.get("foo").is_some());
}

#[test]
fn handles_redirect_uri() {
    let issuer = Issuer::new(IssuerMetadata::default());

    let redirect_uri = || "https://rp.example.com/cb".to_string();

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        redirect_uri: Some(redirect_uri()),
        ..ClientMetadata::default()
    };

    let client = issuer.client(client_metadata, None, None, None).unwrap();

    assert_eq!(redirect_uri(), client.redirect_uri.unwrap());
    assert_eq!(vec![redirect_uri()], client.redirect_uris.unwrap());
}

#[test]
fn returns_error_if_redirect_uri_and_redirect_uris_are_given() {
    let issuer = Issuer::new(IssuerMetadata::default());

    let redirect_uri = || "https://rp.example.com/cb".to_string();

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        redirect_uri: Some(redirect_uri()),
        redirect_uris: Some(vec![redirect_uri()]),
        ..ClientMetadata::default()
    };

    let client_error = issuer
        .client(client_metadata, None, None, None)
        .unwrap_err();

    assert_eq!(
        "provide a redirect_uri or redirect_uris, not both".to_string(),
        client_error.type_error().error.message
    );
}

#[test]
fn handles_response_type() {
    let issuer = Issuer::new(IssuerMetadata::default());

    let response_type = || "code id_token".to_string();

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        response_type: Some(response_type()),
        ..ClientMetadata::default()
    };

    let client = issuer.client(client_metadata, None, None, None).unwrap();

    assert_eq!(response_type(), client.response_type.unwrap());
    assert_eq!(vec![response_type()], client.response_types);
}

#[test]
fn returns_error_if_response_type_and_response_types_are_given() {
    let issuer = Issuer::new(IssuerMetadata::default());

    let response_type = || "code id_token".to_string();

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        response_type: Some(response_type()),
        response_types: Some(vec![response_type()]),
        ..ClientMetadata::default()
    };

    let client_error = issuer
        .client(client_metadata, None, None, None)
        .unwrap_err();

    assert_eq!(
        "provide a response_type or response_types, not both".to_string(),
        client_error.type_error().error.message
    );
}

mod fapi {

    use super::*;

    #[test]
    fn assigns_defaults_to_some_properties_for_fapi_1() {
        let issuer_metadata = IssuerMetadata::default();
        let issuer = Issuer::new(issuer_metadata);

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            token_endpoint_auth_method: Some("private_key_jwt".to_string()),
            ..ClientMetadata::default()
        };

        let mut jwk = Jwk::generate_rsa_key(2048).unwrap();
        jwk.set_algorithm("PS256");

        let jwks = Jwks::from(vec![jwk]);

        let client_result = issuer.client(client_metadata, Some(jwks), None, Some(Fapi::V1));

        assert!(client_result.is_ok());

        let client = client_result.unwrap();

        assert_eq!(vec!["authorization_code", "implicit"], client.grant_types);
        assert_eq!("PS256".to_string(), client.id_token_signed_response_alg);
        assert_eq!(
            Some("PS256".to_string()),
            client.authorization_signed_response_alg
        );
        assert_eq!(vec!["code", "id_token"], client.response_types);
        assert_eq!(
            Some(true),
            client.tls_client_certificate_bound_access_tokens
        );
    }

    #[test]
    fn assigns_defaults_to_some_properties_for_fapi_2() {
        let issuer_metadata = IssuerMetadata::default();
        let issuer = Issuer::new(issuer_metadata);

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            dpop_bound_access_tokens: Some(true),
            ..ClientMetadata::default()
        };

        let client_result = issuer.client(client_metadata, None, None, Some(Fapi::V2));

        assert!(client_result.is_ok());

        let client = client_result.unwrap();

        assert_eq!("PS256".to_string(), client.id_token_signed_response_alg);
        assert_eq!(
            Some("PS256".to_string()),
            client.authorization_signed_response_alg
        );
    }

    #[test]
    fn token_endpoint_auth_method_is_required_for_fapi_1() {
        let issuer_metadata = IssuerMetadata::default();
        let issuer = Issuer::new(issuer_metadata);

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            ..ClientMetadata::default()
        };

        let err = issuer
            .client(client_metadata, None, None, Some(Fapi::V1))
            .unwrap_err();

        assert!(err.is_type_error());

        assert_eq!(
            "token_endpoint_auth_method is required",
            err.type_error().error.message
        );
    }

    #[test]
    fn jwks_is_required_for_private_key_jwt() {
        let issuer_metadata = IssuerMetadata::default();
        let issuer = Issuer::new(issuer_metadata);

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            token_endpoint_auth_method: Some("private_key_jwt".to_string()),
            ..ClientMetadata::default()
        };

        let err = issuer
            .client(client_metadata, None, None, Some(Fapi::V1))
            .unwrap_err();

        assert!(err.is_type_error());

        assert_eq!("jwks is required", err.type_error().error.message);
    }

    #[test]
    fn fapi_1_clients_rejects_other_token_endpoint_auth_methods() {
        let issuer_metadata = IssuerMetadata::default();
        let issuer = Issuer::new(issuer_metadata);

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            token_endpoint_auth_method: Some("client_secret_basic".to_string()),
            ..ClientMetadata::default()
        };

        let err = issuer
            .client(client_metadata, None, None, Some(Fapi::V1))
            .unwrap_err();

        assert!(err.is_type_error());

        assert_eq!(
            "invalid or unsupported token_endpoint_auth_method",
            err.type_error().error.message
        );
    }

    #[test]
    fn either_dpop_or_mtls_bound_at_is_required_for_fapi_2() {
        let issuer_metadata = IssuerMetadata::default();
        let issuer = Issuer::new(issuer_metadata);

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            ..ClientMetadata::default()
        };

        let err = issuer
            .client(client_metadata, None, None, Some(Fapi::V2))
            .unwrap_err();

        assert!(err.is_type_error());
        assert_eq!("one of tls_client_certificate_bound_access_tokens or dpop_bound_access_tokens must be true", err.type_error().error.message);
    }

    #[test]
    fn either_dpop_or_mtls_bound_should_be_configured_for_fapi_2() {
        let issuer_metadata = IssuerMetadata::default();
        let issuer = Issuer::new(issuer_metadata);

        let client_metadata = ClientMetadata {
            client_id: Some("identifier".to_string()),
            dpop_bound_access_tokens: Some(true),
            tls_client_certificate_bound_access_tokens: Some(true),
            ..ClientMetadata::default()
        };

        let err = issuer
            .client(client_metadata, None, None, Some(Fapi::V2))
            .unwrap_err();

        assert!(err.is_type_error());
        assert_eq!("only one of tls_client_certificate_bound_access_tokens or dpop_bound_access_tokens must be true", err.type_error().error.message);
    }
}
