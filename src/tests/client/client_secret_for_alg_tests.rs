use crate::{
    issuer::Issuer,
    types::{ClientMetadata, IssuerMetadata},
};

#[test]
fn secret_alg_test() {
    let issuer = Issuer::new(IssuerMetadata::default(), None);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        client_secret: Some("rj_JR".to_string()),
        ..Default::default()
    };

    let client = issuer.client(client_metadata, None, None, None).unwrap();

    let secret = client.secret_for_alg("HS256").unwrap();

    assert_eq!(
        "rj_JR".to_string(),
        String::from_utf8(secret.key_value().unwrap()).unwrap()
    );
}

#[test]
fn returns_error_if_client_secret_is_not_configured() {
    let issuer = Issuer::new(IssuerMetadata::default(), None);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        ..Default::default()
    };

    let client = issuer.client(client_metadata, None, None, None).unwrap();

    let error = client.secret_for_alg("HS256").unwrap_err();

    assert!(error.is_type_error());

    assert_eq!(
        "client_secret is required",
        error.type_error().error.message
    );
}
