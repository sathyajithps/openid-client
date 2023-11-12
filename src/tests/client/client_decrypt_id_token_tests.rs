use crate::{
    issuer::Issuer,
    tokenset::{TokenSet, TokenSetParams},
    types::{ClientMetadata, IssuerMetadata},
};

#[test]
fn to_decrypt_tokenset_id_token_it_must_have_one() {
    let issuer = Issuer::new(IssuerMetadata::default(), None);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_encrypted_response_alg: Some("RSA-OAEP".to_string()),
        ..Default::default()
    };

    let client = issuer
        .client(client_metadata, None, None, None, None)
        .unwrap();

    let err = client.decrypt_id_token(TokenSet::default()).unwrap_err();

    assert!(err.is_type_error());

    assert_eq!(
        "id_token not present in TokenSet",
        err.type_error().error.message
    );
}

#[test]
fn verifies_the_id_token_using_the_right_alg() {
    let issuer = Issuer::new(IssuerMetadata::default(), None);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_encrypted_response_alg: Some("RSA-OAEP".to_string()),
        ..Default::default()
    };

    let client = issuer
        .client(client_metadata, None, None, None, None)
        .unwrap();

    let header = base64_url::encode(r#"{"alg":"RSA1_5","enc":"A128CBC-HS256"}"#);

    let id_token = format!("{}....", header);

    let token_set_params = TokenSetParams {
        id_token: Some(id_token),
        ..Default::default()
    };

    let err = client
        .decrypt_id_token(TokenSet::new(token_set_params))
        .unwrap_err();

    assert!(err.is_rp_error());

    assert_eq!(
        "unexpected JWE alg received, expected RSA-OAEP, got: RSA1_5",
        err.rp_error().error.message
    );
}

#[test]
fn verifies_the_id_token_is_using_the_right_enc_explicit() {
    let issuer = Issuer::new(IssuerMetadata::default(), None);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_encrypted_response_alg: Some("RSA-OAEP".to_string()),
        id_token_encrypted_response_enc: Some("A128CBC-HS256".to_string()),
        ..Default::default()
    };

    let client = issuer
        .client(client_metadata, None, None, None, None)
        .unwrap();

    let header = base64_url::encode(r#"{"alg":"RSA-OAEP","enc":"A128GCM"}"#);

    let id_token = format!("{}....", header);

    let token_set_params = TokenSetParams {
        id_token: Some(id_token),
        ..Default::default()
    };

    let err = client
        .decrypt_id_token(TokenSet::new(token_set_params))
        .unwrap_err();

    assert!(err.is_rp_error());

    assert_eq!(
        "unexpected JWE enc received, expected A128CBC-HS256, got: A128GCM",
        err.rp_error().error.message
    );
}

#[test]
fn verifies_the_id_token_is_using_the_right_enc_default_to() {
    let issuer = Issuer::new(IssuerMetadata::default(), None);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        id_token_encrypted_response_alg: Some("RSA-OAEP".to_string()),
        ..Default::default()
    };

    let client = issuer
        .client(client_metadata, None, None, None, None)
        .unwrap();

    let header = base64_url::encode(r#"{"alg":"RSA-OAEP","enc":"A128GCM"}"#);

    let id_token = format!("{}....", header);

    let token_set_params = TokenSetParams {
        id_token: Some(id_token),
        ..Default::default()
    };

    let err = client
        .decrypt_id_token(TokenSet::new(token_set_params))
        .unwrap_err();

    assert!(err.is_rp_error());

    assert_eq!(
        "unexpected JWE enc received, expected A128CBC-HS256, got: A128GCM",
        err.rp_error().error.message
    );
}
