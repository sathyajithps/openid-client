use crate::{
    issuer::Issuer,
    types::{ClientMetadata, IssuerMetadata},
};

#[test]
fn client_encryption_secret_test() {
    let issuer = Issuer::new(IssuerMetadata::default(), None);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        client_secret: Some("rj_JR".to_string()),
        ..Default::default()
    };

    let client = issuer.client(client_metadata, None, None, None).unwrap();

    let arr: [u16; 6] = [120, 128, 184, 192, 248, 256];

    for len in arr {
        let key = client.encryption_secret(len).unwrap();
        assert_eq!((len >> 3) as usize, key.len());
    }
}

#[test]
fn returns_error_on_invalid_lengths() {
    let issuer = Issuer::new(IssuerMetadata::default(), None);

    let client_metadata = ClientMetadata {
        client_id: Some("identifier".to_string()),
        client_secret: Some("rj_JR".to_string()),
        ..Default::default()
    };

    let client = issuer.client(client_metadata, None, None, None).unwrap();

    let error = client.encryption_secret(1024).unwrap_err();

    assert!(error.is_error());
    assert_eq!(
        "unsupported symmetric encryption key derivation",
        error.error().error.message
    );
}
