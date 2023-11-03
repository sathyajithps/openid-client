use assert_json_diff::assert_json_eq;
use serde_json::{json, Value};

use crate::{helpers::now, tokenset::TokenSetParams};

use super::TokenSet;

#[test]
fn sets_the_expire_at_automatically_from_expires_in() {
    let tokenset = TokenSet::new(TokenSetParams {
        expires_in: Some(300),
        ..Default::default()
    });

    assert_eq!(Some(300), tokenset.get_expires_in());
    assert_eq!(Some(now() + 300), tokenset.get_expires_at());
    assert_eq!(false, tokenset.expired());
}

#[test]
fn expired_token_sets_expires_in_to_0() {
    let tokenset = TokenSet::new(TokenSetParams {
        expires_in: Some(-30),
        ..Default::default()
    });

    assert_eq!(Some(0), tokenset.get_expires_in());
    assert_eq!(Some(now() - 30), tokenset.get_expires_at());
    assert_eq!(true, tokenset.expired());
}

#[test]
fn provides_a_claims_getter() {
    let tokenset = TokenSet::new(TokenSetParams{
        id_token: Some("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ".to_string()),
        ..Default::default()
    });

    let claims = tokenset.claims().unwrap();

    assert_eq!(Some(&json!("1234567890")), claims.get("sub"));
    assert_eq!(Some(&json!("John Doe")), claims.get("name"));
    assert_eq!(Some(&json!(true)), claims.get("admin"));
}

#[test]
fn claims_is_none_if_id_token_not_present() {
    let tokenset = TokenSet::new(TokenSetParams::default());

    let claims = tokenset.claims();

    assert!(claims.is_none());
}

#[test]
fn claims_does_not_extend_dumped_tokenset_properties() {
    let tokenset = TokenSet::new(TokenSetParams{
        id_token: Some("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ".to_string()),
        ..Default::default()
    });
    let tokenset_str = serde_json::to_string(&tokenset).unwrap();

    assert_json_eq!(
        json!({"id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"}),
        serde_json::from_str::<Value>(&tokenset_str).unwrap()
    );
}
