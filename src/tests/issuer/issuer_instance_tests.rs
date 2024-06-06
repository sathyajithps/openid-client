use crate::http_client::DefaultHttpClient;
use crate::types::query_keystore::QueryKeyStore;
use crate::{issuer::Issuer, types::IssuerMetadata};

use crate::tests::test_http_client::{TestHttpClient, TestHttpReqRes};

static DEFAULT_JWKS: &str = r#"{"keys":[{"e":"AQAB","n":"zwGRh6jBiyfwbSz_gs71ehiLLuVNd5Cyb67wKVPaS6GFyHtPjD5r-Yta5aZ7OaZV1AB7ieuhvvKsjvx4pzBAnQzwyYcaFDdb91jVHad019LMkjO_UTwSHegV_Bcwrhi0g64tfW3bTNUMEEKLZEusJZElpLi9HLZsGRJUlRCYRTqMeq1SYjQunVF9GmTTJlgK7IIdMYJ6ktQNRkQFz9ACpTZCS6SCUCjA4psFz-vtW-pBOvwO1gu4hWFQx9IFmPIojyZhF5kgfVlOnAc0YTRgj03uEMYXwLpBlbC-SPM9YXmFq1iflRbxEZqEP170J_27HjYpvo8eK2YwL9jXxNLC4Q","kty":"RSA","kid":"RraeLjB4KnAKQaihCOLHPByOJaSjXc0iWkhq2b3I7-o"}]}"#;

#[tokio::test]
async fn requires_jwks_uri_to_be_configured() {
    let issuer = Issuer::new(IssuerMetadata::default());

    let mut keystore = issuer.keystore.unwrap();

    assert!(keystore
        .get_keystore_async(false, &DefaultHttpClient)
        .await
        .is_err());
    assert_eq!(
        "jwks_uri must be configured on the issuer".to_string(),
        keystore
            .get_keystore_async(false, &DefaultHttpClient)
            .await
            .unwrap_err()
            .type_error()
            .error
            .message,
    );
}

#[tokio::test]
async fn does_not_refetch_immediately() {
    let http_client = TestHttpReqRes::new("https://op.example.com/jwks")
        .assert_request_header(
            "accept",
            vec![
                "application/json".to_string(),
                "application/jwk-set+json".to_string(),
            ],
        )
        .set_response_content_type_header("application/jwk-set+json")
        .set_response_body(DEFAULT_JWKS)
        .build();

    let issuer = "https://op.example.com".to_string();
    let jwks_uri = "https://op.example.com/jwks".to_string();

    let metadata = IssuerMetadata {
        issuer,
        jwks_uri: Some(jwks_uri),
        ..IssuerMetadata::default()
    };

    let issuer = Issuer::new(metadata);

    let mut keystore = issuer.keystore.unwrap();

    assert!(keystore
        .get_keystore_async(true, &http_client)
        .await
        .is_ok());

    let _ = keystore
        .get_keystore_async(false, &http_client)
        .await
        .unwrap();

    http_client.assert();
}

#[tokio::test]
async fn refetches_if_asked_to() {
    let http_client = TestHttpClient::new()
        .add(
            TestHttpReqRes::new("https://op.example.com/jwks")
                .assert_request_header(
                    "accept",
                    vec![
                        "application/json".to_string(),
                        "application/jwk-set+json".to_string(),
                    ],
                )
                .set_response_content_type_header("application/jwk-set+json")
                .set_response_body(DEFAULT_JWKS),
        )
        .add(
            TestHttpReqRes::new("https://op.example.com/jwks")
                .assert_request_header(
                    "accept",
                    vec![
                        "application/json".to_string(),
                        "application/jwk-set+json".to_string(),
                    ],
                )
                .set_response_content_type_header("application/jwk-set+json")
                .set_response_body(DEFAULT_JWKS),
        );

    let issuer = "https://op.example.com".to_string();
    let jwks_uri = "https://op.example.com/jwks".to_string();

    let metadata = IssuerMetadata {
        issuer,
        jwks_uri: Some(jwks_uri),
        ..IssuerMetadata::default()
    };

    let issuer = Issuer::new(metadata);

    let mut keystore = issuer.keystore.unwrap();

    assert!(keystore
        .get_keystore_async(true, &http_client)
        .await
        .is_ok());

    assert!(keystore
        .get_keystore_async(true, &http_client)
        .await
        .is_ok());

    http_client.assert();
}

#[tokio::test]
async fn rejects_when_no_matching_key_is_found() {
    let http_client = TestHttpReqRes::new("https://op.example.com/jwks")
        .assert_request_header(
            "accept",
            vec![
                "application/json".to_string(),
                "application/jwk-set+json".to_string(),
            ],
        )
        .set_response_content_type_header("application/jwk-set+json")
        .set_response_body(DEFAULT_JWKS)
        .build();

    let issuer = "https://op.example.com".to_string();
    let jwks_uri = "https://op.example.com/jwks".to_string();

    let metadata = IssuerMetadata {
        issuer,
        jwks_uri: Some(jwks_uri),
        ..IssuerMetadata::default()
    };

    let mut issuer = Issuer::new(metadata);

    let query = QueryKeyStore {
        alg: Some("RS256".to_string()),
        key_use: Some("sig".to_string()),
        key_id: Some("noway".to_string()),
        key_type: None,
    };

    let jwk_result = issuer
        .query_keystore_async(query, false, &http_client)
        .await;

    let expected_error = "no valid key found in issuer\'s jwks_uri for key parameters kid: noway, alg: RS256, key_use: sig";

    assert!(jwk_result.is_err());

    let error = jwk_result.unwrap_err();

    assert_eq!(expected_error, error.rp_error().error.message);
}

#[tokio::test]
async fn requires_a_kid_when_multiple_matches_are_found() {
    let http_client = TestHttpReqRes::new("https://op.example.com/jwks")
    .assert_request_header(
        "accept",
        vec![
            "application/json".to_string(),
            "application/jwk-set+json".to_string(),
        ],
    )
    .set_response_content_type_header("application/jwk-set+json")
    .set_response_body(r#"{"keys":[{"e":"AQAB","n":"5RnVQ2VT79TaW_Louj5ib7_dVJ1vX5ebaVeifBjNDlUp3KsrHm5sq1KWzPVz-XE6m4GBGXnVxMc5pmN7pQcqGe2rzw_jTAOIQzjYZ2UPTvl8HSjPCf9VwJleHiy4195YgnOcAF-PVASLKNKnoHjgn4b2gXpikMnztvdTFZrQAAlEVwslbW0Z17imHQsYzDXDYVzwpxjiRl4tWretNXhJS2Bk1NZoctW5kY6otkeMZ8VLpCUfbBzrhhLh5b_7Q0JKQjGX94f8j5tpVz_CXkpwQUXyymfBH9B-FY5s7LDZRKCEneSnCwSFce_nVzPqcO5J4SwsVF6FhwVQMvCC0QmNGw","kty":"RSA"},{"e":"AQAB","n":"3ANc8Uhup5_tnZfJuR4jQIwzobzEegcPGySt_EVzdF8ft2L4RoOE8wWq2fff9tRtrzNcKjSTgpw6cDMXSEa2Mx07FUvuyvjXSzlUG_fEPGIhyEJXqD5NZ89CrgHy55kizSuvgxcpQLkvSddBXVYnccWRGXfCurj7BkY1ycxvm55LAkPkaEtSWmnX8gWX6289SeKx-3rD0Xl20lhoe0_f4nChWibn-2egKBfrq-d1nXnsyxOcDhOZHS9nC4N4UeiZyQ6ervyGDg1fxzi98gxe4qb14J3vogX3KUdyG0YuC4D1SgUtEnmrVbbQl9y3fYBKZy7ysk48j9CdWjA9KYoWUQ","kty":"RSA"}]}"#)
    .build();

    let issuer = "https://op.example.com".to_string();
    let jwks_uri = "https://op.example.com/jwks".to_string();

    let metadata = IssuerMetadata {
        issuer,
        jwks_uri: Some(jwks_uri),
        ..IssuerMetadata::default()
    };

    let mut issuer = Issuer::new(metadata);

    let query = QueryKeyStore {
        alg: Some("RS256".to_string()),
        key_use: Some("sig".to_string()),
        key_id: None,
        key_type: None,
    };

    let jwk_result = issuer
        .query_keystore_async(query, false, &http_client)
        .await;

    let expected_error = "multiple matching keys found in issuer\'s jwks_uri for key parameters kid: , key_use: sig, alg: RS256, kid must be provided in this case";

    assert!(jwk_result.is_err());

    let error = jwk_result.unwrap_err();

    assert_eq!(expected_error, error.rp_error().error.message);
}

#[tokio::test]
async fn multiple_keys_can_match_jwt_header() {
    let http_client = TestHttpReqRes::new("https://op.example.com/jwks")
    .assert_request_header(
        "accept",
        vec![
            "application/json".to_string(),
            "application/jwk-set+json".to_string(),
        ],
    )
    .set_response_content_type_header("application/jwk-set+json")
    .set_response_body(r#"{"keys":[{"e":"AQAB","n":"5RnVQ2VT79TaW_Louj5ib7_dVJ1vX5ebaVeifBjNDlUp3KsrHm5sq1KWzPVz-XE6m4GBGXnVxMc5pmN7pQcqGe2rzw_jTAOIQzjYZ2UPTvl8HSjPCf9VwJleHiy4195YgnOcAF-PVASLKNKnoHjgn4b2gXpikMnztvdTFZrQAAlEVwslbW0Z17imHQsYzDXDYVzwpxjiRl4tWretNXhJS2Bk1NZoctW5kY6otkeMZ8VLpCUfbBzrhhLh5b_7Q0JKQjGX94f8j5tpVz_CXkpwQUXyymfBH9B-FY5s7LDZRKCEneSnCwSFce_nVzPqcO5J4SwsVF6FhwVQMvCC0QmNGw","kty":"RSA","kid":"0pWEDfNcRM4-Lnqq6QDkmVzElFEdYE96gJff6yesi0A"},{"e":"AQAB","n":"3ANc8Uhup5_tnZfJuR4jQIwzobzEegcPGySt_EVzdF8ft2L4RoOE8wWq2fff9tRtrzNcKjSTgpw6cDMXSEa2Mx07FUvuyvjXSzlUG_fEPGIhyEJXqD5NZ89CrgHy55kizSuvgxcpQLkvSddBXVYnccWRGXfCurj7BkY1ycxvm55LAkPkaEtSWmnX8gWX6289SeKx-3rD0Xl20lhoe0_f4nChWibn-2egKBfrq-d1nXnsyxOcDhOZHS9nC4N4UeiZyQ6ervyGDg1fxzi98gxe4qb14J3vogX3KUdyG0YuC4D1SgUtEnmrVbbQl9y3fYBKZy7ysk48j9CdWjA9KYoWUQ","kty":"RSA","kid":"0pWEDfNcRM4-Lnqq6QDkmVzElFEdYE96gJff6yesi0A"}]}"#)
    .build();

    let issuer = "https://op.example.com".to_string();
    let jwks_uri = "https://op.example.com/jwks".to_string();

    let metadata = IssuerMetadata {
        issuer,
        jwks_uri: Some(jwks_uri),
        ..IssuerMetadata::default()
    };

    let mut issuer = Issuer::new(metadata);

    let query = QueryKeyStore {
        alg: Some("RS256".to_string()),
        key_use: Some("sig".to_string()),
        key_id: Some("0pWEDfNcRM4-Lnqq6QDkmVzElFEdYE96gJff6yesi0A".to_string()),
        key_type: None,
    };

    let jwk_result = issuer
        .query_keystore_async(query, false, &http_client)
        .await;

    assert!(jwk_result.is_ok());

    let matched_jwks = jwk_result.unwrap();

    assert!(matched_jwks.len() > 1);
}
