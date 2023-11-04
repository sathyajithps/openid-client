use crate::tests::test_interceptors::get_default_test_interceptor;
use crate::types::query_keystore::QueryKeyStore;
use crate::{issuer::Issuer, types::IssuerMetadata};
use httpmock::Method::GET;
use httpmock::MockServer;

fn get_default_jwks() -> String {
    "{\"keys\":[{\"e\":\"AQAB\",\"n\":\"zwGRh6jBiyfwbSz_gs71ehiLLuVNd5Cyb67wKVPaS6GFyHtPjD5r-Yta5aZ7OaZV1AB7ieuhvvKsjvx4pzBAnQzwyYcaFDdb91jVHad019LMkjO_UTwSHegV_Bcwrhi0g64tfW3bTNUMEEKLZEusJZElpLi9HLZsGRJUlRCYRTqMeq1SYjQunVF9GmTTJlgK7IIdMYJ6ktQNRkQFz9ACpTZCS6SCUCjA4psFz-vtW-pBOvwO1gu4hWFQx9IFmPIojyZhF5kgfVlOnAc0YTRgj03uEMYXwLpBlbC-SPM9YXmFq1iflRbxEZqEP170J_27HjYpvo8eK2YwL9jXxNLC4Q\",\"kty\":\"RSA\",\"kid\":\"RraeLjB4KnAKQaihCOLHPByOJaSjXc0iWkhq2b3I7-o\"}]}".to_string()
}

#[tokio::test]
async fn requires_jwks_uri_to_be_configured() {
    let issuer = Issuer::new(IssuerMetadata::default(), None);

    let mut keystore = issuer.keystore.unwrap();

    assert!(keystore.get_keystore_async(false).await.is_err());
    assert_eq!(
        "jwks_uri must be configured on the issuer".to_string(),
        keystore
            .get_keystore_async(false)
            .await
            .unwrap_err()
            .type_error()
            .error
            .message,
    );
}

#[tokio::test]
async fn does_not_refetch_immediately() {
    let mock_http_server = MockServer::start();

    let jwks_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET)
            .header("Accept", "application/json,application/jwk-set+json")
            .path("/jwks");
        then.status(200)
            .header("content-type", "application/jwk-set+json")
            .body(get_default_jwks());
    });

    let issuer = "https://op.example.com".to_string();
    let jwks_uri = "https://op.example.com/jwks".to_string();

    let metadata = IssuerMetadata {
        issuer,
        jwks_uri: Some(jwks_uri),
        ..IssuerMetadata::default()
    };

    let issuer = Issuer::new(
        metadata,
        get_default_test_interceptor(Some(mock_http_server.port())),
    );

    let mut keystore = issuer.keystore.unwrap();

    assert!(keystore.get_keystore_async(true).await.is_ok());

    let _ = keystore.get_keystore_async(false).await.unwrap();

    jwks_mock_server.assert_hits(1);
}

#[tokio::test]
async fn refetches_if_asked_to() {
    let mock_http_server = MockServer::start();

    let jwks_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET)
            .header("Accept", "application/json,application/jwk-set+json")
            .path("/jwks");
        then.status(200)
            .header("content-type", "application/jwk-set+json")
            .body(get_default_jwks());
    });

    let issuer = "https://op.example.com".to_string();
    let jwks_uri = "https://op.example.com/jwks".to_string();

    let metadata = IssuerMetadata {
        issuer,
        jwks_uri: Some(jwks_uri),
        ..IssuerMetadata::default()
    };

    let issuer = Issuer::new(
        metadata,
        get_default_test_interceptor(Some(mock_http_server.port())),
    );

    let mut keystore = issuer.keystore.unwrap();

    assert!(keystore.get_keystore_async(true).await.is_ok());

    assert!(keystore.get_keystore_async(true).await.is_ok());

    jwks_mock_server.assert_hits(2);
}

#[tokio::test]
async fn rejects_when_no_matching_key_is_found() {
    let mock_http_server = MockServer::start();

    let _jwks_mock_server = mock_http_server.mock(|when, then| {
        when.method(GET)
            .header("Accept", "application/json,application/jwk-set+json")
            .path("/jwks");
        then.status(200)
            .header("content-type", "application/jwk-set+json")
            .body(get_default_jwks());
    });

    let issuer = "https://op.example.com".to_string();
    let jwks_uri = "https://op.example.com/jwks".to_string();

    let metadata = IssuerMetadata {
        issuer,
        jwks_uri: Some(jwks_uri),
        ..IssuerMetadata::default()
    };

    let mut issuer = Issuer::new(
        metadata,
        get_default_test_interceptor(Some(mock_http_server.port())),
    );

    let query = QueryKeyStore {
        alg: Some("RS256".to_string()),
        key_use: Some("sig".to_string()),
        key_id: Some("noway".to_string()),
        key_type: None,
    };

    let jwk_result = issuer.query_keystore_async(query, false).await;

    let expected_error = "no valid key found in issuer\'s jwks_uri for key parameters kid: noway, alg: RS256, key_use: sig";

    assert!(jwk_result.is_err());

    let error = jwk_result.unwrap_err();

    assert_eq!(expected_error, error.rp_error().error.message);
}

#[tokio::test]
async fn requires_a_kid_when_multiple_matches_are_found() {
    let mock_http_server = MockServer::start();

    let _jwks_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .header("Accept", "application/json,application/jwk-set+json")
                .path("/jwks");

            then.status(200)
                .header("content-type", "application/jwk-set+json")
                .body("{\"keys\":[{\"e\":\"AQAB\",\"n\":\"5RnVQ2VT79TaW_Louj5ib7_dVJ1vX5ebaVeifBjNDlUp3KsrHm5sq1KWzPVz-XE6m4GBGXnVxMc5pmN7pQcqGe2rzw_jTAOIQzjYZ2UPTvl8HSjPCf9VwJleHiy4195YgnOcAF-PVASLKNKnoHjgn4b2gXpikMnztvdTFZrQAAlEVwslbW0Z17imHQsYzDXDYVzwpxjiRl4tWretNXhJS2Bk1NZoctW5kY6otkeMZ8VLpCUfbBzrhhLh5b_7Q0JKQjGX94f8j5tpVz_CXkpwQUXyymfBH9B-FY5s7LDZRKCEneSnCwSFce_nVzPqcO5J4SwsVF6FhwVQMvCC0QmNGw\",\"kty\":\"RSA\"},{\"e\":\"AQAB\",\"n\":\"3ANc8Uhup5_tnZfJuR4jQIwzobzEegcPGySt_EVzdF8ft2L4RoOE8wWq2fff9tRtrzNcKjSTgpw6cDMXSEa2Mx07FUvuyvjXSzlUG_fEPGIhyEJXqD5NZ89CrgHy55kizSuvgxcpQLkvSddBXVYnccWRGXfCurj7BkY1ycxvm55LAkPkaEtSWmnX8gWX6289SeKx-3rD0Xl20lhoe0_f4nChWibn-2egKBfrq-d1nXnsyxOcDhOZHS9nC4N4UeiZyQ6ervyGDg1fxzi98gxe4qb14J3vogX3KUdyG0YuC4D1SgUtEnmrVbbQl9y3fYBKZy7ysk48j9CdWjA9KYoWUQ\",\"kty\":\"RSA\"}]}");
        });

    let issuer = "https://op.example.com".to_string();
    let jwks_uri = "https://op.example.com/jwks".to_string();

    let metadata = IssuerMetadata {
        issuer,
        jwks_uri: Some(jwks_uri),
        ..IssuerMetadata::default()
    };

    let mut issuer = Issuer::new(
        metadata,
        get_default_test_interceptor(Some(mock_http_server.port())),
    );

    let query = QueryKeyStore {
        alg: Some("RS256".to_string()),
        key_use: Some("sig".to_string()),
        key_id: None,
        key_type: None,
    };

    let jwk_result = issuer.query_keystore_async(query, false).await;

    let expected_error = "multiple matching keys found in issuer\'s jwks_uri for key parameters kid: , key_use: sig, alg: RS256, kid must be provided in this case";

    assert!(jwk_result.is_err());

    let error = jwk_result.unwrap_err();

    assert_eq!(expected_error, error.rp_error().error.message);
}

#[tokio::test]
async fn multiple_keys_can_match_jwt_header() {
    let mock_http_server = MockServer::start();

    let _jwks_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .header("Accept", "application/json,application/jwk-set+json")
                .path("/jwks");

            then.status(200)
                .header("content-type", "application/jwk-set+json")
                .body("{\"keys\":[{\"e\":\"AQAB\",\"n\":\"5RnVQ2VT79TaW_Louj5ib7_dVJ1vX5ebaVeifBjNDlUp3KsrHm5sq1KWzPVz-XE6m4GBGXnVxMc5pmN7pQcqGe2rzw_jTAOIQzjYZ2UPTvl8HSjPCf9VwJleHiy4195YgnOcAF-PVASLKNKnoHjgn4b2gXpikMnztvdTFZrQAAlEVwslbW0Z17imHQsYzDXDYVzwpxjiRl4tWretNXhJS2Bk1NZoctW5kY6otkeMZ8VLpCUfbBzrhhLh5b_7Q0JKQjGX94f8j5tpVz_CXkpwQUXyymfBH9B-FY5s7LDZRKCEneSnCwSFce_nVzPqcO5J4SwsVF6FhwVQMvCC0QmNGw\",\"kty\":\"RSA\",\"kid\":\"0pWEDfNcRM4-Lnqq6QDkmVzElFEdYE96gJff6yesi0A\"},{\"e\":\"AQAB\",\"n\":\"3ANc8Uhup5_tnZfJuR4jQIwzobzEegcPGySt_EVzdF8ft2L4RoOE8wWq2fff9tRtrzNcKjSTgpw6cDMXSEa2Mx07FUvuyvjXSzlUG_fEPGIhyEJXqD5NZ89CrgHy55kizSuvgxcpQLkvSddBXVYnccWRGXfCurj7BkY1ycxvm55LAkPkaEtSWmnX8gWX6289SeKx-3rD0Xl20lhoe0_f4nChWibn-2egKBfrq-d1nXnsyxOcDhOZHS9nC4N4UeiZyQ6ervyGDg1fxzi98gxe4qb14J3vogX3KUdyG0YuC4D1SgUtEnmrVbbQl9y3fYBKZy7ysk48j9CdWjA9KYoWUQ\",\"kty\":\"RSA\",\"kid\":\"0pWEDfNcRM4-Lnqq6QDkmVzElFEdYE96gJff6yesi0A\"}]}");
        });

    let issuer = "https://op.example.com".to_string();
    let jwks_uri = "https://op.example.com/jwks".to_string();

    let metadata = IssuerMetadata {
        issuer,
        jwks_uri: Some(jwks_uri),
        ..IssuerMetadata::default()
    };

    let mut issuer = Issuer::new(
        metadata,
        get_default_test_interceptor(Some(mock_http_server.port())),
    );

    let query = QueryKeyStore {
        alg: Some("RS256".to_string()),
        key_use: Some("sig".to_string()),
        key_id: Some("0pWEDfNcRM4-Lnqq6QDkmVzElFEdYE96gJff6yesi0A".to_string()),
        key_type: None,
    };

    let jwk_result = issuer.query_keystore_async(query, false).await;

    assert!(jwk_result.is_ok());

    let matched_jwks = jwk_result.unwrap();

    assert!(matched_jwks.len() > 1);
}

#[cfg(test)]
mod http_options {

    use crate::tests::test_interceptors::TestInterceptor;

    use super::*;

    #[tokio::test]
    async fn allows_for_http_options_to_be_defined_for_issuer_keystore_calls() {
        let mock_http_server = MockServer::start();

        let issuer = "https://op.example.com".to_string();
        let jwks_uri = "https://op.example.com/jwks".to_string();

        let jwks_mock_server = mock_http_server.mock(|when, then| {
            when.method(GET)
                .header("testHeader", "testHeaderValue")
                .path("/jwks");

            then.status(200)
                .header("content-type", "application/jwk-set+json")
                .body(get_default_jwks());
        });

        let _ = Issuer::discover_async(
            "https://op.example.com/.well-known/custom-configuration",
            Some(Box::new(TestInterceptor {
                test_header: Some("testHeader".to_string()),
                test_header_value: Some("testHeaderValue".to_string()),
                test_server_port: Some(mock_http_server.port()),
                crt: None,
                key: None,
                pfx: None,
            })),
        )
        .await;

        let metadata = IssuerMetadata {
            issuer,
            jwks_uri: Some(jwks_uri),
            ..IssuerMetadata::default()
        };

        let issuer = Issuer::new(
            metadata,
            Some(Box::new(TestInterceptor {
                test_header: Some("testHeader".to_string()),
                test_header_value: Some("testHeaderValue".to_string()),
                test_server_port: Some(mock_http_server.port()),
                crt: None,
                key: None,
                pfx: None,
            })),
        );

        let _ = issuer.keystore.unwrap().get_keystore_async(false).await;

        jwks_mock_server.assert_hits(1);
    }
}
