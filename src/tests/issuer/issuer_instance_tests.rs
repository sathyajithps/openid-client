use crate::tests::test_interceptors::get_default_test_interceptor;
use crate::{issuer::Issuer, types::IssuerMetadata};
use httpmock::Method::GET;
use httpmock::MockServer;

fn get_default_jwks() -> String {
    "{\"keys\":[{\"e\":\"AQAB\",\"n\":\"zwGRh6jBiyfwbSz_gs71ehiLLuVNd5Cyb67wKVPaS6GFyHtPjD5r-Yta5aZ7OaZV1AB7ieuhvvKsjvx4pzBAnQzwyYcaFDdb91jVHad019LMkjO_UTwSHegV_Bcwrhi0g64tfW3bTNUMEEKLZEusJZElpLi9HLZsGRJUlRCYRTqMeq1SYjQunVF9GmTTJlgK7IIdMYJ6ktQNRkQFz9ACpTZCS6SCUCjA4psFz-vtW-pBOvwO1gu4hWFQx9IFmPIojyZhF5kgfVlOnAc0YTRgj03uEMYXwLpBlbC-SPM9YXmFq1iflRbxEZqEP170J_27HjYpvo8eK2YwL9jXxNLC4Q\",\"kty\":\"RSA\",\"kid\":\"RraeLjB4KnAKQaihCOLHPByOJaSjXc0iWkhq2b3I7-o\"}]}".to_string()
}

#[test]
fn requires_jwks_uri_to_be_configured() {
    let mut issuer = Issuer::new(IssuerMetadata::default(), None);

    assert!(issuer.get_keystore(false).is_err());
    assert_eq!(
        "jwks_uri must be configured on the issuer".to_string(),
        issuer
            .get_keystore(false)
            .unwrap_err()
            .type_error()
            .error
            .message,
    );

    let async_runtime = tokio::runtime::Runtime::new().unwrap();
    async_runtime.block_on(async {
        assert!(issuer.get_keystore_async(false).await.is_err());
        assert_eq!(
            "jwks_uri must be configured on the issuer".to_string(),
            issuer
                .get_keystore_async(false)
                .await
                .unwrap_err()
                .type_error()
                .error
                .message,
        );
    });
}

#[test]
fn does_not_refetch_immediately() {
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

    let mut issuer = Issuer::new(
        metadata,
        get_default_test_interceptor(mock_http_server.port()),
    );

    assert!(issuer.get_keystore(true).is_ok());

    let _ = issuer.get_keystore(false).unwrap();

    jwks_mock_server.assert_hits(1);
}

#[test]
fn does_not_refetch_immediately_async() {
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

    let mut issuer = Issuer::new(
        metadata,
        get_default_test_interceptor(mock_http_server.port()),
    );

    let async_runtime = tokio::runtime::Runtime::new().unwrap();
    async_runtime.block_on(async {
        assert!(issuer.get_keystore_async(true).await.is_ok());

        let _ = issuer.get_keystore_async(false).await.unwrap();
    });

    jwks_mock_server.assert_hits(1);
}

#[test]
fn refetches_if_asked_to() {
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

    let mut issuer = Issuer::new(
        metadata,
        get_default_test_interceptor(mock_http_server.port()),
    );

    assert!(issuer.get_keystore(true).is_ok());
    assert!(issuer.get_keystore(true).is_ok());

    jwks_mock_server.assert_hits(2);
}

#[test]
fn refetches_if_asked_to_async() {
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

    let mut issuer = Issuer::new(
        metadata,
        get_default_test_interceptor(mock_http_server.port()),
    );

    let async_runtime = tokio::runtime::Runtime::new().unwrap();
    async_runtime.block_on(async {
        assert!(issuer.get_keystore_async(true).await.is_ok());
        assert!(issuer.get_keystore_async(true).await.is_ok());
    });

    jwks_mock_server.assert_hits(2);
}

#[test]
fn rejects_when_no_matching_key_is_found() {
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
        get_default_test_interceptor(mock_http_server.port()),
    );

    let jwk_result = issuer.get_jwk(
        Some("RS256".to_string()),
        Some("sig".to_string()),
        Some("noway".to_string()),
    );

    let expected_error = "no valid key found in issuer\'s jwks_uri for key parameters kid: noway, alg: RS256, key_use: sig";

    assert!(jwk_result.is_err());

    let error = jwk_result.unwrap_err();

    assert_eq!(expected_error, error.error().error.message);

    let async_runtime = tokio::runtime::Runtime::new().unwrap();
    async_runtime.block_on(async {
        let jwk_result_async = issuer
            .get_jwk_async(
                Some("RS256".to_string()),
                Some("sig".to_string()),
                Some("noway".to_string()),
            )
            .await;

        assert!(jwk_result_async.is_err());

        let error_async = jwk_result_async.unwrap_err();

        assert_eq!(expected_error, error_async.error().error.message);
    });
}

#[test]
fn requires_a_kid_when_multiple_matches_are_found() {
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
        get_default_test_interceptor(mock_http_server.port()),
    );

    let jwk_result = issuer.get_jwk(Some("RS256".to_string()), Some("sig".to_string()), None);

    let expected_error = "multiple matching keys found in issuer\'s jwks_uri for key parameters kid: , key_use: sig, alg: RS256, kid must be provided in this case";

    assert!(jwk_result.is_err());

    let error = jwk_result.unwrap_err();

    assert_eq!(expected_error, error.error().error.message);

    let async_runtime = tokio::runtime::Runtime::new().unwrap();
    async_runtime.block_on(async {
        let jwk_result_async = issuer
            .get_jwk_async(Some("RS256".to_string()), Some("sig".to_string()), None)
            .await;

        assert!(jwk_result_async.is_err());

        let error_async = jwk_result_async.unwrap_err();

        assert_eq!(expected_error, error_async.error().error.message);
    });
}

#[test]
fn multiple_keys_can_match_jwt_header() {
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
        get_default_test_interceptor(mock_http_server.port()),
    );

    let jwk_result = issuer.get_jwk(
        Some("RS256".to_string()),
        Some("sig".to_string()),
        Some("0pWEDfNcRM4-Lnqq6QDkmVzElFEdYE96gJff6yesi0A".to_string()),
    );

    assert!(jwk_result.is_ok());

    let matched_jwks = jwk_result.unwrap();

    assert!(matched_jwks.len() > 1);

    let async_runtime = tokio::runtime::Runtime::new().unwrap();
    async_runtime.block_on(async {
        let jwk_result_async = issuer
            .get_jwk_async(
                Some("RS256".to_string()),
                Some("sig".to_string()),
                Some("0pWEDfNcRM4-Lnqq6QDkmVzElFEdYE96gJff6yesi0A".to_string()),
            )
            .await;

        assert!(jwk_result_async.is_ok());

        let matched_jwks_async = jwk_result_async.unwrap();

        assert!(matched_jwks_async.len() > 1);
    });
}

#[cfg(test)]
mod http_options {

    use crate::tests::test_interceptors::TestInterceptor;

    use super::*;

    #[test]
    fn allows_for_http_options_to_be_defined_for_issuer_keystore_calls() {
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

        let _ = Issuer::discover(
            "https://op.example.com/.well-known/custom-configuration",
            Some(Box::new(TestInterceptor {
                test_header: Some("testHeader".to_string()),
                test_header_value: Some("testHeaderValue".to_string()),
                test_server_port: Some(mock_http_server.port()),
            })),
        );

        let metadata = IssuerMetadata {
            issuer,
            jwks_uri: Some(jwks_uri),
            ..IssuerMetadata::default()
        };

        let mut issuer = Issuer::new(
            metadata,
            Some(Box::new(TestInterceptor {
                test_header: Some("testHeader".to_string()),
                test_header_value: Some("testHeaderValue".to_string()),
                test_server_port: Some(mock_http_server.port()),
            })),
        );

        let _ = issuer.get_keystore(false);

        jwks_mock_server.assert_hits(1);
    }

    #[test]
    fn allows_for_http_options_to_be_defined_for_issuer_keystore_calls_async() {
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

        let _ = Issuer::discover(
            "https://op.example.com/.well-known/custom-configuration",
            Some(Box::new(TestInterceptor {
                test_header: Some("testHeader".to_string()),
                test_header_value: Some("testHeaderValue".to_string()),
                test_server_port: Some(mock_http_server.port()),
            })),
        );

        let metadata = IssuerMetadata {
            issuer,
            jwks_uri: Some(jwks_uri),
            ..IssuerMetadata::default()
        };

        let mut issuer = Issuer::new(
            metadata,
            Some(Box::new(TestInterceptor {
                test_header: Some("testHeader".to_string()),
                test_header_value: Some("testHeaderValue".to_string()),
                test_server_port: Some(mock_http_server.port()),
            })),
        );

        let async_runtime = tokio::runtime::Runtime::new().unwrap();

        async_runtime.block_on(async {
            let _ = issuer.get_keystore_async(false).await;
            jwks_mock_server.assert_hits(1);
        });
    }
}
