//! Issuer implementation for jwks

use std::collections::HashMap;

use reqwest::{
    header::{HeaderMap, HeaderValue},
    Method, StatusCode,
};

use crate::{
    helpers::convert_json_to,
    http::{request, request_async},
    types::{Jwk, Jwks},
    Issuer, OidcClientError, Request, RequestInterceptor, Response,
};

impl Issuer {
    /// # Gets Jwks for the issuer
    /// If the jwks is empty, tries to fetch from the jwks_uri
    pub fn get_keystore(&mut self, refresh: bool) -> Result<&Jwks, OidcClientError> {
        self.jwks_uri_check()?;

        if refresh || self.keystore.is_none() {
            let keystore = fetch_jwks(
                &mut self.request_interceptor,
                self.jwks_uri.as_ref().unwrap(),
            )?;
            self.keystore = Some(keystore);
        }

        Ok(self.keystore.as_ref().unwrap())
    }

    /// # Gets Jwks for the issuer
    /// If the jwks is empty, tries to fetch from the jwks_uri
    pub async fn get_keystore_async(&mut self, refresh: bool) -> Result<&Jwks, OidcClientError> {
        self.jwks_uri_check()?;

        if refresh || self.keystore.is_none() {
            let keystore = fetch_jwks_async(
                &mut self.request_interceptor,
                self.jwks_uri.as_ref().unwrap(),
            )
            .await?;
            self.keystore = Some(keystore);
        }

        Ok(self.keystore.as_ref().unwrap())
    }

    fn jwks_uri_check(&mut self) -> Result<(), OidcClientError> {
        if self.jwks_uri.is_none() {
            return Err(OidcClientError::new(
                "TypeError",
                "jwks_uri_invalid",
                "jwks_uri must be configured on the issuer",
                None,
            ));
        }
        Ok(())
    }

    /// Gets as list of Jwk for the arguments specified
    pub fn get_jwk(
        &mut self,
        alg: Option<String>,
        key_use: Option<String>,
        kid: Option<String>,
    ) -> Result<Vec<&Jwk>, OidcClientError> {
        let key_store = self.get_keystore(false)?;
        internal_get_jwk(key_store, alg, key_use, kid)
    }

    /// Gets as list of Jwk for the arguments specified
    pub async fn get_jwk_async(
        &mut self,
        alg: Option<String>,
        key_use: Option<String>,
        kid: Option<String>,
    ) -> Result<Vec<&Jwk>, OidcClientError> {
        let key_store = self.get_keystore_async(false).await?;
        internal_get_jwk(key_store, alg, key_use, kid)
    }
}

fn internal_get_jwk(
    key_store: &Jwks,
    alg: Option<String>,
    key_use: Option<String>,
    kid: Option<String>,
) -> Result<Vec<&Jwk>, OidcClientError> {
    let matched_keys = key_store.get(alg.clone(), key_use.clone(), kid.clone())?;

    let unwrapped_kid = kid.clone().or_else(|| Some("".to_string())).unwrap();
    let unwrapped_key_use = key_use.or_else(|| Some("".to_string())).unwrap();
    let unwrapped_alg = alg.or_else(|| Some("".to_string())).unwrap();

    if matched_keys.is_empty() {
        let error_description = format!("no valid key found in issuer\'s jwks_uri for key parameters kid: {}, alg: {}, key_use: {}", unwrapped_kid, unwrapped_alg, unwrapped_key_use);
        return Err(OidcClientError::new(
            "IssuerError",
            "no matching key found",
            &error_description,
            None,
        ));
    }

    if (kid.is_none() || unwrapped_kid.is_empty()) && matched_keys.len() > 1 {
        let error_description = format!("multiple matching keys found in issuer\'s jwks_uri for key parameters kid: {}, key_use: {}, alg: {}, kid must be provided in this case", unwrapped_kid, unwrapped_key_use, unwrapped_alg);
        return Err(OidcClientError::new(
            "IssuerError",
            "multiple matching keys found",
            &error_description,
            None,
        ));
    }

    Ok(matched_keys)
}

fn fetch_jwks(interceptor: &mut RequestInterceptor, url: &str) -> Result<Jwks, OidcClientError> {
    let req = make_get_jwks_uri_request(url);

    let res = request(req, interceptor)?;
    process_jwks_response(res)
}

async fn fetch_jwks_async(
    interceptor: &mut RequestInterceptor,
    url: &str,
) -> Result<Jwks, OidcClientError> {
    let req = make_get_jwks_uri_request(url);

    let res = request_async(req, interceptor).await?;
    process_jwks_response(res)
}

fn make_get_jwks_uri_request(url: &str) -> Request {
    let mut headers = HeaderMap::new();
    headers.insert(
        "Accept",
        HeaderValue::from_static("application/json,application/jwk-set+json"),
    );

    Request {
        expect_body: true,
        expected: StatusCode::OK,
        method: Method::GET,
        url: url.to_string(),
        headers,
        bearer: false,
        search_params: HashMap::new(),
    }
}

fn process_jwks_response(res: Response) -> Result<Jwks, OidcClientError> {
    let jwks_body = res.body.as_ref();
    match jwks_body {
        Some(body) => match convert_json_to::<Jwks>(body) {
            Ok(jwks) => Ok(jwks),
            Err(_) => Err(OidcClientError::new(
                "TypeErr",
                "invalid jwks",
                "jwks was invalid",
                Some(res),
            )),
        },
        None => Err(OidcClientError::new(
            "ServerError",
            "body empty",
            "Jwks response was empty",
            Some(res),
        )),
    }
}
