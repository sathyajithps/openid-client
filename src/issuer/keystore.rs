use std::{collections::HashMap, fmt::Debug};

use lru_time_cache::LruCache;
use url::Url;

use crate::{
    helpers::{convert_json_to, now},
    http::request_async,
    jwks::Jwks,
    types::{
        http_client::HttpMethod, HttpRequest, OidcClientError, OidcHttpClient, OidcReturnType,
    },
};

pub(crate) struct KeyStore {
    jwks: Option<Jwks>,
    jwks_uri: Option<String>,
    pub(crate) cache: LruCache<u64, bool>,
    pub(crate) last_accessed: u64,
    now: fn() -> u64,
}

impl KeyStore {
    pub(crate) fn new(jwks_uri: Option<String>) -> KeyStore {
        Self {
            jwks: None,
            jwks_uri,
            cache: LruCache::with_capacity(100),
            last_accessed: 0,
            now,
        }
    }

    pub(crate) async fn get_keystore_async<T>(
        &mut self,
        reload: bool,
        http_client: &T,
    ) -> OidcReturnType<Jwks>
    where
        T: OidcHttpClient,
    {
        let uri = match &self.jwks_uri {
            Some(u) => u,
            None => {
                return Err(Box::new(OidcClientError::new_type_error(
                    "jwks_uri must be configured on the issuer",
                    None,
                )))
            }
        };

        if !reload {
            if let Some(jwks) = &self.jwks {
                return Ok(jwks.clone());
            }
        }

        let mut headers = HashMap::new();
        headers.insert(
            "accept".to_string(),
            vec![
                "application/json".to_string(),
                "application/jwk-set+json".to_string(),
            ],
        );

        let req = HttpRequest::new()
            .url(Url::parse(uri).unwrap())
            .expect_body(true)
            .expect_status_code(200)
            .method(HttpMethod::GET)
            .headers(headers)
            .expect_bearer(false);

        let res = request_async(req, http_client).await?;

        let jwks_body = res.body.as_ref();
        match jwks_body {
            Some(body) => match convert_json_to::<Jwks>(body) {
                Ok(jwks) => {
                    self.jwks = Some(jwks);

                    self.last_accessed = (self.now)();

                    if let Some(jwks) = &self.jwks {
                        return Ok(jwks.clone());
                    }

                    Err(Box::new(OidcClientError::new_error(
                        "Shoud not reach here KeyStore.get_keystore_async()",
                        None,
                    )))
                }
                Err(_) => Err(Box::new(OidcClientError::new_op_error(
                    "invalid jwks".to_string(),
                    Some("jwks was invalid".to_string()),
                    None,
                    Some(res),
                ))),
            },
            None => Err(Box::new(OidcClientError::new_op_error(
                "body empty".to_string(),
                Some("Jwks response was empty".to_string()),
                None,
                Some(res),
            ))),
        }
    }
}

impl Debug for KeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyStore")
            .field("jwks", &self.jwks)
            .field("jwks_uri", &self.jwks_uri)
            .field("key_cache", &"LruCache<u64, bool>")
            .field("last_accessed", &self.last_accessed)
            .finish()
    }
}

impl Clone for KeyStore {
    fn clone(&self) -> Self {
        Self {
            jwks: self.jwks.clone(),
            jwks_uri: self.jwks_uri.clone(),
            cache: self.cache.clone(),
            last_accessed: self.last_accessed,
            now,
        }
    }
}
