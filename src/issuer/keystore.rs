use std::{collections::HashMap, fmt::Debug};

use lru_time_cache::LruCache;
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Method, StatusCode,
};

use crate::{
    helpers::{convert_json_to, now},
    http::request_async,
    jwks::Jwks,
    types::{OidcClientError, Request, RequestInterceptor},
};

pub(crate) struct KeyStore {
    jwks: Option<Jwks>,
    jwks_uri: Option<String>,
    pub(crate) cache: LruCache<u64, bool>,
    pub(crate) last_accessed: i64,
    interceptor: Option<RequestInterceptor>,
    now: fn() -> i64,
}

impl KeyStore {
    pub(crate) fn new(
        jwks_uri: Option<String>,
        interceptor: Option<RequestInterceptor>,
    ) -> KeyStore {
        Self {
            jwks: None,
            jwks_uri,
            cache: LruCache::with_capacity(100),
            last_accessed: 0,
            interceptor,
            now,
        }
    }

    pub(crate) async fn get_keystore_async(
        &mut self,
        reload: bool,
    ) -> Result<Jwks, OidcClientError> {
        let uri = match &self.jwks_uri {
            Some(u) => u,
            None => {
                return Err(OidcClientError::new_type_error(
                    "jwks_uri must be configured on the issuer",
                    None,
                ))
            }
        };

        if !reload {
            if let Some(jwks) = &self.jwks {
                return Ok(jwks.clone());
            }
        }

        let mut headers = HeaderMap::new();
        headers.insert(
            "Accept",
            HeaderValue::from_static("application/json,application/jwk-set+json"),
        );

        let req = Request {
            expect_body: true,
            expected: StatusCode::OK,
            method: Method::GET,
            url: uri.to_string(),
            headers,
            bearer: false,
            search_params: HashMap::new(),
            ..Default::default()
        };

        let res = request_async(&req, &mut self.interceptor).await?;

        let jwks_body = res.body.as_ref();
        match jwks_body {
            Some(body) => match convert_json_to::<Jwks>(body) {
                Ok(jwks) => {
                    self.jwks = Some(jwks);

                    self.last_accessed = (self.now)();

                    if let Some(jwks) = &self.jwks {
                        return Ok(jwks.clone());
                    }

                    Err(OidcClientError::new_error(
                        "Shoud not reach here KeyStore.get_keystore_async()",
                        None,
                    ))
                }
                Err(_) => Err(OidcClientError::new_op_error(
                    "invalid jwks".to_string(),
                    Some("jwks was invalid".to_string()),
                    None,
                    None,
                    None,
                    Some(res),
                )),
            },
            None => Err(OidcClientError::new_op_error(
                "body empty".to_string(),
                Some("Jwks response was empty".to_string()),
                None,
                None,
                None,
                Some(res),
            )),
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
            .field("interceptor", &self.interceptor)
            .finish()
    }
}

impl Clone for KeyStore {
    fn clone(&self) -> Self {
        let interceptor = self.interceptor.as_ref().map(|i| i.clone_box());

        Self {
            jwks: self.jwks.clone(),
            jwks_uri: self.jwks_uri.clone(),
            cache: self.cache.clone(),
            last_accessed: self.last_accessed,
            interceptor,
            now,
        }
    }
}
