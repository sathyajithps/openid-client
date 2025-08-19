use serde_json::{json, Map, Number, Value};
use std::{cell::RefCell, collections::HashMap};
use url::Url;

use crate::{
    defaults::Crypto,
    errors::{OidcReturn, OpenIdError},
    helpers::{base64_url_encode, generate_random, unix_timestamp},
    jwk::{Jwk, JwkType},
    types::{
        http_client::{HttpMethod, HttpRequest, HttpResponse},
        DpopSigningAlg, Header, OpenIdCrypto, Payload,
    },
};

/// DPoP Options
#[derive(Debug, Clone)]
pub struct DPoPOptions {
    /// DPoP signing key
    pub key: Jwk,
    /// Signing algorithm. Defaults to RS256.
    pub algorithm: DpopSigningAlg,
    /// Stores dpop nonces from server
    pub nonce_cache: RefCell<HashMap<String, String>>,
}

impl DPoPOptions {
    /// Creates a new instance of [DPoPOptions]
    pub fn new(
        key: Jwk,
        signing_algorithm: DpopSigningAlg,
        nonce_cache: Option<HashMap<String, String>>,
    ) -> Self {
        DPoPOptions {
            key,
            algorithm: signing_algorithm,
            nonce_cache: RefCell::new(nonce_cache.unwrap_or_default()),
        }
    }
}

impl DPoPOptions {
    /// Generates a DPoP header from the request and access token
    pub fn generate_dpop_header(
        &self,
        req: &mut HttpRequest,
        access_token: Option<&str>,
        supported_dpop_algorithms: Option<&Vec<DpopSigningAlg>>,
        clock_skew: i32,
    ) -> OidcReturn<()> {
        if !self.key.is_valid_private_key() || self.key.key_type() == JwkType::Oct {
            return Err(OpenIdError::new_error(
                "DPoP error: Symmetric key or Invalid private key",
            ));
        }

        if let Some(supported) = supported_dpop_algorithms {
            if !supported.contains(&self.algorithm) {
                return Err(OpenIdError::new_error(format!(
                    "Unsupported DPoP algorithm. Supported algorithms are {:?}",
                    supported
                )));
            }
        }

        let htu = DPoPOptions::dpop_htu(&req.url);

        let nonce_key = DPoPOptions::dpop_origin(&req.url);

        let htm = match req.method {
            HttpMethod::GET => "GET",
            HttpMethod::POST => "POST",
            HttpMethod::PUT => "PUT",
            HttpMethod::PATCH => "PATCH",
            HttpMethod::DELETE => "DELETE",
            HttpMethod::HEAD => "HEAD",
            HttpMethod::OPTIONS => "OPTIONS",
            HttpMethod::TRACE => "TRACE",
            HttpMethod::CONNECT => "CONNECT",
        };

        let mut payload = Payload { params: Map::new() };

        payload
            .params
            .insert("htm".to_owned(), Value::String(htm.to_owned()));

        if let Some(nonce) = (self.nonce_cache.borrow()).get(&nonce_key) {
            payload
                .params
                .insert("nonce".to_owned(), Value::String(nonce.to_owned()));
        }

        payload.params.insert("htu".to_owned(), Value::String(htu));

        if let Some(at) = access_token {
            let ath = base64_url_encode(&<sha2::Sha256 as sha2::Digest>::digest(at)[..]);
            payload.params.insert("ath".to_string(), Value::String(ath));
        }

        payload
            .params
            .insert("jti".to_owned(), Value::String(generate_random(None)));

        let now = unix_timestamp();

        let iat = now.checked_add_signed(clock_skew as i64).unwrap_or(now);

        payload
            .params
            .insert("iat".to_owned(), Value::Number(Number::from(iat)));

        let mut header = Header { params: Map::new() };

        header
            .params
            .insert("alg".to_owned(), json!(self.algorithm));

        header
            .params
            .insert("typ".to_owned(), Value::String("dpop+jwt".to_owned()));

        let public_jwk = self
            .key
            .extract_public_key_jwk()
            .ok_or(OpenIdError::new_error(
                "DPoP Key does not have a valid public part".to_owned(),
            ))?;

        header
            .params
            .insert("jwk".to_owned(), Value::Object(public_jwk.params));

        let dpop = Crypto
            .jws_serialize(payload, header, &self.key)
            .map_err(OpenIdError::new_error)?;

        req.headers.insert("DPoP".to_owned(), vec![dpop]);

        Ok(())
    }

    /// Extracts the DPoP nonce from the response if present
    pub fn extract_server_dpop_nonce(&self, request_url: &Url, res: &HttpResponse) {
        if let Some(dpop_nonce) = res.dpop_nonce_header() {
            (*self.nonce_cache.borrow_mut())
                .insert(DPoPOptions::dpop_origin(request_url), dpop_nonce.to_owned());
        }
    }

    /// Clears the DPoP nonce cache
    pub fn clear_nonce(&self) {
        (*self.nonce_cache.borrow_mut()).clear();
    }

    /// Get the DPoP `htu` claim value
    pub fn dpop_htu(url: &Url) -> String {
        url.origin().ascii_serialization() + url.path()
    }

    fn dpop_origin(url: &Url) -> String {
        url.origin().ascii_serialization()
    }
}
