use base64::{engine::general_purpose, Engine};
use rand::random;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use url::form_urlencoded;

use crate::{
    errors::{OidcReturn, OpenIdError},
    types::Pkce,
};

/// Converts a map to form url encoded string
pub fn map_to_url_encoded(map: &HashMap<String, String>) -> String {
    let mut form_urlencoded = form_urlencoded::Serializer::new(String::new());
    for (k, v) in map {
        form_urlencoded.append_pair(k, v);
    }

    form_urlencoded.finish()
}

/// Converts a form url encoded string to map
pub fn url_decode(form_string: &str) -> HashMap<String, String> {
    form_urlencoded::parse(form_string.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// Converts string into form encoded string
pub fn url_encoded(bytes: &[u8]) -> String {
    form_urlencoded::byte_serialize(bytes).collect()
}

/// Converts plain JSON to a struct/enum that impl's serde's [Deserialize]. Uses [serde_json::from_str] under
/// the hood
pub fn deserialize<T: for<'a> Deserialize<'a>>(plain: &str) -> Result<T, String> {
    if let Ok(r) = serde_json::from_str::<T>(plain) {
        return Ok(r);
    }

    Err("Parse Error".to_string())
}

/// Generates a random string using [rand::thread_rng]. You can pass in the bytes to generates
pub fn generate_random(bytes_to_generate: Option<u32>) -> String {
    let mut random_bytes = vec![];

    for _ in 0..bytes_to_generate.unwrap_or(32) {
        random_bytes.push(random());
    }

    base64_url::encode(&random_bytes)
}

/// Generate PKCE verifier and challenge
pub fn generate_pkce() -> Pkce {
    let verifier = generate_random(None);

    let mut hasher = Sha256::new();

    hasher.update(&verifier);

    Pkce {
        verifier,
        challenge: base64_url::encode(&hasher.finalize().to_vec()),
    }
}

/// Gets current timestamp
pub fn unix_timestamp() -> u64 {
    let start = std::time::SystemTime::now();
    start
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

/// Converts a string to b64
pub fn base64_encode(s: impl AsRef<[u8]>) -> String {
    general_purpose::STANDARD.encode(s)
}

/// Converts a string to b64url
pub fn base64_url_encode(s: impl AsRef<[u8]>) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(s)
}

/// Decodes a base64url string into UTF-8 text
pub fn base64_url_decode(s: impl AsRef<str>) -> OidcReturn<String> {
    let bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(s.as_ref())
        .map_err(|e| OpenIdError::new_error(e.to_string()))?;
    String::from_utf8(bytes).map_err(|e| OpenIdError::new_error(e.to_string()))
}

/// Normalize webfinger resource
pub fn webfinger_normalize(input: &str) -> String {
    let output: String;

    if private::has_scheme(input) {
        output = input.to_string();
    } else if private::acct_scheme_assumed(input) {
        output = "acct:".to_string() + input;
    } else {
        output = "https://".to_string() + input;
    }

    output.split('#').next().unwrap().to_string()
}

/// Private helpers
mod private {
    pub fn has_scheme(input: &str) -> bool {
        if input.contains("://") {
            return true;
        }

        if let Some(authority) = input
            .replace("/", "#")
            .replace("?", "#")
            .split('#')
            .next()
            .map(|a| a.to_string())
        {
            if let Some(index) = authority.find(':') {
                let host_or_port = &authority[index + 1..];
                if !host_or_port.chars().all(char::is_numeric) {
                    return true;
                }
            }
        }

        false
    }

    pub fn acct_scheme_assumed(input: &str) -> bool {
        if !input.contains('@') {
            return false;
        }

        let parts: Vec<&str> = input.split('@').collect();
        let host = parts[parts.len() - 1];
        !(host.contains(':') || host.contains('/') || host.contains('?'))
    }
}
