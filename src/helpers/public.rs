use std::time::{SystemTime, UNIX_EPOCH};

use josekit::{jws::JwsHeader, jwt::JwtPayload};
use jwt_compact::jwk::JsonWebKey;
use rand::Rng;
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::types::{DecodedToken, OidcClientError, OidcReturnType};

/// Gets a Unix Timestamp in seconds. Uses [`SystemTime::now`]
pub fn now() -> i64 {
    let start = SystemTime::now();
    start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as i64
}

/// Generates a random string using [rand::thread_rng]. You can pass in the bytes to generates
pub fn generate_random(bytes_to_generate: Option<u32>) -> String {
    let mut random_bytes = vec![];

    for _ in 0..bytes_to_generate.unwrap_or(32) {
        random_bytes.push(rand::thread_rng().gen());
    }

    base64_url::encode(&random_bytes)
}

/// Generates a random string as the state. Uses [generate_random] under the hood.
pub fn generate_state(bytes: Option<u32>) -> String {
    generate_random(bytes)
}

/// Generates a random string as the nonce. Uses [generate_random] under the hood.
pub fn generate_nonce(bytes: Option<u32>) -> String {
    generate_random(bytes)
}

/// Generates a random string as the code_verifier. Uses [generate_random] under the hood.
pub fn generate_code_verifier(bytes: Option<u32>) -> String {
    generate_random(bytes)
}

/// Generates the S256 PKCE code challenge for `verifier`.
pub fn code_challenge(verifier: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();

    hasher.update(verifier);

    hasher.finalize().to_vec()
}

/// Converts plain JSON to a struct/enum that impl's serde's [Deserialize]. Uses [serde_json::from_str] under
/// the hood
pub fn convert_json_to<T: for<'a> Deserialize<'a>>(plain: &str) -> Result<T, String> {
    if let Ok(r) = serde_json::from_str::<T>(plain) {
        return Ok(r);
    }

    Err("Parse Error".to_string())
}

/// Gets S256 thumbprint of a JWK JSON.
pub fn get_s256_jwk_thumbprint(jwk_str: &str) -> OidcReturnType<String> {
    let jwk: JsonWebKey<'_> = serde_json::from_str(jwk_str)
        .map_err(|_| OidcClientError::new_error("Invalid JWK", None))?;

    Ok(base64_url::encode(&jwk.thumbprint::<Sha256>().to_vec()))
}

/// Decodes a JWT without verification
pub fn decode_jwt(token: &str) -> OidcReturnType<DecodedToken> {
    let split_token: Vec<&str> = token.split('.').collect();

    if split_token.len() == 5 {
        return Err(Box::new(OidcClientError::new_type_error(
            "encrypted JWTs cannot be decoded",
            None,
        )));
    }

    if split_token.len() != 3 {
        return Err(Box::new(OidcClientError::new_error(
            "JWTs must have three components",
            None,
        )));
    }

    let map_err_decode = |_| OidcClientError::new_error("JWT is malformed", None);
    let map_err_deserialize = |_| OidcClientError::new_error("JWT is malformed", None);
    let map_err_jose = |_| OidcClientError::new_error("JWT is malformed", None);

    let header_str = base64_url::decode(split_token[0]).map_err(map_err_decode)?;
    let payload_str = base64_url::decode(split_token[1]).map_err(map_err_decode)?;
    let signature = split_token[2].to_string();

    let header = serde_json::from_slice::<Map<String, Value>>(&header_str)
        .map(JwsHeader::from_map)
        .map_err(map_err_deserialize)?
        .map_err(map_err_jose)?;

    let payload = serde_json::from_slice::<Map<String, Value>>(&payload_str)
        .map(JwtPayload::from_map)
        .map_err(map_err_deserialize)?
        .map_err(map_err_jose)?;

    Ok(DecodedToken {
        header,
        payload,
        signature,
    })
}
