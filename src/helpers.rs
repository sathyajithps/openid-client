use std::time::{SystemTime, UNIX_EPOCH};

use josekit::{jws::JwsHeader, jwt::JwtPayload};
use jwt_compact::jwk::JsonWebKey;
use lazy_static::lazy_static;
use rand::Rng;
use regex::Regex;
use reqwest::{header::HeaderValue, Url};
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256, Sha384, Sha512};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::types::{DecodedToken, OidcClientError, Response, StandardBodyError};

lazy_static! {
    static ref SCHEME_REGEX: Regex = Regex::new(r"/(/|\\?)/g").unwrap();
    static ref WWW_REGEX: Regex = Regex::new(r#"(\w+)=("[^"]*")"#).unwrap();
}

pub(crate) fn validate_url(url: &str) -> Result<Url, OidcClientError> {
    let url_result = Url::parse(url);
    if url_result.is_err() {
        return Err(OidcClientError::new_type_error(
            "only valid absolute URLs can be requested",
            None,
        ));
    }
    Ok(url_result.unwrap())
}

pub(crate) fn convert_json_to<T: for<'a> Deserialize<'a>>(plain: &str) -> Result<T, String> {
    let result: Result<T, _> = serde_json::from_str(plain);
    if result.is_err() {
        return Err("Parse Error".to_string());
    }

    Ok(result.unwrap())
}

fn has_scheme(input: &str) -> bool {
    if input.contains("://") {
        return true;
    }

    let replaced_result = SCHEME_REGEX.replace(input, "#");

    let mut authority = match replaced_result {
        std::borrow::Cow::Borrowed(b) => b.to_string(),
        std::borrow::Cow::Owned(o) => o,
    };

    authority = authority.split('#').next().unwrap().to_string();

    if let Some(index) = authority.find(':') {
        let host_or_port = &authority[index + 1..];
        if !host_or_port.chars().all(char::is_numeric) {
            return true;
        }
    }

    false
}

fn acct_scheme_assumed(input: &str) -> bool {
    if !input.contains('@') {
        return false;
    }

    let parts: Vec<&str> = input.split('@').collect();
    let host = parts[parts.len() - 1];
    !(host.contains(':') || host.contains('/') || host.contains('?'))
}

pub(crate) fn webfinger_normalize(input: &str) -> String {
    let output: String;

    if has_scheme(input) {
        output = input.to_string();
    } else if acct_scheme_assumed(input) {
        output = "acct:".to_string() + input;
    } else {
        output = "https://".to_string() + input;
    }

    output.split('#').next().unwrap().to_string()
}

pub(crate) fn parse_www_authenticate_error(
    header_value: &HeaderValue,
    response: &Response,
) -> Result<(), OidcClientError> {
    if let Ok(header_value_str) = header_value.to_str() {
        let mut oidc_error = StandardBodyError {
            error: "".to_string(),
            error_description: None,
            error_uri: None,
            scope: None,
            state: None,
        };

        for capture in WWW_REGEX.captures_iter(header_value_str) {
            if let Some(key_match) = capture.get(1) {
                let key_str = key_match.as_str();
                if let Some(value_match) = capture.get(2) {
                    let value_str = value_match.as_str();
                    let split_value: Vec<&str> = value_str.split('"').collect();
                    let value = split_value[1];
                    if key_str == "error" {
                        oidc_error.error = value.to_string();
                    }

                    if key_str == "error_description" {
                        oidc_error.error_description = Some(value.to_string());
                    }
                }
            }
        }

        if oidc_error.error.is_empty() {
            return Err(OidcClientError::new_error(
                "www authenticate error",
                Some(response.clone()),
            ));
        }

        return Err(OidcClientError::OPError(oidc_error, Some(response.clone())));
    }

    Ok(())
}

pub(crate) fn now() -> i64 {
    let start = SystemTime::now();
    start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as i64
}

pub(crate) fn random() -> String {
    let bytes = rand::thread_rng().gen::<[u8; 32]>();
    base64_url::encode(&bytes)
}

pub(crate) fn decode_jwt(token: &str) -> Result<DecodedToken, OidcClientError> {
    let split_token: Vec<&str> = token.split('.').collect();

    if split_token.len() == 5 {
        return Err(OidcClientError::new_type_error(
            "encrypted JWTs cannot be decoded",
            None,
        ));
    }

    if split_token.len() != 3 {
        return Err(OidcClientError::new_error(
            "JWTs must have three components",
            None,
        ));
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

pub(crate) fn get_jwk_thumbprint_s256(jwk_str: &str) -> Result<String, OidcClientError> {
    let jwk: JsonWebKey<'_> = serde_json::from_str(jwk_str)
        .map_err(|_| OidcClientError::new_error("Invalid JWK", None))?;

    Ok(base64_url::encode(&jwk.thumbprint::<Sha256>().to_vec()))
}

fn get_hash(alg: &str, token: &str, curve: Option<&str>) -> Result<Vec<u8>, OidcClientError> {
    match alg {
        "HS256" | "RS256" | "PS256" | "ES256" | "ES256K" => Ok(Sha256::digest(token)[..].to_vec()),
        "HS384" | "RS384" | "PS384" | "ES384" => Ok(Sha384::digest(token)[..].to_vec()),
        "HS512" | "RS512" | "PS512" | "ES512" => Ok(Sha512::digest(token)[..].to_vec()),
        "EdDSA" => match curve {
            Some("Ed25519") => Ok(Sha512::digest(token)[..].to_vec()),
            Some("Ed448") => {
                let mut hasher = Shake256::default();
                hasher.update(token.as_bytes());
                let mut reader = hasher.finalize_xof();
                let mut hashed = [0u8; 114];
                reader.read(&mut hashed);

                Ok(hashed.to_vec())
            }
            _ => Err(OidcClientError::new_type_error(
                "unrecognized or invalid EdDSA curve provided",
                None,
            )),
        },
        _ => Err(OidcClientError::new_type_error(
            "unrecognized or invalid JWS algorithm provided",
            None,
        )),
    }
}

fn generate_hash(alg: &str, token: &str, curve: Option<&str>) -> Result<String, OidcClientError> {
    let hash = get_hash(alg, token, curve).unwrap();

    Ok(base64_url::encode(&hash[0..hash.len() / 2]))
}

pub(crate) struct Names {
    pub claim: String,
    pub source: String,
}

pub(crate) fn validate_hash(
    name: Names,
    actual: &str,
    alg: &str,
    source: &str,
    curve: Option<&str>,
) -> Result<(), OidcClientError> {
    if name.claim.is_empty() {
        return Err(OidcClientError::new_type_error(
            "names.claim must be a non-empty string",
            None,
        ));
    }

    if name.source.is_empty() {
        return Err(OidcClientError::new_type_error(
            "names.source must be a non-empty string",
            None,
        ));
    }

    let mut expected = "".to_string();

    let msg = match generate_hash(alg, source, curve) {
        Ok(sha) => {
            expected = sha;
            format!(
                "{} mismatch, expected {}, got: {}",
                name.claim, expected, actual
            )
        }
        Err(err) => format!(
            "{} could not be validated ({})",
            name.claim,
            err.type_error().error.message
        ),
    };

    if expected != actual {
        return Err(OidcClientError::new_error(&msg, None));
    }

    Ok(())
}
