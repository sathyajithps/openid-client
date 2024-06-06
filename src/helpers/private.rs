use std::collections::HashMap;

use lazy_static::lazy_static;
use regex::Regex;
use reqwest::Url;
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384, Sha512};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use url::form_urlencoded;

use crate::types::{HttpResponse, OidcClientError, OidcReturnType, StandardBodyError};

lazy_static! {
    static ref SCHEME_REGEX: Regex = Regex::new(r"/(/|\\?)/g").unwrap();
    static ref WWW_REGEX: Regex = Regex::new(r#"(\w+)=("[^"]*")"#).unwrap();
}

pub(crate) fn validate_url(url: &str) -> OidcReturnType<Url> {
    if let Ok(u) = Url::parse(url) {
        return Ok(u);
    }

    Err(Box::new(OidcClientError::new_type_error(
        "only valid absolute URLs can be requested",
        None,
    )))
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
    header_value: &str,
    response: &HttpResponse,
) -> OidcReturnType<()> {
    let mut oidc_error = StandardBodyError {
        error: "".to_string(),
        error_description: None,
        error_uri: None,
    };

    for capture in WWW_REGEX.captures_iter(header_value) {
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
        return Err(Box::new(OidcClientError::new_error(
            "www authenticate error",
            Some(response.clone()),
        )));
    }

    Err(Box::new(OidcClientError::OPError(
        oidc_error,
        Some(response.clone()),
    )))
}

fn get_hash(alg: &str, token: &str, curve: Option<&str>) -> OidcReturnType<Vec<u8>> {
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
            _ => Err(Box::new(OidcClientError::new_type_error(
                "unrecognized or invalid EdDSA curve provided",
                None,
            ))),
        },
        _ => Err(Box::new(OidcClientError::new_type_error(
            "unrecognized or invalid JWS algorithm provided",
            None,
        ))),
    }
}

pub(crate) fn generate_hash(alg: &str, token: &str, curve: Option<&str>) -> OidcReturnType<String> {
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
) -> OidcReturnType<()> {
    if name.claim.is_empty() {
        return Err(Box::new(OidcClientError::new_type_error(
            "names.claim must be a non-empty string",
            None,
        )));
    }

    if name.source.is_empty() {
        return Err(Box::new(OidcClientError::new_type_error(
            "names.source must be a non-empty string",
            None,
        )));
    }

    let mut expected = "".to_string();

    let msg = match generate_hash(alg, source, curve) {
        Ok(sha) => {
            expected = sha;
            format!(
                "{} mismatch, expected {expected}, got: {actual}",
                name.claim
            )
        }
        Err(err) => format!(
            "{} could not be validated ({})",
            name.claim,
            err.type_error().error.message
        ),
    };

    if expected != actual {
        return Err(Box::new(OidcClientError::new_error(&msg, None)));
    }

    Ok(())
}

pub(crate) fn get_serde_value_as_string(v: &Value) -> OidcReturnType<String> {
    match v {
        Value::Null => Ok("null".to_string()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Number(n) => Ok(n.to_string()),
        Value::String(s) => Ok(s.to_string()),
        Value::Array(a) => {
            serde_json::to_string(a)
                .ok()
                .ok_or(Box::new(OidcClientError::new_error(
                    &format!("Invalid serde array value to convert to string: {:?}", a),
                    None,
                )))
        }
        Value::Object(o) => {
            serde_json::to_string(o)
                .ok()
                .ok_or(Box::new(OidcClientError::new_error(
                    &format!("Invalid serde object value to convert to string: {:?}", o),
                    None,
                )))
        }
    }
}

pub(crate) fn string_map_to_form_url_encoded(
    map: &HashMap<String, String>,
) -> OidcReturnType<String> {
    let mut form_urlencoded = form_urlencoded::Serializer::new(String::new());
    for (k, v) in map {
        form_urlencoded.append_pair(k, v);
    }

    Ok(form_urlencoded.finish())
}

pub(crate) fn form_url_encoded_to_string_map(string: &str) -> HashMap<String, String> {
    let form_urlencoded: HashMap<String, String> = form_urlencoded::parse(string.as_bytes())
        .map(|(x, y)| (x.to_string(), y.to_string()))
        .collect();

    form_urlencoded
}
