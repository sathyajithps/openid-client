use httpmock::Regex;
use reqwest::{header::HeaderValue, Url};
use serde::Deserialize;

use crate::{types::OidcClientError, Response};

pub fn validate_url(url: &str) -> Result<Url, OidcClientError> {
    let url_result = Url::parse(url);
    if url_result.is_err() {
        return Err(OidcClientError::new(
            "TypeError",
            "invalid_url",
            "only valid absolute URLs can be requested",
            None,
        ));
    }
    Ok(url_result.unwrap())
}

pub fn convert_json_to<T: for<'a> Deserialize<'a>>(plain: &str) -> Result<T, String> {
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

    let replaced_result = Regex::new(r#"/(/|\\?)/g"#).unwrap().replace(input, "#");

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

pub fn webfinger_normalize(input: &str) -> String {
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

pub fn parse_www_authenticate_error(
    header_value: &HeaderValue,
    response: &Response,
) -> Result<(), OidcClientError> {
    if let Ok(header_value_str) = header_value.to_str() {
        let regex = Regex::new(r#"(\w+)=("[^"]*")"#).unwrap();

        let mut oidc_error = OidcClientError::new(
            "OPError",
            "authentication_error",
            "authentication_error",
            Some(response.clone()),
        );

        for capture in regex.captures_iter(header_value_str) {
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
                        oidc_error.error_description = value.to_string();
                    }
                }
            }
        }

        return Err(oidc_error);
    }

    Ok(())
}
