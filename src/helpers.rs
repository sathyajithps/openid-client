use reqwest::Url;
use serde::Deserialize;

use crate::types::OidcClientError;

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

pub fn convert_json_to<T: for<'a> Deserialize<'a>>(plain: &String) -> Result<T, String> {
    let result: Result<T, _> = serde_json::from_str(plain.as_str());
    if result.is_err() {
        return Err("Parse Error".to_string());
    }

    Ok(result.unwrap())
}
