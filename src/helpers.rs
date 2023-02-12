use json::JsonValue;
use reqwest::Url;

use crate::errors::OidcClientError;

pub fn json_value_to_vec_string(val: &JsonValue) -> Option<Vec<String>> {
    let mut vec_string = Vec::<String>::new();

    return match val {
        JsonValue::Array(vec_json_value) => {
            for item in vec_json_value {
                if item.is_string() {
                    vec_string.push(item.to_string())
                }
            }
            Some(vec_string)
        }
        _ => None,
    };
}

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
