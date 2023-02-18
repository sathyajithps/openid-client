use crate::{
    helpers::convert_json_to,
    types::{OidcClientError, Request, RequestOptions, Response, StandardBodyError},
};
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::Value;
use std::time::Duration;

pub fn default_request_options(_request: &Request) -> RequestOptions {
    let mut headers = HeaderMap::new();
    headers.append(
        "User-Agent",
        HeaderValue::from_static("openid-client/0.1.0"),
    );
    RequestOptions {
        headers,
        timeout: Duration::from_millis(3500),
    }
}

pub fn request(
    request: Request,
    request_options: &mut Box<dyn FnMut(&Request) -> RequestOptions>,
) -> Result<Response, OidcClientError> {
    let options = request_options(&request);
    let client = reqwest::blocking::Client::new();

    let mut headers = HeaderMap::new();
    request
        .headers
        .iter()
        .for_each(|(header_name, header_values)| {
            headers.append(header_name, header_values.into());
            ()
        });
    options
        .headers
        .iter()
        .for_each(|(header_name, header_values)| {
            headers.append(header_name, header_values.into());
            ()
        });

    let res = client
        .request(request.method, request.url)
        .headers(headers)
        .timeout(options.timeout)
        .send();

    if res.is_err() {
        return Err(OidcClientError::new(
            "OPError",
            "unknown_error",
            "error while sending the request",
            None,
        ));
    }

    let response = Response::from(res.unwrap());

    if response.status != request.expected {
        if let Some(body) = &response.body {
            let standard_body_error_result: Result<StandardBodyError, _> = convert_json_to(body);
            if let Ok(standard_body_error) = standard_body_error_result {
                return Err(OidcClientError::new(
                    "OPError",
                    standard_body_error.error.as_str(),
                    standard_body_error.error_description.as_str(),
                    Some(response),
                ));
            }
        }

        return Err(OidcClientError::new(
            "OPError",
            "server_error",
            format!("expected {}, got: {}", request.expected, response.status).as_str(),
            Some(response),
        ));
    }

    if request.expect_body && response.body.is_none() {
        return Err(OidcClientError::new(
            "OPError",
            "server_error",
            format!(
                "expected {} with body but no body was returned",
                request.expected
            )
            .as_str(),
            None,
        ));
    }

    let mut invalid_json = false;

    if let Some(body) = &response.body {
        let val: Result<Value, _> = convert_json_to(body);
        invalid_json = val.is_err();
    }

    if request.expect_body && invalid_json {
        return Err(OidcClientError {
            name: "TypeError".to_string(),
            error: "parse_error".to_string(),
            error_description: "unexpected body type".to_string(),
            response: Some(response),
        });
    }

    Ok(response)
}
