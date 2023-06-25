use crate::{
    helpers::{convert_json_to, parse_www_authenticate_error},
    tests::process_url,
    types::{
        OidcClientError, Request, RequestInterceptor, RequestOptions, Response, StandardBodyError,
    },
};
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::Value;
use std::time::Duration;

pub fn request(
    request: Request,
    interceptor: &mut RequestInterceptor,
) -> Result<Response, OidcClientError> {
    let (options, url) = pre_request(&request, interceptor);

    let client = reqwest::blocking::Client::new();
    let mut req = client
        .request(request.method.clone(), url)
        .headers(combine_and_create_new_header_map(
            &request.headers,
            &options.headers,
        ))
        .query(&request.get_reqwest_query())
        .timeout(options.timeout);

    if let Some(json_body) = &request.json {
        match serde_json::to_string(json_body) {
            Ok(serialized) => req = req.body(serialized),
            _ => {
                return Err(OidcClientError::new(
                    "SerializeError",
                    "invalid json",
                    "error while serializing body to string",
                    None,
                ))
            }
        }
    }

    let response = match req.send() {
        Ok(res) => Response::from(res),
        _ => return Err(request_send_error()),
    };

    process_response(response, &request)
}

pub async fn request_async(
    request: Request,
    interceptor: &mut RequestInterceptor,
) -> Result<Response, OidcClientError> {
    let (options, url) = pre_request(&request, interceptor);

    let client = reqwest::Client::new();
    let mut req = client
        .request(request.method.clone(), url)
        .headers(combine_and_create_new_header_map(
            &request.headers,
            &options.headers,
        ))
        .query(&request.get_reqwest_query())
        .timeout(options.timeout);

    if let Some(json_body) = &request.json {
        match serde_json::to_string(json_body) {
            Ok(serialized) => req = req.body(serialized),
            _ => {
                return Err(OidcClientError::new(
                    "SerializeError",
                    "invalid json",
                    "error while serializing body to string",
                    None,
                ))
            }
        }
    }

    let response = match req.send().await {
        Ok(res) => Response::from_async(res).await,
        _ => return Err(request_send_error()),
    };

    process_response(response, &request)
}

pub fn default_request_interceptor(_request: &Request) -> RequestOptions {
    let mut headers = HeaderMap::new();
    headers.append(
        "User-Agent",
        HeaderValue::from_static("openid-client/0.0.0"),
    );
    RequestOptions {
        headers,
        timeout: Duration::from_millis(3500),
    }
}

fn pre_request(
    request: &Request,
    request_options: &mut Box<dyn FnMut(&Request) -> RequestOptions>,
) -> (RequestOptions, String) {
    let options = request_options(request);

    let url = process_url(&request.url);
    (options, url)
}

fn process_response(response: Response, request: &Request) -> Result<Response, OidcClientError> {
    let mut res = return_error_if_not_expected_status(response, request)?;

    res = return_error_if_expected_body_is_absent(res, request)?;

    if let Some(response_type) = &request.response_type {
        if response_type != "json" {
            return Ok(res);
        }
    }

    let mut invalid_json = false;

    if let Some(body) = &res.body {
        let val: Result<Value, _> = convert_json_to(body);
        invalid_json = val.is_err();
    }

    res = return_error_if_json_is_invalid(invalid_json, res, request)?;
    Ok(res)
}

#[inline]
fn combine_and_create_new_header_map(one: &HeaderMap, two: &HeaderMap) -> HeaderMap {
    let mut new_headers = HeaderMap::new();
    one.iter()
        .chain(two.iter())
        .for_each(|(header_name, header_values)| {
            new_headers.append(header_name, header_values.into());
        });

    new_headers
}

#[inline]
fn request_send_error() -> OidcClientError {
    OidcClientError::new(
        "OPError",
        "unknown_error",
        "error while sending the request",
        None,
    )
}

#[inline]
fn return_error_if_not_expected_status(
    response: Response,
    request: &Request,
) -> Result<Response, OidcClientError> {
    if response.status != request.expected {
        if let Some(body) = &response.body {
            let standard_body_error_result: Result<StandardBodyError, _> = convert_json_to(body);
            if let Ok(standard_body_error) = standard_body_error_result {
                return Err(OidcClientError::new(
                    "OPError",
                    &standard_body_error.error,
                    &standard_body_error.error_description,
                    Some(response),
                ));
            } else if let Some(header_value) = response.headers.get("www-authenticate") {
                if request.bearer {
                    parse_www_authenticate_error(header_value, &response)?;
                }
            }
        }

        return Err(OidcClientError::new(
            "OPError",
            "server_error",
            &format!("expected {}, got: {}", request.expected, response.status),
            Some(response),
        ));
    }
    Ok(response)
}

#[inline]
fn return_error_if_expected_body_is_absent(
    response: Response,
    request: &Request,
) -> Result<Response, OidcClientError> {
    if request.expect_body && response.body.is_none() {
        return Err(OidcClientError::new(
            "OPError",
            "server_error",
            &format!(
                "expected {} with body but no body was returned",
                request.expected
            ),
            Some(response),
        ));
    }
    Ok(response)
}

#[inline]
fn return_error_if_json_is_invalid(
    invalid_json: bool,
    response: Response,
    request: &Request,
) -> Result<Response, OidcClientError> {
    if request.expect_body && invalid_json {
        return Err(OidcClientError::new(
            "TypeError",
            "parse_error",
            "unexpected body type",
            Some(response),
        ));
    }
    Ok(response)
}
