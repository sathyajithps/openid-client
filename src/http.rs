use std::time::Duration;

use crate::{
    helpers::{convert_json_to, parse_www_authenticate_error},
    types::{
        Lookup, OidcClientError, Request, RequestInterceptor, RequestOptions, Response,
        StandardBodyError,
    },
};
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::Value;
use url::Url;

pub fn request(
    request: Request,
    interceptor: &mut Option<RequestInterceptor>,
) -> Result<Response, OidcClientError> {
    match (&request.json, &request.form, &request.body) {
        (None, Some(_), Some(_))
        | (Some(_), Some(_), None)
        | (Some(_), Some(_), Some(_))
        | (Some(_), None, Some(_)) => {
            return Err(OidcClientError::new_error(
                "cannot request with multiple request bodies",
                None,
            ))
        }
        _ => {}
    }

    let (mut url, options) = pre_request(&request, interceptor);

    let mut client_builder = reqwest::blocking::ClientBuilder::new();

    if let Some(l) = options.lookup {
        lookup_resolve(l, &mut url)?;
    }

    if options.danger_accept_invalid_certs {
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }

    if request.mtls
        && options.client_pkcs_12.is_none()
        && options.client_crt.is_none()
        && options.client_key.is_none()
    {
        return Err(OidcClientError::new_type_error(
            "mutual-TLS certificate and key not set",
            None,
        ));
    }

    let client = client_builder.build().map_err(client_build_error)?;

    let mut req = client
        .request(request.method.clone(), url)
        .query(&request.get_reqwest_query())
        .timeout(options.timeout);

    let mut final_headers = combine_and_create_new_header_map(&request.headers, &options.headers);

    if let Some(json_body) = &request.json {
        final_headers.insert("content-type", HeaderValue::from_static("application/json"));

        match serde_json::to_string(json_body) {
            Ok(serialized) => req = req.body(serialized),
            _ => return Err(invalid_json_body()),
        }
    }

    if let Some(form_body) = &request.form {
        final_headers.insert(
            "content-type",
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );

        let mut form_string = String::new();

        for (k, v) in form_body {
            if k.trim().is_empty() {
                continue;
            }

            if v.is_array() || v.is_object() {
                form_string += &format!("{}=&", k);
            }

            form_string += &format!("{0}={1}", k, v);
        }

        req = req.body(form_string.trim_end_matches('&').to_owned());
    }

    if let Some(body) = &request.body {
        final_headers.insert(
            "content-length",
            HeaderValue::from_bytes(format!("{}", body.len()).as_bytes()).unwrap(),
        );

        req = req.body(body.to_owned());
    }

    req = req.headers(final_headers);

    let response = match req.send() {
        Ok(res) => Response::from(res),
        _ => return Err(request_send_error()),
    };

    process_response(response, &request)
}

pub async fn request_async(
    request: Request,
    interceptor: &mut Option<RequestInterceptor>,
) -> Result<Response, OidcClientError> {
    let (mut url, options) = pre_request(&request, interceptor);

    let mut client_builder = reqwest::ClientBuilder::new();

    if let Some(l) = options.lookup {
        lookup_resolve(l, &mut url)?;
    }

    if options.danger_accept_invalid_certs {
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }

    let client = client_builder.build().map_err(client_build_error)?;

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
            _ => return Err(invalid_json_body()),
        }
    }

    let response = match req.send().await {
        Ok(res) => Response::from_async(res).await,
        _ => return Err(request_send_error()),
    };

    process_response(response, &request)
}

fn lookup_resolve(mut l: Box<dyn Lookup>, url: &mut Url) -> Result<(), OidcClientError> {
    let lookedup_url = l.lookup(url);

    if let Some(host) = lookedup_url.host_str() {
        if lookedup_url.scheme() != "https" && lookedup_url.scheme() != "http" {
            return Err(OidcClientError::new_type_error(
                "Interceptor Lookup Error: only http or https is supported as a scheme.",
                None,
            ));
        }

        url.set_scheme(lookedup_url.scheme()).map_err(|_| {
            OidcClientError::new_error("Interceptor Lookup Error: error when changing scheme", None)
        })?;

        url.set_host(Some(host)).map_err(|_| {
            OidcClientError::new_error("Interceptor Lookup Error: error when setting host", None)
        })?;

        if let Some(port) = lookedup_url.port() {
            url.set_port(Some(port)).map_err(|_| {
                OidcClientError::new_error(
                    "Interceptor Lookup Error: error when setting port",
                    None,
                )
            })?;
        }
    } else {
        return Err(OidcClientError::new_type_error(
            "Interceptor Lookup Error: no host found.",
            None,
        ));
    }

    Ok(())
}

#[inline]
fn invalid_json_body() -> OidcClientError {
    OidcClientError::new_error("error while serializing body to string", None)
}

#[inline]
fn client_build_error(_: reqwest::Error) -> OidcClientError {
    OidcClientError::new_error("error when building reqwest client", None)
}

fn pre_request(
    request: &Request,
    interceptor: &mut Option<RequestInterceptor>,
) -> (Url, RequestOptions) {
    let url = Url::parse(&request.url).unwrap();

    let options = match interceptor {
        Some(i) => i.intercept(request),
        None => {
            let mut headers = HeaderMap::new();
            headers.append(
                "User-Agent",
                HeaderValue::from_static(
                    "openid-client/0.0.18-dev (https://github.com/sathyajithps/openid-client)",
                ),
            );
            RequestOptions {
                headers,
                timeout: Duration::from_secs(5),
                ..Default::default()
            }
        }
    };
    (url, options)
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
    OidcClientError::new_error("error while sending the request", None)
}

#[inline]
fn return_error_if_not_expected_status(
    response: Response,
    request: &Request,
) -> Result<Response, OidcClientError> {
    if response.status != request.expected {
        if let Some(body) = &response.body {
            let standard_body_error_result: Result<StandardBodyError, _> = convert_json_to(body);
            if let Ok(sbe) = standard_body_error_result {
                return Err(OidcClientError::new_op_error(
                    sbe.error,
                    sbe.error_description,
                    sbe.error_uri,
                    sbe.scope,
                    sbe.state,
                    Some(response),
                ));
            } else if let Some(header_value) = response.headers.get("www-authenticate") {
                if request.bearer {
                    parse_www_authenticate_error(header_value, &response)?;
                }
            }
        }

        return Err(OidcClientError::new_op_error(
            "server_error".to_string(),
            Some(format!(
                "expected {}, got: {}",
                request.expected, response.status
            )),
            None,
            None,
            None,
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
        return Err(OidcClientError::new_op_error(
            "server_error".to_string(),
            Some(format!(
                "expected {} with body but no body was returned",
                request.expected
            )),
            None,
            None,
            None,
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
        return Err(OidcClientError::new_type_error(
            "unexpected body type",
            Some(response),
        ));
    }
    Ok(response)
}
