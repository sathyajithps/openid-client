use std::time::Duration;

use crate::{
    helpers::{convert_json_to, get_serde_value_as_string, parse_www_authenticate_error},
    types::{
        Lookup, OidcClientError, Request, RequestInterceptor, RequestOptions, Response,
        StandardBodyError,
    },
};
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::Value;
use url::Url;

pub async fn request_async(
    request: Request,
    interceptor: &mut Option<RequestInterceptor>,
) -> Result<Response, OidcClientError> {
    let mut url = Url::parse(&request.url).unwrap();

    let options = match interceptor {
        Some(i) => i.intercept(&request),
        None => {
            let mut headers = HeaderMap::new();
            headers.append(
                "User-Agent",
                HeaderValue::from_static(
                    "openid-client/0.0.35-dev (https://github.com/sathyajithps/openid-client)",
                ),
            );
            RequestOptions {
                headers,
                timeout: Duration::from_secs(5),
                ..Default::default()
            }
        }
    };

    let mut client_builder = reqwest::ClientBuilder::new();

    if let Some(l) = options.lookup {
        lookup_resolve(l, &mut url)?;
    }

    if options.danger_accept_invalid_certs {
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }

    let client = client_builder
        .build()
        .map_err(|_| OidcClientError::new_error("error when building reqwest client", None))?;

    let mut req = client
        .request(request.method.clone(), url)
        .query(&request.get_reqwest_query())
        .timeout(options.timeout);

    let mut headers = combine_and_create_new_header_map(&request.headers, &options.headers);

    if let Some(json_body) = &request.json {
        match serde_json::to_string(json_body) {
            Ok(serialized) => {
                headers.remove("content-type");
                headers.insert("content-type", HeaderValue::from_static("application/json"));
                headers.remove("content-length");
                // remove unwrap ?
                headers.insert(
                    "content-length",
                    HeaderValue::from_str(&serialized.as_bytes().len().to_string()).unwrap(),
                );

                req = req.body(serialized);
            }
            _ => {
                return Err(OidcClientError::new_error(
                    "error while serializing body to string",
                    None,
                ))
            }
        }
    } else if let Some(form_body) = &request.form {
        let mut form_encoded_body = String::new();
        for (k, v) in form_body {
            let v_str = get_serde_value_as_string(v)?;
            form_encoded_body += &format!(
                "{}={}&",
                urlencoding::encode(k),
                urlencoding::encode(&v_str)
            );
        }

        form_encoded_body = form_encoded_body.trim_end_matches('&').to_owned();

        headers.remove("content-type");
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );

        headers.remove("content-length");
        // remove unwrap ?
        headers.insert(
            "content-length",
            HeaderValue::from_str(&form_encoded_body.as_bytes().len().to_string()).unwrap(),
        );

        req = req.body(form_encoded_body);
    } else if let Some(body) = &request.body {
        req = req.body(body.to_owned());

        headers.remove("content-length");
        // remove unwrap ?
        headers.insert(
            "content-length",
            HeaderValue::from_str(&body.as_bytes().len().to_string()).unwrap(),
        );
    }

    req = req.headers(headers);

    let response = match req.send().await {
        Ok(res) => Response::from_async(res).await,
        _ => {
            return Err(OidcClientError::new_error(
                "error while sending the request",
                None,
            ))
        }
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

fn process_response(response: Response, request: &Request) -> Result<Response, OidcClientError> {
    let mut res = return_error_if_not_expected_status(response, request)?;

    res = return_error_if_expected_body_is_absent(res, request)?;

    if !request.expect_body_to_be_json {
        return Ok(res);
    }

    let mut invalid_json = false;

    if let Some(body) = &res.body {
        let val: Result<Value, _> = convert_json_to(body);
        invalid_json = val.is_err();
    }

    res = return_error_if_json_is_invalid(invalid_json, res, request)?;
    Ok(res)
}

fn combine_and_create_new_header_map(one: &HeaderMap, two: &HeaderMap) -> HeaderMap {
    let mut new_headers = HeaderMap::new();
    one.iter()
        .chain(two.iter())
        .for_each(|(header_name, header_values)| {
            new_headers.append(header_name, header_values.into());
        });

    new_headers
}

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

fn return_error_if_expected_body_is_absent(
    mut response: Response,
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

    if !request.expect_body {
        response.body = None;
    }

    Ok(response)
}

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
