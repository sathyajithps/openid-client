use crate::{
    helpers::{convert_json_to, parse_www_authenticate_error},
    types::{
        HttpRequest, HttpResponse, HttpResponseExpectations, OidcClientError, OidcHttpClient,
        OidcReturnType, StandardBodyError,
    },
};
use serde_json::Value;

pub async fn request_async<T>(
    mut request: HttpRequest,
    http_client: &T,
) -> OidcReturnType<HttpResponse>
where
    T: OidcHttpClient,
{
    if request.mtls {
        let cert = http_client.get_client_certificate(&request).await;
        if cert.is_none() {
            return Err(Box::new(OidcClientError::new_type_error(
                "mutual-TLS certificate and key not set",
                None,
            )));
        }
        request.client_certificate = cert;
    }

    let expectations = request.expectations;

    let res = http_client
        .request(request)
        .await
        .map_err(|e| OidcClientError::new_error(&e, None))?;

    process_response(res, expectations)
}

fn process_response(
    response: HttpResponse,
    expectations: HttpResponseExpectations,
) -> OidcReturnType<HttpResponse> {
    let mut res = return_error_if_not_expected_status(response, &expectations)?;

    res = return_error_if_expected_body_is_absent(res, &expectations)?;

    if !expectations.json_body {
        return Ok(res);
    }

    let mut invalid_json = false;

    if let Some(body) = &res.body {
        let val: Result<Value, _> = convert_json_to(body);
        invalid_json = val.is_err();
    }

    res = return_error_if_json_is_invalid(invalid_json, res, &expectations)?;
    Ok(res)
}

fn return_error_if_not_expected_status(
    response: HttpResponse,
    expectations: &HttpResponseExpectations,
) -> OidcReturnType<HttpResponse> {
    if response.status_code != expectations.status_code {
        if let Some(body) = &response.body {
            let standard_body_error_result: Result<StandardBodyError, _> = convert_json_to(body);
            if let Ok(sbe) = standard_body_error_result {
                return Err(Box::new(OidcClientError::new_op_error(
                    sbe.error,
                    sbe.error_description,
                    sbe.error_uri,
                    Some(response),
                )));
            }
        }

        if let Some(value) = response.www_authenticate.as_ref() {
            // check if bearer or dpop auth?
            parse_www_authenticate_error(value, &response)?;
        }

        return Err(Box::new(OidcClientError::new_op_error(
            "server_error".to_string(),
            Some(format!(
                "expected {}, got: {}",
                status_to_text(expectations.status_code),
                status_to_text(response.status_code)
            )),
            None,
            Some(response),
        )));
    }
    Ok(response)
}

fn return_error_if_expected_body_is_absent(
    mut response: HttpResponse,
    expectations: &HttpResponseExpectations,
) -> OidcReturnType<HttpResponse> {
    if expectations.body && response.body.is_none() {
        return Err(Box::new(OidcClientError::new_op_error(
            "server_error".to_string(),
            Some(format!(
                "expected {} with body but no body was returned",
                status_to_text(expectations.status_code)
            )),
            None,
            Some(response),
        )));
    }

    if !expectations.body {
        response.body = None;
    }

    Ok(response)
}

fn return_error_if_json_is_invalid(
    invalid_json: bool,
    response: HttpResponse,
    expectations: &HttpResponseExpectations,
) -> OidcReturnType<HttpResponse> {
    if expectations.body && invalid_json {
        return Err(Box::new(OidcClientError::new_type_error(
            "unexpected body type",
            Some(response),
        )));
    }
    Ok(response)
}

fn status_to_text(status: u16) -> &'static str {
    match status {
        100 => "100 Continue",
        101 => "101 Switching Protocols",
        200 => "200 OK",
        201 => "201 Created",
        202 => "202 Accepted",
        204 => "204 No Content",
        301 => "301 Moved Permanently",
        302 => "302 Found",
        307 => "307 Temporary Redirect",
        308 => "308 Permanent Redirect",
        400 => "400 Bad Request",
        401 => "401 Unauthorized",
        402 => "402 Payment Required",
        403 => "403 Forbidden",
        404 => "404 Not Found",
        405 => "405 Method Not Allowed",
        406 => "406 Not Acceptable",
        408 => "408 Request Timeout",
        409 => "409 Conflict",
        418 => "418 I'm a teapot",
        422 => "422 Unprocessable Entity",
        429 => "429 Too Many Requests",
        500 => "500 Internal Server Error",
        501 => "501 Not Implemented",
        502 => "502 Bad Gateway",
        503 => "503 Service Unavailable",
        504 => "504 Gateway Timeout",
        505 => "505 HTTP Version Not Supported",
        _ => "Unknown",
    }
}
