use std::borrow::Cow;

use crate::{
    config::{DPoPOptions, OpenIdClientConfiguration},
    errors::{OidcReturn, OpenIdError, StandardBodyError},
    helpers::deserialize,
    types::{
        http_client::{HttpRequest, HttpResponse, HttpResponseExpectations, OidcHttpClient},
        DpopSigningAlg,
    },
};

use serde_json::Value;
use www_authenticate_parser::{CowStr, UniCase};

/// # DPoP
/// Represents the DPoP
struct DPoP<'a> {
    options: &'a DPoPOptions,
    supported_alg_values: Option<&'a Vec<DpopSigningAlg>>,
    clock_skew: i32,
}

pub(crate) struct Http<'a> {
    config: Option<&'a OpenIdClientConfiguration>,
    access_token: Option<&'a str>,
    dpop: Option<DPoP<'a>>,
    check_expectations: bool,
}

impl<'a> Default for Http<'a> {
    fn default() -> Self {
        Self {
            config: Default::default(),
            access_token: Default::default(),
            dpop: Default::default(),
            check_expectations: true,
        }
    }
}

impl<'a> Http<'a> {
    pub fn set_config(mut self, config: &'a OpenIdClientConfiguration) -> Self {
        self.config = Some(config);
        self
    }

    pub fn set_access_token(mut self, access_token: &'a str) -> Self {
        self.access_token = Some(access_token);
        self
    }

    pub fn set_check_expectations(mut self, check: bool) -> Self {
        self.check_expectations = check;
        self
    }

    pub fn set_dpop(
        mut self,
        options: &'a DPoPOptions,
        supported_alg_values: Option<&'a Vec<DpopSigningAlg>>,
        clock_skew: i32,
    ) -> Self {
        self.dpop = Some(DPoP {
            options,
            supported_alg_values,
            clock_skew,
        });
        self
    }

    pub async fn request_async<T>(
        &self,
        mut request: HttpRequest,
        http_client: &T,
    ) -> OidcReturn<HttpResponse>
    where
        T: OidcHttpClient,
    {
        if request.mtls {
            let cert = http_client.get_client_certificate(&request).await;
            if cert.is_none() {
                return Err(OpenIdError::new_error(
                    "mutual-TLS certificate and key not set",
                ));
            }
            request.client_certificate = cert;
        }

        let expectations = request.expectations;

        if let Some(dpop) = &self.dpop {
            dpop.options.generate_dpop_header(
                &mut request,
                self.access_token,
                dpop.supported_alg_values,
                dpop.clock_skew,
            )?;
        }

        let url = request.url.clone();

        request.prepare();

        let res = http_client
            .request(request)
            .await
            .map_err(|e| OpenIdError::new_error(&e))?;

        if let Some(dpop) = &self.dpop {
            dpop.options.extract_server_dpop_nonce(&url, &res);
        }

        if self.check_expectations {
            process_response(res, expectations)
        } else {
            Ok(res)
        }
    }
}

fn process_response(
    response: HttpResponse,
    expectations: HttpResponseExpectations,
) -> OidcReturn<HttpResponse> {
    let mut response = return_error_if_not_expected_status(response, &expectations)?;

    response = return_error_if_expected_body_is_absent(response, &expectations)?;

    if expectations.json {
        if let Some(body) = &response.body {
            if deserialize::<Value>(body).is_err() {
                return Err(OpenIdError::new_error("unexpected body type"));
            }
        }
    } else {
        response.body = None;
    }

    Ok(response)
}

fn return_error_if_not_expected_status(
    response: HttpResponse,
    expectations: &HttpResponseExpectations,
) -> OidcReturn<HttpResponse> {
    if response.status_code != expectations.status_code {
        if let Some(body) = &response.body {
            if let Ok(sbe) = deserialize::<StandardBodyError>(body) {
                return Err(OpenIdError::new_op_error(
                    sbe.error,
                    sbe.error_description,
                    sbe.error_uri,
                ));
            }
        }

        if expectations.bearer {
            parse_www_authenticate_error(&response)?;
        }

        return Err(OpenIdError::new_error(format!(
            "expected {}, got: {}",
            expectations.status_code, response.status_code
        )));
    }
    Ok(response)
}

fn return_error_if_expected_body_is_absent(
    mut response: HttpResponse,
    expectations: &HttpResponseExpectations,
) -> OidcReturn<HttpResponse> {
    if expectations.body && response.body.is_none() {
        return Err(OpenIdError::new_error(format!(
            "expected {} with body but no body was returned",
            status_to_text(expectations.status_code)
        )));
    }

    if !expectations.body {
        response.body = None;
    }

    Ok(response)
}

fn parse_www_authenticate_error(response: &HttpResponse) -> OidcReturn<()> {
    if let Some(errors) = response.parsed_www_authenticate_errors() {
        let oidc_error = match errors.get(&UniCase::new(CowStr(Cow::Borrowed("Bearer")))) {
            Some(oidc_challenge) => StandardBodyError {
                error: oidc_challenge
                    .error()
                    .map_or("www_authenticate_error".to_owned(), |e| e.to_owned()),
                error_description: oidc_challenge.error_description().map(ToOwned::to_owned),
                error_uri: oidc_challenge.error_uri().map(ToOwned::to_owned),
            },
            None => StandardBodyError {
                error: "www_authenticate_error".to_string(),
                error_description: None,
                error_uri: None,
            },
        };

        return Err(OpenIdError::OPError(oidc_error));
    }

    Ok(())
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
