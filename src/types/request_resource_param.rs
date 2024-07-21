use std::collections::HashMap;

use josekit::jwk::Jwk;

use super::{HttpMethod, RequestResourceOptions};

#[derive(Default)]
/// # RequestResourceParams
pub struct RequestResourceParams<'a> {
    /// Resource server Url
    pub resource_url: &'a str,
    /// Access Token
    pub access_token: &'a str,
    /// Type of the token
    pub token_type: Option<&'a str>,
    /// Specify if the request should be retried once
    pub retry: bool,
    /// [RequestResourceOptions]
    pub options: RequestResourceOptions<'a>,
}

impl<'a> RequestResourceParams<'a> {
    /// Sets resource url
    pub fn resource_url(mut self, resource_url: &'a str) -> Self {
        self.resource_url = resource_url;
        self
    }

    /// Sets access token
    pub fn access_token(mut self, access_token: &'a str) -> Self {
        self.access_token = access_token;
        self
    }

    /// Sets token type
    pub fn token_type(mut self, token_type: &'a str) -> Self {
        self.token_type = Some(token_type);
        self
    }

    /// Sets retry
    pub fn retry(mut self, retry: bool) -> Self {
        self.retry = retry;
        self
    }

    /// Set the resource request method
    pub fn set_method(mut self, method: HttpMethod) -> Self {
        self.options.method = method;

        self
    }

    /// Append a request header. If the value does not exist, a new value will be created.
    pub fn append_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let name = name.into();
        let value = value.into();
        if let Some(header) = self.options.headers.get_mut(&name) {
            if !header.contains(&value) {
                header.push(value);
            }
        } else {
            let mut headers = HashMap::new();
            headers.insert(name, vec![value]);

            self.options.headers = headers;
        }

        self
    }

    /// Set a request header
    pub fn set_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.options.headers.insert(name.into(), vec![value.into()]);

        self
    }

    /// Remove a header with the name
    pub fn remove_header(mut self, name: &str) -> Self {
        self.options.headers.remove(name);

        self
    }

    /// Set the request body
    pub fn set_body(mut self, body: impl Into<String>) -> Self {
        self.options.body = Some(body.into());

        self
    }

    /// Set if the request should use bearer auth
    pub fn use_bearer(mut self, bearer: bool) -> Self {
        self.options.bearer = bearer;

        self
    }

    /// Expect the response body to be json
    pub fn expect_json_body(mut self, expect: bool) -> Self {
        self.options.expect_body_to_be_json = expect;

        self
    }

    /// Set the dpop key
    pub fn set_dpop_key(mut self, dpop: &'a Jwk) -> Self {
        self.options.dpop = Some(dpop);

        self
    }
}
