//! GrantParams
use std::collections::HashMap;

use josekit::jwk::Jwk;
use serde_json::Value;

use super::GrantExtras;

/// Params for grant_async method
pub struct GrantParams<'a> {
    /// HashMap<String, Value> : Request body
    pub body: HashMap<String, String>,
    /// [GrantExtras] : Parameters for customizing auth request
    pub extras: GrantExtras<'a>,
    /// Will retry exactly once if true.
    pub retry: bool,
}

impl Default for GrantParams<'_> {
    fn default() -> Self {
        Self {
            body: HashMap::new(),
            extras: Default::default(),
            retry: true,
        }
    }
}

impl<'a> GrantParams<'a> {
    /// Adds a key-value to the body of the grant
    pub fn add_body_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.body.insert(key.into(), value.into());
        self
    }

    /// Sets the grant type of the grant
    ///
    /// example:
    ///     - authorization_code
    ///     - client_credentials
    pub fn set_grant_type(mut self, value: impl Into<String>) -> Self {
        self.body.insert("grant_type".to_string(), value.into());
        self
    }

    /// Space separated scopes for the grant
    pub fn set_scopes(mut self, value: impl Into<String>) -> Self {
        self.body.insert("scope".to_string(), value.into());
        self
    }

    /// Sets dpop key to the grant
    pub fn set_dpop_key(mut self, dpop: &'a Jwk) -> Self {
        self.extras.dpop = Some(dpop);

        self
    }

    /// Set the auth method to use for the grant
    pub fn set_auth_method(mut self, eam: &'a str) -> Self {
        self.extras.endpoint_auth_method = Some(eam);

        self
    }

    /// Add extra claims to the client assertion payload
    pub fn add_client_assertion_claim(mut self, key: impl Into<String>, value: Value) -> Self {
        match self.extras.client_assertion_payload.as_mut() {
            Some(cap) => {
                cap.insert(key.into(), value);
            }
            None => {
                let mut new = HashMap::new();

                new.insert(key.into(), value);

                self.extras.client_assertion_payload = Some(new);
            }
        }
        self
    }

    /// Sets the `retry` flag indicating whether to retry the request on failure.
    ///
    ///  - `retry`: A boolean value. True to retry once, False to not retry.
    pub fn retry(mut self, retry: bool) -> Self {
        self.retry = retry;
        self
    }
}
