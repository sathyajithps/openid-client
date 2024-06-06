//! GrantParams
use std::collections::HashMap;

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

impl<'a> Default for GrantParams<'a> {
    fn default() -> Self {
        Self {
            body: HashMap::new(),
            extras: Default::default(),
            retry: true,
        }
    }
}

impl<'a> GrantParams<'a> {
    /// Sets the request body with the provided HashMap.
    ///
    /// This method takes ownership of the provided `body` HashMap.
    ///
    ///  - `body`: A HashMap containing key-value pairs representing the request body.  
    ///           Keys are strings and values are also strings.  
    ///
    pub fn body(mut self, body: HashMap<String, String>) -> Self {
        self.body = body;
        self
    }

    /// Sets the `GrantExtras` for customizing the authentication request.
    ///
    ///  - `extras`: A `GrantExtras` instance containing additional parameters.
    pub fn extras(mut self, extras: GrantExtras<'a>) -> Self {
        self.extras = extras;
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
