use serde::Deserialize;

use super::http::Response;

/// # StandardBodyError
/// Error that is returned from the OIDC Server
/// - [Error Response](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1)
#[derive(Debug, Deserialize)]
pub struct StandardBodyError {
    /// Short title of the error
    pub error: String,
    /// Description of the error
    pub error_description: Option<String>,
    /// Error uri
    pub error_uri: Option<String>,
}

/// # OidcClientError
/// Error That will be returned to the end user of this library
#[derive(Debug)]
pub struct OidcClientError {
    /// Name of the error. One of *TypeError*, *OPError*
    pub name: String,
    /// Short title of the error
    pub error: String,
    /// Description
    pub error_description: String,
    /// If the error occurred as part of a request, the response field will be available
    pub response: Option<Response>,
}

impl OidcClientError {
    /// Creates a new instance of the [OidcClientError]
    pub fn new(
        name: &str,
        error: &str,
        error_description: &str,
        response: Option<Response>,
    ) -> Self {
        Self {
            name: name.to_string(),
            error: error.to_string(),
            error_description: error_description.to_string(),
            response,
        }
    }
}
