use crate::http::Response;

#[derive(Debug)]
pub struct OidcClientError {
    pub name: String,
    pub error: String,
    pub error_description: String,
    pub response: Option<Response>,
}

impl OidcClientError {
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
