use std::collections::HashMap;

use josekit::jwk::Jwk;

use super::http_client::HttpMethod;

/// # RequestResourceParams
/// Parameters for the `request_resource_async` method in Client
#[derive(Default, Clone)]
pub struct RequestResourceOptions<'a> {
    /// Request method
    pub method: HttpMethod,
    /// Header to send with the request
    pub headers: HashMap<String, Vec<String>>,
    /// Body of the request
    pub body: Option<String>,
    /// Specifies if the request should use bearer auth
    pub bearer: bool,
    /// Checks if the body should be of type json
    pub expect_body_to_be_json: bool,
    /// When provided the client will send a DPoP Proof JWT.
    pub dpop: Option<&'a Jwk>,
}
