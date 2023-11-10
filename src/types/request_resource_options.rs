use josekit::jwk::Jwk;
use reqwest::{header::HeaderMap, Method};

/// # RequestResourceParams
/// Parameters for the `request_resource_async` method in Client
#[derive(Default, Clone)]
pub struct RequestResourceOptions {
    /// Request method
    pub method: Method,
    /// Header to send with the request
    pub headers: HeaderMap,
    /// Body of the request
    pub body: Option<String>,
    /// Specifies if the request should use bearer auth
    pub bearer: bool,
    /// Checks if the body should be of type json
    pub expect_body_to_be_json: bool,
    /// When provided the client will send a DPoP Proof JWT.
    /// The DPoP Proof JWT's algorithm is determined automatically based on the type of key and the issuer metadata.
    pub dpop: Option<Jwk>,
}
