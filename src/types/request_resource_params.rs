use reqwest::{header::HeaderMap, Method};

/// # RequestResourceParams
/// Parameters for the `request_resource_async` method in Client
#[derive(Default, Clone)]
pub struct RequestResourceParams {
    /// Request method
    pub method: Method,
    /// Header to send with the request
    pub headers: HeaderMap,
    /// Body of the request
    pub body: Option<String>,
}
