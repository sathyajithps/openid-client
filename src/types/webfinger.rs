use serde::Deserialize;

/// # WebFingerResponse
/// Represents the WebFingerResponse
#[derive(Debug, Deserialize)]
pub struct WebFingerResponse {
    pub links: Vec<Link>,
}

/// # Link
/// Represents the Link
#[derive(Debug, Deserialize)]
pub struct Link {
    pub rel: String,
    pub href: Option<String>,
}
