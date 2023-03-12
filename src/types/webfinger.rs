use serde::Deserialize;

/// # WebFingerResponse
/// Represents response from webfinger endpoint
#[derive(Debug, Deserialize)]
pub struct WebFingerResponse {
    /// Uri that identifies entity that JSON Resource Descriptor describes. [See](https://www.rfc-editor.org/rfc/rfc7033.html#section-4.4.1)
    pub subject: String,
    /// List of the links for the requested subject.[See](https://www.rfc-editor.org/rfc/rfc5988)
    pub links: Vec<Link>,
}

/// # Link
/// Refer [RFC 5988](https://www.rfc-editor.org/rfc/rfc5988)
#[derive(Debug, Deserialize)]
pub struct Link {
    /// [Link relation](https://www.rfc-editor.org/rfc/rfc5988#section-4)
    pub rel: String,
    /// Uri pointing to the target resource
    pub href: Option<String>,
}
