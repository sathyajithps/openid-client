use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct WebFingerResponse {
    pub subject: String,
    pub links: Vec<Link>,
}

#[derive(Debug, Deserialize)]
pub struct Link {
    pub rel: String,
    pub href: Option<String>,
}
