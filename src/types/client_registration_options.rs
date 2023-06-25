use crate::{ClientOptions, Jwks};

/// # Client Registration Options
#[derive(Default, Clone)]
pub struct ClientRegistrationOptions {
    /// Private JWKS
    pub jwks: Option<Jwks>,
    /// Initial Access Token for the client to register with
    pub initial_access_token: Option<String>,
    /// Other options
    pub client_options: ClientOptions,
}
