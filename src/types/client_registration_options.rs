use crate::{jwks::Jwks, types::ClientOptions};

/// # Client Registration Options
#[derive(Default)]
pub struct ClientRegistrationOptions {
    /// Private JWKS of the client
    pub jwks: Option<Jwks>,
    /// Initial Access Token for the client to register with
    pub initial_access_token: Option<String>,
    /// Other options
    pub client_options: ClientOptions,
}
