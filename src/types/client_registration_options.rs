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

impl ClientRegistrationOptions {
    /// Set Jwks
    pub fn set_jwks(mut self, jwks: Jwks) -> Self {
        self.jwks = Some(jwks);
        self
    }

    /// Set Initial Access Token
    pub fn set_iniatial_access_token(mut self, iat: impl Into<String>) -> Self {
        self.initial_access_token = Some(iat.into());
        self
    }

    /// Add Authorized Party
    pub fn add_authorized_parties(mut self, pty: impl Into<String>) -> Self {
        match self.client_options.additional_authorized_parties.as_mut() {
            Some(aap) => aap.push(pty.into()),
            None => {
                self.client_options = ClientOptions {
                    additional_authorized_parties: Some(vec![pty.into()]),
                };
            }
        };
        self
    }
}
