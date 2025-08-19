use std::collections::HashMap;

use crate::helpers::generate_random;

/// # EndSessionParameters
/// Represents the EndSessionParameters
pub struct EndSessionParameters {
    /// A previously issued ID Token used as a hint to identify the user's session for termination.
    pub id_token_hint: Option<String>,
    /// The URI where the user is redirected after a successful logout session.
    pub post_logout_redirect_uri: Option<String>,
    /// An opaque value used to maintain state between the logout request and the redirect callback.
    pub state: Option<String>,
    /// The unique identifier for the client application initiating the logout.
    pub client_id: Option<String>,
    /// A hint provided to the server about the user's identity to facilitate the logout process.
    pub logout_hint: Option<String>,
    /// A collection of non-standard or custom parameters to be included in the logout request.
    pub additional_parameters: Option<HashMap<String, String>>,
}

// Builder methods
impl EndSessionParameters {
    /// Sets the `id_token_hint`
    pub fn id_token_hint(mut self, hint: impl Into<String>) -> Self {
        self.id_token_hint = Some(hint.into());
        self
    }

    /// Sets the `post_logout_redirect_uri`
    pub fn post_logout_redirect_uri(mut self, uri: impl Into<String>) -> Self {
        self.post_logout_redirect_uri = Some(uri.into());
        self
    }

    /// Sets the `client_id`
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Sets the `logout_hint`
    pub fn logout_hint(mut self, hint: impl Into<String>) -> Self {
        self.logout_hint = Some(hint.into());
        self
    }

    /// Add additional param to the end session request
    pub fn add_additional_param(
        mut self,
        param: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        match &mut self.additional_parameters {
            Some(additional_parameters) => {
                additional_parameters.insert(param.into(), value.into());
            }
            None => {
                let mut map = HashMap::new();
                map.insert(param.into(), value.into());
                self.additional_parameters = Some(map)
            }
        }

        self
    }
}

// Helper methods
impl EndSessionParameters {
    /// Sets the `state` parameter
    pub fn state(&mut self) -> String {
        let state = generate_random(None);
        self.state = Some(state.to_owned());
        state
    }
}
