use crate::{tokenset::TokenSet, types::OidcHttpClient};

pub(crate) struct ValidateIdTokenParams<'a, T: OidcHttpClient> {
    pub token_set: TokenSet,
    pub nonce: Option<String>,
    pub returned_by: &'a str,
    pub max_age: Option<u64>,
    pub state: Option<String>,
    pub auth_req_id: Option<String>,
    pub http_client: &'a T,
}

impl<'a, T: OidcHttpClient> ValidateIdTokenParams<'a, T> {
    pub fn new(token_set: TokenSet, returned_by: &'a str, http_client: &'a T) -> Self {
        Self {
            token_set,
            nonce: None,
            returned_by,
            max_age: None,
            state: None,
            http_client,
            auth_req_id: None,
        }
    }

    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    pub fn max_age(mut self, max_age: u64) -> Self {
        self.max_age = Some(max_age);
        self
    }

    pub fn state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }

    pub fn auth_req_id(mut self, auth_req_id: impl Into<String>) -> Self {
        self.auth_req_id = Some(auth_req_id.into());
        self
    }
}
