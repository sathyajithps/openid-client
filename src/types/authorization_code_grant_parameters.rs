use crate::types::{MaxAgeCheck, NonceCheck, StateCheck};
use std::collections::HashMap;

/// # AuthorizationCodeGrantParameters
/// Represents the AuthorizationCodeGrantParameters
pub struct AuthorizationCodeGrantParameters {
    /// Redirect URI to which the response will be sent
    pub redirect_uri: String,
    /// Additional parameters to be included in the request
    pub additional_parameters: HashMap<String, String>,
    /// PKCE code verifier used for this request
    pub pkce_code_verifier: Option<String>,
    /// State check to be performed
    pub state_check: StateCheck,
    /// Nonce check to be performed
    pub nonce_check: Option<NonceCheck>,
    /// Whether an ID token is expected in the response
    pub expect_id_token: bool,
    /// Maximum authentication age check
    pub max_age_check: Option<MaxAgeCheck>,
}

impl AuthorizationCodeGrantParameters {
    /// Creates a new instance with the required redirect URI and state verification strategy.
    pub fn new(redirect_uri: impl Into<String>, state_check: StateCheck) -> Self {
        Self {
            redirect_uri: redirect_uri.into(),
            additional_parameters: HashMap::new(),
            pkce_code_verifier: None,
            state_check,
            nonce_check: None,
            expect_id_token: false,
            max_age_check: None,
        }
    }

    /// Sets the PKCE code verifier for the authorization request.
    pub fn pkce_code_verifier(mut self, verifier: impl Into<String>) -> Self {
        self.pkce_code_verifier = Some(verifier.into());
        self
    }

    /// Updates the state verification strategy for this request.
    pub fn state_check(mut self, check: StateCheck) -> Self {
        self.state_check = check;
        self
    }

    /// Sets the nonce verification strategy for this request.
    pub fn nonce_check(mut self, check: NonceCheck) -> Self {
        self.nonce_check = Some(check);
        self
    }

    /// Specifies whether an ID token is expected in the resulting response.
    pub fn expect_id_token(mut self, expect: bool) -> Self {
        self.expect_id_token = expect;
        self
    }

    /// Sets the maximum authentication age validation criteria.
    pub fn max_age_check(mut self, check: MaxAgeCheck) -> Self {
        self.max_age_check = Some(check);
        self
    }

    /// Adds a custom parameter to be sent with the authorization request.
    pub fn add_additional_parameter(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.additional_parameters.insert(key.into(), value.into());
        self
    }
}
