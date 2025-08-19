use crate::types::{MaxAgeCheck, NonceCheck, StateCheck};

/// Parameters for managing and validating an OIDC Implicit grant.
pub struct ImplicitGrantParameters {
    /// Defines the validation logic for the state parameter to protect against CSRF attacks.
    pub state_check: StateCheck,
    /// Defines the validation logic for the nonce claim to mitigate replay attacks.
    pub nonce_check: Option<NonceCheck>,
    /// Indicates whether the response is expected to include an OpenID Connect ID Token.
    pub expect_id_token: bool,
    /// Defines the criteria for validating the user's authentication timing.
    pub max_age_check: Option<MaxAgeCheck>,
}

impl ImplicitGrantParameters {
    /// Creates a new instance with the specified state verification strategy.
    pub fn new(state_check: StateCheck) -> Self {
        Self {
            state_check,
            nonce_check: None,
            expect_id_token: false,
            max_age_check: None,
        }
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
}
