use crate::types::{MaxAgeCheck, NonceCheck};

/// # AuthorizationCodeGrantValidationParameters
/// Options to validate authorization code grant response
#[derive(Default)]
pub struct AuthorizationCodeGrantValidationParameters {
    /// Nonce check to be performed
    pub nonce_check: Option<NonceCheck>,
    /// Whether an ID token is expected in the response
    pub expect_id_token: bool,
    /// Maximum authentication age check
    pub max_age_check: Option<MaxAgeCheck>,
}

impl AuthorizationCodeGrantValidationParameters {
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
