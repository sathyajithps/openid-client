use josekit::jwk::Jwk;
use serde_json::Value;
use std::collections::HashMap;

use super::{CallbackExtras, CallbackParams, OAuthCallbackChecks, OpenIDCallbackChecks};

#[derive(Default)]
/// #OpenIdCallbackParams
pub struct OpenIdCallbackParams<'a> {
    /// Redirect uri that was set in the authorize request
    pub redirect_uri: &'a str,
    /// The [CallbackParams] from the response
    pub parameters: CallbackParams,
    /// Checks for validation of openid response
    pub checks: Option<OpenIDCallbackChecks<'a>>,
    /// Extra Parameter to send to the Token endpoint
    pub extras: Option<CallbackExtras>,
}

impl<'a> OpenIdCallbackParams<'a> {
    /// Creates a new [OpenIdCallbackParams]
    pub fn new(redirect_uri: &'a str, parameters: CallbackParams) -> Self {
        Self {
            redirect_uri,
            parameters,
            checks: None,
            extras: None,
        }
    }

    /// Checks the max_age
    pub fn check_max_age(mut self, max_age: u64) -> Self {
        match self.checks.as_mut() {
            Some(oidc_checks) => {
                oidc_checks.max_age = Some(max_age);
            }
            None => {
                self.checks = Some(OpenIDCallbackChecks {
                    max_age: Some(max_age),
                    ..Default::default()
                });
            }
        }

        self
    }

    /// Checks the nonce
    pub fn check_nonce(mut self, nonce: &'a str) -> Self {
        match self.checks.as_mut() {
            Some(oidc_checks) => {
                oidc_checks.nonce = Some(nonce);
            }
            None => {
                self.checks = Some(OpenIDCallbackChecks {
                    nonce: Some(nonce),
                    ..Default::default()
                });
            }
        }

        self
    }

    /// Checks if the response type is of the given type
    pub fn check_response_type(mut self, response_type: &'a str) -> Self {
        let mut oidc_checks = match self.checks {
            Some(oidc_checks) => oidc_checks,
            None => OpenIDCallbackChecks::default(),
        };

        let mut oauth_checks = match oidc_checks.oauth_checks {
            Some(oauth_checks) => oauth_checks,
            None => OAuthCallbackChecks::default(),
        };

        oauth_checks.response_type = Some(response_type);

        oidc_checks.oauth_checks = Some(oauth_checks);

        self.checks = Some(oidc_checks);

        self
    }

    /// Verifies the code verifier
    pub fn check_code_verifier(mut self, code_verifier: &'a str) -> Self {
        let mut oidc_checks = match self.checks {
            Some(oidc_checks) => oidc_checks,
            None => OpenIDCallbackChecks::default(),
        };

        let mut oauth_checks = match oidc_checks.oauth_checks {
            Some(oauth_checks) => oauth_checks,
            None => OAuthCallbackChecks::default(),
        };

        oauth_checks.code_verifier = Some(code_verifier);

        oidc_checks.oauth_checks = Some(oauth_checks);

        self.checks = Some(oidc_checks);

        self
    }

    /// Checks the response state
    pub fn check_state(mut self, state: &'a str) -> Self {
        let mut oidc_checks = match self.checks {
            Some(oidc_checks) => oidc_checks,
            None => OpenIDCallbackChecks::default(),
        };

        let mut oauth_checks = match oidc_checks.oauth_checks {
            Some(oauth_checks) => oauth_checks,
            None => OAuthCallbackChecks::default(),
        };

        oauth_checks.state = Some(state);

        oidc_checks.oauth_checks = Some(oauth_checks);

        self.checks = Some(oidc_checks);

        self
    }

    /// Check if the response is JARM
    pub fn check_jarm(mut self, jarm: bool) -> Self {
        let mut oidc_checks = match self.checks {
            Some(oidc_checks) => oidc_checks,
            None => OpenIDCallbackChecks::default(),
        };

        let mut oauth_checks = match oidc_checks.oauth_checks {
            Some(oauth_checks) => oauth_checks,
            None => OAuthCallbackChecks::default(),
        };

        oauth_checks.jarm = Some(jarm);

        oidc_checks.oauth_checks = Some(oauth_checks);

        self.checks = Some(oidc_checks);

        self
    }

    /// Add extra claims to the client assertion payload
    pub fn add_client_assertion_claim(mut self, key: impl Into<String>, value: Value) -> Self {
        let mut extras = match self.extras {
            Some(e) => e,
            None => CallbackExtras {
                exchange_body: None,
                client_assertion_payload: None,
                dpop: None,
            },
        };

        match extras.client_assertion_payload.as_mut() {
            Some(cap) => {
                cap.insert(key.into(), value);
            }
            None => {
                let mut new = HashMap::new();

                new.insert(key.into(), value);

                extras.client_assertion_payload = Some(new);
            }
        }

        self.extras = Some(extras);

        self
    }

    /// Sets dpop key to the grant
    pub fn set_dpop_key(mut self, dpop: Jwk) -> Self {
        let extras = match self.extras {
            Some(mut e) => {
                e.dpop = Some(dpop);
                e
            }
            None => CallbackExtras {
                exchange_body: None,
                client_assertion_payload: None,
                dpop: Some(dpop),
            },
        };

        self.extras = Some(extras);

        self
    }

    /// Add extra claims to the token exchange body
    pub fn add_exchange_body_param(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        let mut extras = match self.extras {
            Some(e) => e,
            None => CallbackExtras {
                exchange_body: None,
                client_assertion_payload: None,
                dpop: None,
            },
        };

        match extras.exchange_body.as_mut() {
            Some(eb) => {
                eb.insert(key.into(), value.into());
            }
            None => {
                let mut new = HashMap::new();

                new.insert(key.into(), value.into());

                extras.exchange_body = Some(new);
            }
        }

        self.extras = Some(extras);

        self
    }
}
