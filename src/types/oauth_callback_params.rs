use josekit::jwk::Jwk;
use serde_json::Value;
use std::collections::HashMap;

use super::{CallbackExtras, CallbackParams, OAuthCallbackChecks};

/// #OAuthCallbackParams
pub struct OAuthCallbackParams<'a> {
    /// Redirect uri that was set in the oauth authorize request
    pub redirect_uri: &'a str,
    /// The [CallbackParams] from the response
    pub parameters: CallbackParams,
    /// Checks for validation of oauth response
    pub checks: Option<OAuthCallbackChecks<'a>>,
    /// Extra Parameter to send to the Token endpoint
    pub extras: Option<CallbackExtras>,
}

impl<'a> OAuthCallbackParams<'a> {
    /// Creates a new [OAuthCallbackParams]
    pub fn new(redirect_uri: &'a str, parameters: CallbackParams) -> Self {
        Self {
            redirect_uri,
            parameters,
            checks: None,
            extras: None,
        }
    }

    /// Checks if the response type is of the given type
    pub fn check_response_type(mut self, response_type: &'a str) -> Self {
        match self.checks.as_mut() {
            Some(oauth_checks) => {
                oauth_checks.response_type = Some(response_type);
            }
            None => {
                self.checks = Some(OAuthCallbackChecks {
                    response_type: Some(response_type),
                    ..Default::default()
                });
            }
        }

        self
    }

    /// Verifies the code verifier
    pub fn check_code_verifier(mut self, code_verifier: &'a str) -> Self {
        match self.checks.as_mut() {
            Some(oauth_checks) => {
                oauth_checks.code_verifier = Some(code_verifier);
            }
            None => {
                self.checks = Some(OAuthCallbackChecks {
                    code_verifier: Some(code_verifier),
                    ..Default::default()
                });
            }
        }

        self
    }

    /// Checks the response state
    pub fn check_state(mut self, state: &'a str) -> Self {
        match self.checks.as_mut() {
            Some(oauth_checks) => {
                oauth_checks.state = Some(state);
            }
            None => {
                self.checks = Some(OAuthCallbackChecks {
                    state: Some(state),
                    ..Default::default()
                });
            }
        }

        self
    }

    /// Check if the response is JARM
    pub fn check_jarm(mut self, jarm: bool) -> Self {
        match self.checks.as_mut() {
            Some(oauth_checks) => {
                oauth_checks.jarm = Some(jarm);
            }
            None => {
                self.checks = Some(OAuthCallbackChecks {
                    jarm: Some(jarm),
                    ..Default::default()
                });
            }
        }

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
