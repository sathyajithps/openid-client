use std::collections::HashMap;

use josekit::jwk::Jwk;
use serde_json::Value;

/// # PushedAuthorizationRequestExtras
/// Extra parameters for Pushed Authorization Request
#[derive(Default)]
pub struct PushedAuthorizationRequestExtras<'a> {
    /// Additional claims to be added in the client assertion payload
    pub client_assertion_payload: Option<HashMap<String, Value>>,
    /// When provided the client will send a DPoP Proof JWT.
    pub dpop: Option<&'a Jwk>,
}

impl<'a> PushedAuthorizationRequestExtras<'a> {
    /// Creates a new instance
    pub fn new() -> Self {
        PushedAuthorizationRequestExtras {
            client_assertion_payload: None,
            dpop: None,
        }
    }

    /// Add extra claims to the client assertion payload
    pub fn add_client_assertion_claim(mut self, key: impl Into<String>, value: Value) -> Self {
        match self.client_assertion_payload.as_mut() {
            Some(cap) => {
                cap.insert(key.into(), value);
            }
            None => {
                let mut new = HashMap::new();

                new.insert(key.into(), value);

                self.client_assertion_payload = Some(new);
            }
        }
        self
    }

    /// Sets dpop key
    pub fn set_dpop_key(mut self, dpop: &'a Jwk) -> Self {
        self.dpop = Some(dpop);

        self
    }
}
