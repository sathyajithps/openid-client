use std::collections::HashMap;

use josekit::jwk::Jwk;
use serde_json::Value;

/// # RefreshParams
/// Parameters for the Client's `refresh_async` request
#[derive(Debug)]
pub struct RefreshTokenExtras<'a> {
    /// Additional claims to be added in the client assertion payload
    pub client_assertion_payload: Option<HashMap<String, Value>>,
    /// Additional body params to sent with the exchange request
    pub exchange_body: Option<HashMap<String, String>>,
    /// When provided the client will send a DPoP Proof JWT.
    pub dpop: Option<&'a Jwk>,
}

impl<'a> RefreshTokenExtras<'a> {
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

    /// Add extra params to the exchange body
    pub fn add_exchange_body_param(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        match self.exchange_body.as_mut() {
            Some(eb) => {
                eb.insert(key.into(), value.into());
            }
            None => {
                let mut new = HashMap::new();

                new.insert(key.into(), value.into());

                self.exchange_body = Some(new);
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
