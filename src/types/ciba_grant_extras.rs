use std::collections::HashMap;

use josekit::jwk::Jwk;
use serde_json::Value;

/// # CibaGrantExtras
/// Additional parameters for CIBA Grant
#[derive(Default, Debug)]
pub struct CibaAuthenticationExtras {
    /// Extra request body properties to be sent in token grant.
    pub exchange_body: Option<HashMap<String, String>>,
    /// Extra client assertion payload parameters to be sent as part of a client JWT assertion.
    /// This is only used when the client's token_endpoint_auth_method is either client_secret_jwt or private_key_jwt
    pub client_assertion_payload: Option<HashMap<String, Value>>,
    /// When provided the client will send a DPoP Proof JWT.
    pub dpop: Option<Jwk>,
}

impl CibaAuthenticationExtras {
    /// Create a new instance
    pub fn new() -> Self {
        Self {
            exchange_body: None,
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
    pub fn set_dpop_key(mut self, dpop: Jwk) -> Self {
        self.dpop = Some(dpop);

        self
    }
}
