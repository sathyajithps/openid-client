use std::collections::HashMap;

use serde_json::Value;

/// # RevokeRequestParams
/// Parameters for customizing Token Revocation request
#[derive(Default)]
pub struct RevokeExtras {
    /// Additional claims to be added in the client assertion payload
    pub client_assertion_payload: Option<HashMap<String, Value>>,
    /// Additional body params to sent with the revocation request
    pub revocation_body: Option<HashMap<String, String>>,
}

impl RevokeExtras {
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

    /// Add extra params to the revoke request body
    pub fn add_revocation_body_param(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        match self.revocation_body.as_mut() {
            Some(rb) => {
                rb.insert(key.into(), value.into());
            }
            None => {
                let mut new = HashMap::new();

                new.insert(key.into(), value.into());

                self.revocation_body = Some(new);
            }
        }
        self
    }
}
