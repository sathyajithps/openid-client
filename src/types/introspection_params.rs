use std::collections::HashMap;

use serde_json::Value;

/// # IntrospectionParams
/// Parameters for customizing Introspection request
#[derive(Default)]
pub struct IntrospectionExtras {
    /// Additional claims to be added in the client assertion payload
    pub client_assertion_payload: Option<HashMap<String, Value>>,
    /// Additional body params to sent with the introspection request
    pub introspect_body: Option<HashMap<String, String>>,
}

impl IntrospectionExtras {
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

    /// Add extra params to the introspect body
    pub fn add_introspect_body_param(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        match self.introspect_body.as_mut() {
            Some(ib) => {
                ib.insert(key.into(), value.into());
            }
            None => {
                let mut new = HashMap::new();

                new.insert(key.into(), value.into());

                self.introspect_body = Some(new);
            }
        }
        self
    }
}
