use std::collections::HashMap;

use serde_json::Value;

/// # IntrospectionParams
/// Parameters for customizing Introspection request
pub struct IntrospectionExtras {
    /// Additional claims to be added in the client assertion payload
    pub client_assertion_payload: Option<HashMap<String, Value>>,
    /// Additional body params to sent with the introspection request
    pub introspect_body: Option<HashMap<String, Value>>,
}
