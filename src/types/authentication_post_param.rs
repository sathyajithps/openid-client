use std::collections::HashMap;

use josekit::jwk::Jwk;
use serde_json::Value;

pub struct AuthenticationPostParams<'a> {
    pub client_assertion_payload: Option<&'a HashMap<String, Value>>,
    pub endpoint_auth_method: Option<&'a str>,
    pub dpop: Option<&'a Jwk>,
}
