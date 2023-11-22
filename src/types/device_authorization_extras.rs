use std::collections::HashMap;

use josekit::jwk::Jwk;
use serde_json::Value;

/// # DeviceAuthorizationExtras
/// Additional parameters for Device Authorization Request
#[derive(Default, Debug)]
pub struct DeviceAuthorizationExtras {
    /// Extra request body properties to be sent to the AS during code exchange.
    pub exchange_body: Option<HashMap<String, Value>>,
    /// Extra client assertion payload parameters to be sent as part of a client JWT assertion.
    /// This is only used when the client's token_endpoint_auth_method is either client_secret_jwt or private_key_jwt
    pub client_assertion_payload: Option<HashMap<String, Value>>,
    /// When provided the client will send a DPoP Proof JWT.
    pub dpop: Option<Jwk>,
}
