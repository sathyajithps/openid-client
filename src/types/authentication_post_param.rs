use std::collections::HashMap;

use josekit::jwk::Jwk;
use serde_json::Value;

/// The parameters that will be set for the authentication post request.
pub struct AuthenticationPostParams<'a> {
    /// Extra client assertion payload parameters to be sent as part of a client JWT assertion.
    /// This is only used when the client's token_endpoint_auth_method is either client_secret_jwt or private_key_jwt
    pub client_assertion_payload: Option<&'a HashMap<String, Value>>,
    /// The Authentication method this client should use
    pub endpoint_auth_method: Option<&'a str>,
    /// When provided the client will send a DPoP Proof JWT.
    pub dpop: Option<&'a Jwk>,
}
