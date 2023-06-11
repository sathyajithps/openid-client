use std::collections::HashMap;

use serde::Deserialize;

// TODO: Add rest of the fields from https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata

/// # Client Metadata
#[derive(Debug, Deserialize)]
pub struct ClientMetadata {
    /// Client Id
    pub client_id: Option<String>,
    /// Client secret
    pub client_secret: Option<String>,
    /// [Authentication method](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    /// used by the client for authenticating with the OP
    pub token_endpoint_auth_method: Option<String>,
    /// [Algorithm](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
    /// used for signing the JWT used to authenticate
    /// the client at the token endpoint.
    pub token_endpoint_auth_signing_alg: Option<String>,
    /// [Authentication method](https://www.rfc-editor.org/rfc/rfc8414.html#section-2)
    /// used by the client for introspection endpoint
    pub introspection_endpoint_auth_method: Option<String>,
    /// [Algorithm](https://www.rfc-editor.org/rfc/rfc8414.html#section-2)
    /// used for signing the JWT used to authenticate
    /// the client at the introspection endpoint.
    pub introspection_endpoint_auth_signing_alg: Option<String>,
    /// [Authentication method](https://www.rfc-editor.org/rfc/rfc8414.html#section-2)
    /// used by the client for revocation endpoint
    pub revocation_endpoint_auth_method: Option<String>,
    /// [Algorithm](https://www.rfc-editor.org/rfc/rfc8414.html#section-2)
    /// used for signing the JWT used to authenticate
    /// the client at the revocation endpoint.
    pub revocation_endpoint_auth_signing_alg: Option<String>,
    /// The [redirect uri](https://openid.net/specs/openid-connect-http-redirect-1_0-01.html#rf_prep)
    /// where response will be sent
    pub redirect_uri: Option<String>,
    /// A list of acceptable [redirect uris](https://openid.net/specs/openid-connect-http-redirect-1_0-01.html#rf_prep)
    pub redirect_uris: Option<Vec<String>>,
    /// [Response type](https://openid.net/specs/openid-connect-http-redirect-1_0-01.html#rf_prep) supported by the client.
    pub response_type: Option<String>,
    /// List of [Response type](https://openid.net/specs/openid-connect-http-redirect-1_0-01.html#rf_prep) supported by the client
    pub response_types: Option<Vec<String>>,
    /// Extra key values
    #[serde(flatten)]
    pub other_fields: HashMap<String, serde_json::Value>,
}

/// Default implementation of client metadata
impl Default for ClientMetadata {
    /// Default implementation of client metadata (empty)
    fn default() -> Self {
        Self {
            client_id: None,
            client_secret: None,
            token_endpoint_auth_method: None,
            token_endpoint_auth_signing_alg: None,
            introspection_endpoint_auth_method: None,
            introspection_endpoint_auth_signing_alg: None,
            revocation_endpoint_auth_method: None,
            revocation_endpoint_auth_signing_alg: None,
            redirect_uri: None,
            redirect_uris: None,
            response_type: None,
            response_types: None,
            other_fields: HashMap::new(),
        }
    }
}
