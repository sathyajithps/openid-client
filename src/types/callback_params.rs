// use std::collections::HashMap;

// use josekit::jwk::Jwk;
// use serde_json::Value;

// pub struct CallbackParams {
//     pub access_token: Option<String>,
//     pub code: Option<String>,
//     pub error: Option<String>,
//     pub error_description: Option<String>,
//     pub error_uri: Option<String>,
//     pub expires_in: Option<String>,
//     pub id_token: Option<String>,
//     pub state: Option<String>,
//     pub token_type: Option<String>,
//     pub session_state: Option<String>,
//     pub response: Option<String>,
//     pub other: Option<HashMap<String, Value>>,
// }

// pub struct CallbackExtras {
//     pub exchange_body: Option<HashMap<String, Value>>,
//     pub client_assertion_payload: Option<HashMap<String, Value>>,
//     pub dpop: Option<Jwk>,
// }

// pub struct OAuthCallbackChecks {
//     pub response_type: Option<String>,
//     pub state: Option<String>,
//     pub code_verifier: Option<String>,
//     pub jarm: Option<bool>,
//     pub scope: Option<String>, // TODO: remove in v6.x
// }

// pub struct OpenIDCallbackChecks {
//     pub max_age: Option<i64>,
//     pub nonce: Option<String>,
//     pub oauth_checks: Option<OAuthCallbackChecks>,
// }
