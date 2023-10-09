//! Type used to query [crate::issuer::Issuer]'s Jwks Keystore

use serde::Serialize;

#[derive(Hash, Serialize, Default)]
pub struct QueryKeyStore {
    pub key_id: Option<String>,
    pub key_use: Option<String>,
    pub key_type: Option<String>,
    pub alg: Option<String>,
}
