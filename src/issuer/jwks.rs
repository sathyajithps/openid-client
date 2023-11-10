//! Issuer methods for Keystore

use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
};

use serde_json::Value;

use crate::{
    issuer::Issuer,
    jwks::Jwks,
    types::{query_keystore::QueryKeyStore, OidcClientError},
};

/// [Issuer]'s Keystore methods
impl Issuer {
    pub(crate) async fn query_keystore_async(
        &mut self,
        mut query: QueryKeyStore,
        allow_multi: bool,
    ) -> Result<Jwks, OidcClientError> {
        let mut hasher = DefaultHasher::new();
        query.hash(&mut hasher);
        let hash = hasher.finish();

        match &mut self.keystore {
            Some(keystore) => {
                let reload = keystore.cache.contains_key(&hash)
                    || (self.now)() - keystore.last_accessed > 60;

                let jwks = keystore.get_keystore_async(reload).await?;

                let keys = jwks.get(
                    query.alg.clone(),
                    query.key_use.clone(),
                    query.key_id.clone(),
                )?;

                let alg = query.alg.clone();

                // Why delete and print in the error below?
                query.alg = None;

                if keys.is_empty() {
                    let message = format!("no valid key found in issuer\'s jwks_uri for key parameters kid: {}, alg: {}, key_use: {}", query.key_id.unwrap_or("".to_string()), alg.unwrap_or("".to_string()), query.key_use.unwrap_or("".to_string()));

                    let mut extra_data = HashMap::<String, Value>::new();

                    let json_jwks = match serde_json::to_value(&jwks) {
                        Ok(v) => v,
                        Err(_) => return Err(OidcClientError::new_error("Malformed jwks", None)),
                    };

                    extra_data.insert("jwks".to_string(), json_jwks);

                    return Err(OidcClientError::new_rp_error(
                        &message,
                        None,
                        Some(extra_data),
                    ));
                }

                if !allow_multi && keys.len() > 1 && query.key_id.is_none() {
                    let message = format!("multiple matching keys found in issuer\'s jwks_uri for key parameters kid: {}, key_use: {}, alg: {}, kid must be provided in this case", query.key_id.unwrap_or("".to_string()), query.key_use.unwrap_or("".to_string()), alg.unwrap_or("".to_string()));

                    let mut extra_data = HashMap::<String, Value>::new();

                    let json_jwks = match serde_json::to_value(&jwks) {
                        Ok(v) => v,
                        Err(_) => return Err(OidcClientError::new_error("Malformed jwks", None)),
                    };

                    extra_data.insert("jwks".to_string(), json_jwks);

                    return Err(OidcClientError::new_rp_error(
                        &message,
                        None,
                        Some(extra_data),
                    ));
                }

                keystore.cache.insert(hash, true);

                Ok(jwks)
            }
            _ => Err(OidcClientError::new_error(
                "No Keystore found for this issuer",
                None,
            )),
        }
    }

    /// Reload Issuer Jwks
    /// This method force refreshes the issuer Jwks using the configured Jwks Uri.
    /// If no `jwks_uri` is found, returns an [OidcClientError].
    pub async fn reload_jwks_async(&mut self) -> Result<bool, OidcClientError> {
        match &mut self.keystore {
            Some(keystore) => {
                keystore.get_keystore_async(true).await?;
                Ok(true)
            }
            _ => Err(OidcClientError::new_error(
                "No Keystore found for this issuer",
                None,
            )),
        }
    }
}
