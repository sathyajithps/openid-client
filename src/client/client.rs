use std::collections::HashMap;

use crate::{types::ClientMetadata, Issuer, OidcClientError};

/// # Client instance
#[derive(Debug)]
pub struct Client {
    client_id: String,
    client_secret: Option<String>,
    grant_types: Vec<String>,
    id_token_signed_response_alg: String,
    response_types: Vec<String>,
    token_endpoint_auth_method: String,
    token_endpoint_auth_signing_alg: Option<String>,
    introspection_endpoint_auth_method: Option<String>,
    introspection_endpoint_auth_signing_alg: Option<String>,
    revocation_endpoint_auth_method: Option<String>,
    revocation_endpoint_auth_signing_alg: Option<String>,
    redirect_uri: Option<String>,
    redirect_uris: Option<Vec<String>>,
    response_type: Option<String>,
    other_fields: HashMap<String, serde_json::Value>,
}

impl Client {
    pub(crate) fn default() -> Self {
        Self {
            client_id: String::new(),
            client_secret: None,
            grant_types: vec!["authorization_code".to_string()],
            id_token_signed_response_alg: "RS256".to_string(),
            response_types: vec!["code".to_string()],
            token_endpoint_auth_method: "client_secret_basic".to_string(),
            token_endpoint_auth_signing_alg: None,
            introspection_endpoint_auth_method: None,
            introspection_endpoint_auth_signing_alg: None,
            revocation_endpoint_auth_method: None,
            revocation_endpoint_auth_signing_alg: None,
            redirect_uri: None,
            redirect_uris: None,
            response_type: None,
            other_fields: HashMap::new(),
        }
    }

    /// Method used by Issuer::client to create a new client
    pub(crate) fn from(metadata: ClientMetadata, issuer: Issuer) -> Result<Self, OidcClientError> {
        if metadata.client_id.is_empty() {
            return Err(OidcClientError {
                name: "MetadataError".to_string(),
                error: "client_id is required".to_string(),
                error_description: "client_id is required".to_string(),
                response: None,
            });
        }

        let mut client = Self {
            client_id: metadata.client_id,
            client_secret: metadata.client_secret,
            other_fields: metadata.other_fields,
            ..Client::default()
        };

        if metadata.response_type.is_some() && metadata.response_types.is_some() {
            return Err(OidcClientError {
                name: "TypeError".to_string(),
                error: "invalid configuration".to_string(),
                error_description: "provide a response_type or response_types, not both"
                    .to_string(),
                response: None,
            });
        }

        if let Some(response_type) = &metadata.response_type {
            client.response_type = Some(response_type.clone());
            client.response_types = vec![response_type.clone()];
        }

        if let Some(response_types) = &metadata.response_types {
            client.response_types = response_types.clone().to_vec();
        }

        if metadata.redirect_uri.is_some() && metadata.redirect_uris.is_some() {
            return Err(OidcClientError {
                name: "TypeError".to_string(),
                error: "invalid configuration".to_string(),
                error_description: "provide a redirect_uri or redirect_uris, not both".to_string(),
                response: None,
            });
        }

        if let Some(redirect_uri) = &metadata.redirect_uri {
            client.redirect_uri = Some(redirect_uri.clone());
            client.redirect_uris = Some(vec![redirect_uri.clone()])
        }

        if let Some(redirect_uris) = &metadata.redirect_uris {
            client.redirect_uris = Some(redirect_uris.clone().to_vec());
        }

        if let Some(team) = metadata.token_endpoint_auth_method {
            client.token_endpoint_auth_method = team;
        } else if let Some(teams) = &issuer.token_endpoint_auth_methods_supported {
            if !teams.contains(&client.get_token_endpoint_auth_method())
                && teams.contains(&"client_secret_post".to_string())
            {
                client.token_endpoint_auth_method = "client_secret_post".to_string();
            }
        }

        if metadata.token_endpoint_auth_signing_alg.is_some() {
            client.token_endpoint_auth_signing_alg = metadata.token_endpoint_auth_signing_alg;
        }

        client.introspection_endpoint_auth_method = metadata
            .introspection_endpoint_auth_method
            .or(Some(client.get_token_endpoint_auth_method()));

        client.introspection_endpoint_auth_signing_alg = metadata
            .introspection_endpoint_auth_signing_alg
            .or(client.get_token_endpoint_auth_signing_alg());

        client.revocation_endpoint_auth_method = metadata
            .revocation_endpoint_auth_method
            .or(Some(client.get_token_endpoint_auth_method()));

        client.revocation_endpoint_auth_signing_alg = metadata
            .revocation_endpoint_auth_signing_alg
            .or(client.get_token_endpoint_auth_signing_alg());

        assert_signing_alg_values_support(
            &Some(client.token_endpoint_auth_method.clone()),
            &client.token_endpoint_auth_signing_alg,
            &issuer.token_endpoint_auth_methods_supported,
            "token",
        )?;

        assert_signing_alg_values_support(
            &client.introspection_endpoint_auth_method,
            &client.introspection_endpoint_auth_signing_alg,
            &issuer.introspection_endpoint_auth_methods_supported,
            "introspection",
        )?;

        assert_signing_alg_values_support(
            &client.revocation_endpoint_auth_method,
            &client.revocation_endpoint_auth_signing_alg,
            &issuer.revocation_endpoint_auth_methods_supported,
            "revocation",
        )?;

        Ok(client)
    }
}

/// Getter method implementations for Client
impl Client {
    /// Get client id
    pub fn get_client_id(&self) -> String {
        self.client_id.clone()
    }

    /// Get client secret
    pub fn get_client_secret(&self) -> Option<String> {
        self.client_secret.clone()
    }

    /// Get grant types
    pub fn get_grant_types(&self) -> Vec<String> {
        self.grant_types.to_vec()
    }

    /// Get id token signed response algorithm
    pub fn get_id_token_signed_response_alg(&self) -> String {
        self.id_token_signed_response_alg.clone()
    }

    /// Get response types. See [ClientMetadata].
    pub fn get_response_types(&self) -> Vec<String> {
        self.response_types.to_vec()
    }

    /// Get token endpoint authentication method. See [ClientMetadata].
    pub fn get_token_endpoint_auth_method(&self) -> String {
        self.token_endpoint_auth_method.clone()
    }

    /// Get token endpoint authentication signing alg. See [ClientMetadata].
    pub fn get_token_endpoint_auth_signing_alg(&self) -> Option<String> {
        self.token_endpoint_auth_signing_alg.clone()
    }

    /// Get introspection endpoint authentication method. See [ClientMetadata].
    pub fn get_introspection_endpoint_auth_method(&self) -> Option<String> {
        self.introspection_endpoint_auth_method.clone()
    }

    /// Get introspection endpoint authentication signing alg. See [ClientMetadata].
    pub fn get_introspection_endpoint_auth_signing_alg(&self) -> Option<String> {
        self.introspection_endpoint_auth_signing_alg.clone()
    }

    /// Get revocation endpoint authentication method. See [ClientMetadata].
    pub fn get_revocation_endpoint_auth_method(&self) -> Option<String> {
        self.revocation_endpoint_auth_method.clone()
    }

    /// Get revocation endpoint authentication signing alg. See [ClientMetadata].
    pub fn get_revocation_endpoint_auth_signing_alg(&self) -> Option<String> {
        self.revocation_endpoint_auth_signing_alg.clone()
    }

    /// Gets a field from `other_fields`
    pub fn get_field(&self, key: &str) -> Option<&serde_json::Value> {
        self.other_fields.get(key)
    }

    /// Get redirect uri. See [ClientMetadata].
    pub fn get_redirect_uri(&self) -> Option<String> {
        self.redirect_uri.clone()
    }

    /// Get redirect uris. See [ClientMetadata].
    pub fn get_redirect_uris(&self) -> Option<Vec<String>> {
        Some(self.redirect_uris.clone()?.to_vec())
    }

    /// Get response type
    pub fn get_response_type(&self) -> Option<String> {
        self.response_type.clone()
    }
}

fn assert_signing_alg_values_support(
    auth_method: &Option<String>,
    supported_alg: &Option<String>,
    issuer_supported_alg_values: &Option<Vec<String>>,
    endpoint: &str,
) -> Result<(), OidcClientError> {
    if let Some(am) = auth_method {
        if am.ends_with("_jwt") && supported_alg.is_none() && issuer_supported_alg_values.is_none()
        {
            return Err(OidcClientError {
                name: "TypeError".to_string(),
                error: "invalid configuration".to_string(),
                error_description: format!("{0}_endpoint_auth_signing_alg_values_supported must be configured on the issuer if {0}_endpoint_auth_signing_alg is not defined on a client", endpoint),
                response: None,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/client_test.rs"]
mod client_test;
