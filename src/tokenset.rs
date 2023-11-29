use std::{cmp::max, collections::HashMap, num::Wrapping};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::helpers::now;

/// # TokenSetParams
/// Argument to create new TokenSetParams
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TokenSetParams {
    /// `access_token`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    /// `token_type`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    /// `id_token`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    /// `refresh_token`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// `expires_in` - Access token expiration in (seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<i64>,
    /// `expires_at` - Access token expiration timestamp, represented as the number of seconds since the epoch
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// `session_state`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_state: Option<String>,
    /// `scope`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// `other`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other: Option<HashMap<String, Value>>,
}

/// # TokenSet
/// Represents a set of tokens retrieved from either authorization callback or successful token endpoint grant call.
/// - If there are other properties present, it will be stored in `other` field. Access it via [`TokenSet::get_other()`]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenSet {
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_in: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", flatten)]
    other: Option<HashMap<String, Value>>,
    #[serde(skip_serializing, skip_deserializing, default = "default_now")]
    pub(crate) now: fn() -> i64,
}

fn default_now() -> fn() -> i64 {
    now
}

impl Default for TokenSet {
    fn default() -> Self {
        Self {
            access_token: Default::default(),
            token_type: Default::default(),
            id_token: Default::default(),
            refresh_token: Default::default(),
            expires_in: Default::default(),
            expires_at: Default::default(),
            session_state: Default::default(),
            scope: Default::default(),
            other: Default::default(),
            now,
        }
    }
}

impl TokenSet {
    /// # Create a [TokenSet] instance
    ///
    /// - `expires_at` - Access token expiration timestamp, represented as the number of seconds since the epoch
    pub fn new(params: TokenSetParams) -> Self {
        let mut tokenset = Self {
            access_token: params.access_token,
            token_type: params.token_type,
            id_token: params.id_token,
            refresh_token: params.refresh_token,
            expires_in: params.expires_in,
            expires_at: params.expires_at,
            session_state: params.session_state,
            scope: params.scope,
            other: params.other,
            now,
        };

        if params.expires_at.is_none() && params.expires_in.is_some() {
            if let Some(e) = params.expires_in {
                tokenset.expires_at = Some((Wrapping((tokenset.now)()) + Wrapping(e)).0);
            }
        }

        if let Some(e) = params.expires_in {
            if e < 0 {
                tokenset.expires_in = Some(0);
            }
        }

        tokenset
    }

    /// Returns if the set is expired or not
    pub fn expired(&self) -> bool {
        let expires_in = self.get_expires_in_internal();

        if let Some(e) = expires_in {
            return e == 0;
        }
        false
    }

    /// Get claims from the id_token
    /// - This method just decodes and returns the found claims. Does not validate
    pub fn claims(&self) -> Option<HashMap<String, Value>> {
        if let Some(id_token) = &self.id_token {
            let id_token_components: Vec<&str> = id_token.split('.').collect();
            let payload = id_token_components.get(1)?;

            return match base64_url::decode(payload) {
                Ok(decoded) => serde_json::from_slice::<HashMap<String, Value>>(&decoded).ok(),
                Err(_) => None,
            };
        }
        None
    }

    /// Gets the access token
    pub fn get_access_token(&self) -> Option<String> {
        self.access_token.clone()
    }

    /// Gets the access token type
    pub fn get_token_type(&self) -> Option<String> {
        self.token_type.clone()
    }

    /// Gets the raw id token
    pub fn get_id_token(&self) -> Option<String> {
        self.id_token.clone()
    }

    /// Gets the refresh token
    pub fn get_refresh_token(&self) -> Option<String> {
        self.refresh_token.clone()
    }

    /// Gets the expires in
    pub fn get_expires_in(&self) -> Option<i64> {
        self.expires_in
    }

    /// Gets the expires in (seconds)
    pub fn get_expires_at(&self) -> Option<i64> {
        self.expires_at
    }

    /// Gets the session state from OP
    pub fn get_session_state(&self) -> Option<String> {
        self.session_state.clone()
    }

    /// Gets the scope
    pub fn get_scope(&self) -> Option<String> {
        self.scope.clone()
    }

    /// Gets the other fields
    pub fn get_other(&self) -> Option<HashMap<String, Value>> {
        self.other.clone()
    }

    pub(self) fn get_expires_in_internal(&self) -> Option<i64> {
        if let Some(e) = self.expires_at {
            return Some(max((Wrapping(e) - Wrapping((self.now)())).0, 0));
        }
        None
    }

    /// Sets id_token
    pub(crate) fn set_id_token(&mut self, token: Option<String>) {
        self.id_token = token;
    }

    /// Sets session_state
    pub(crate) fn set_session_state(&mut self, session_state: Option<String>) {
        self.session_state = session_state;
    }
}

#[cfg(test)]
#[path = "./tests/tokenset_tests.rs"]
mod tokenset_tests;
