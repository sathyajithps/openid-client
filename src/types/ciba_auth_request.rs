use std::collections::HashMap;

/// # CibaAuthRequest
/// CIBA Auth request parameters
/// Represents an OpenID Client-Initiated Backchannel Authentication (CIBA) request.
pub struct CibaAuthRequest {
    /// The scope of the authentication request, typically a list of space-separated strings.
    pub scope: Vec<String>,

    /// An optional token used by the client to receive asynchronous notifications.
    pub client_notification_token: Option<String>,

    /// Optional Authentication Context Class Reference values.
    pub acr_values: Option<Vec<String>>,

    /// An optional token used as a hint to identify the end-user for authentication.
    pub login_hint_token: Option<String>,

    /// An optional ID Token previously issued by the Authorization Server being passed as a hint.
    pub id_token_hint: Option<String>,

    /// An optional hint to the Authorization Server about the login identifier the End-User might use.
    pub login_hint: Option<String>,

    /// An optional message to be displayed to the user during authentication.
    pub binding_message: Option<String>,

    /// An optional user code for identifying the end-user.
    pub user_code: Option<String>,

    /// An optional requested expiry time for the authentication request in seconds.
    pub requested_expiry: Option<u64>,

    /// A map for any other additional parameters not covered by the standard fields.
    pub other: HashMap<String, String>,
}

impl Default for CibaAuthRequest {
    fn default() -> Self {
        Self::new()
    }
}

impl CibaAuthRequest {
    /// Create new instance.
    pub fn new() -> Self {
        Self {
            scope: vec![],
            client_notification_token: None,
            acr_values: None,
            login_hint_token: None,
            id_token_hint: None,
            login_hint: None,
            binding_message: None,
            user_code: None,
            requested_expiry: None,
            other: HashMap::new(),
        }
    }

    /// Add scope to the request
    pub fn add_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope.push(scope.into());
        self
    }

    /// Add acr_values to the request
    pub fn add_acr_value(mut self, acr_value: impl Into<String>) -> Self {
        self.acr_values
            .get_or_insert_with(Vec::new)
            .push(acr_value.into());
        self
    }

    /// Set the client notification token
    pub fn set_client_notification_token(mut self, token: impl Into<String>) -> Self {
        self.client_notification_token = Some(token.into());
        self
    }

    /// Set the login hint token
    pub fn set_login_hint_token(mut self, token: impl Into<String>) -> Self {
        self.login_hint_token = Some(token.into());
        self
    }

    /// Set the id token hint
    pub fn set_id_token_hint(mut self, token: impl Into<String>) -> Self {
        self.id_token_hint = Some(token.into());
        self
    }

    /// Set the login hint
    pub fn set_login_hint(mut self, hint: impl Into<String>) -> Self {
        self.login_hint = Some(hint.into());
        self
    }

    /// Set the binding message
    pub fn set_binding_message(mut self, message: impl Into<String>) -> Self {
        self.binding_message = Some(message.into());
        self
    }

    /// Set the user code
    pub fn set_user_code(mut self, code: impl Into<String>) -> Self {
        self.user_code = Some(code.into());
        self
    }

    /// Set expiry in seconds
    pub fn set_requested_expiry(mut self, expiry: u64) -> Self {
        self.requested_expiry = Some(expiry);
        self
    }

    /// Add additional body parameter to be sent
    pub fn add_request_body_param(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.other.insert(key.into(), value.into());
        self
    }
}
