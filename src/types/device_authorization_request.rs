use std::collections::HashMap;

/// Device Authorization Request parameters as defined in RFC 8628.
///
/// Used to initiate the OAuth 2.0 Device Authorization Grant flow for devices
/// that either lack a browser or have limited input capabilities (e.g., smart TVs,
/// media consoles, printers).
pub struct DeviceAuthorizationRequest {
    /// The client identifier as described in Section 2.2 of RFC 6749.
    pub client_id: Option<String>,

    /// The scope of the access request as defined by Section 3.3 of RFC 6749.
    ///
    /// A space-separated list of scope values indicating the requested access.
    /// When `openid` is included, an ID token will be issued alongside the access token.
    pub scope: Vec<String>,
}

impl Default for DeviceAuthorizationRequest {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceAuthorizationRequest {
    /// Create a new instance.
    pub fn new() -> Self {
        Self {
            client_id: None,
            scope: vec![],
        }
    }

    /// Set the client identifier.
    pub fn set_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Add a scope to the request.
    pub fn add_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope.push(scope.into());
        self
    }
}

impl From<DeviceAuthorizationRequest> for HashMap<String, String> {
    fn from(request: DeviceAuthorizationRequest) -> Self {
        let mut map = HashMap::new();

        if let Some(client_id) = request.client_id {
            map.insert("client_id".to_owned(), client_id);
        }

        if !request.scope.is_empty() {
            map.insert("scope".to_owned(), request.scope.join(" "));
        }

        map
    }
}
