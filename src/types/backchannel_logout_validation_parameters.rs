/// Parameters for validating a Backchannel Logout Token.
pub struct BackchannelLogoutValidationParameters {
    /// Expected subject identifier (`sub`). If provided, the token's `sub` claim is validated against this.
    pub expected_sub: Option<String>,
    /// Expected session identifier (`sid`). If provided, the token's `sid` claim is validated against this.
    pub expected_sid: Option<String>,
    /// Expected event types to be verified. If provided, checks that these event URIs are present and are JSON objects.
    /// If not provided, defaults to validating only the standard `http://schemas.openid.net/event/backchannel-logout` event.
    pub expected_events: Option<Vec<String>>,
}

impl BackchannelLogoutValidationParameters {
    /// Creates a new instance with default parameters.
    pub fn new() -> Self {
        Self {
            expected_sub: None,
            expected_sid: None,
            expected_events: None,
        }
    }

    /// Sets the expected subject identifier.
    pub fn expected_sub(mut self, sub: impl Into<String>) -> Self {
        self.expected_sub = Some(sub.into());
        self
    }

    /// Sets the expected session identifier.
    pub fn expected_sid(mut self, sid: impl Into<String>) -> Self {
        self.expected_sid = Some(sid.into());
        self
    }

    /// Sets the expected events to be verified.
    pub fn expected_events(mut self, events: Vec<String>) -> Self {
        self.expected_events = Some(events);
        self
    }
}

impl Default for BackchannelLogoutValidationParameters {
    fn default() -> Self {
        Self::new()
    }
}
