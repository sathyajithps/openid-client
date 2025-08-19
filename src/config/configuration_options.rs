/// Default clock skew
pub const DEFAULT_CLOCK_SKEW: i32 = 0;
/// Default clock tolerance
pub const DEFAULT_CLOCK_TOLERANCE: u32 = 300;

/// # ConfigurationOptions
/// Represents the ConfigurationOptions
#[derive(Debug, Clone)]
pub struct ConfigurationOptions {
    /// If `true` skips validation of authentication methods supported
    pub skip_auth_checks: bool,
    /// Adds client_id to the request (body or url) if the client auth is ClientAuth::None
    pub add_client_id_to_request: bool,
    /// Skew in seconds used to adjust the current time
    pub clock_skew: i32,
    /// Allowed clock tolerance in seconds while checking jwt date time claims
    pub clock_tolerance: u32,
}

impl Default for ConfigurationOptions {
    fn default() -> Self {
        Self {
            skip_auth_checks: false,
            add_client_id_to_request: false,
            clock_skew: DEFAULT_CLOCK_SKEW,
            clock_tolerance: DEFAULT_CLOCK_TOLERANCE,
        }
    }
}
