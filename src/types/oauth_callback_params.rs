use super::{CallbackExtras, CallbackParams, OAuthCallbackChecks};

#[derive(Default)]
/// #OAuthCallbackParams
pub struct OAuthCallbackParams<'a> {
    /// Redirect uri that was set in the oauth authorize request
    pub redirect_uri: Option<&'a str>,
    /// The [CallbackParams] from the response
    pub parameters: CallbackParams,
    /// Checks for validation of oauth response
    pub checks: Option<OAuthCallbackChecks<'a>>,
    /// Extra Parameter to send to the Token endpoint
    pub extras: Option<CallbackExtras>,
}

impl<'a> OAuthCallbackParams<'a> {
    /// Sets the redirect uri
    pub fn redirect_uri(mut self, redirect_uri: &'a str) -> Self {
        self.redirect_uri = Some(redirect_uri);
        self
    }

    /// Sets the CallbackParams
    pub fn parameters(mut self, parameters: CallbackParams) -> Self {
        self.parameters = parameters;
        self
    }

    /// Sets the OAuthCallbackChecks
    pub fn checks(mut self, checks: OAuthCallbackChecks<'a>) -> Self {
        self.checks = Some(checks);
        self
    }

    /// Sets CallbackExtras
    pub fn extras(mut self, extras: CallbackExtras) -> Self {
        self.extras = Some(extras);
        self
    }
}
