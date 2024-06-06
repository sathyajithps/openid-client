use super::{CallbackExtras, CallbackParams, OpenIDCallbackChecks};

#[derive(Default)]
/// #OpenIdCallbackParams
pub struct OpenIdCallbackParams<'a> {
    /// Redirect uri that was set in the authorize request
    pub redirect_uri: Option<&'a str>,
    /// The [CallbackParams] from the response
    pub parameters: CallbackParams,
    /// Checks for validation of openid response
    pub checks: Option<OpenIDCallbackChecks<'a>>,
    /// Extra Parameter to send to the Token endpoint
    pub extras: Option<CallbackExtras>,
}

impl<'a> OpenIdCallbackParams<'a> {
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

    /// Sets the OpenIDCallbackChecks
    pub fn checks(mut self, checks: OpenIDCallbackChecks<'a>) -> Self {
        self.checks = Some(checks);
        self
    }

    /// Sets CallbackExtras
    pub fn extras(mut self, extras: CallbackExtras) -> Self {
        self.extras = Some(extras);
        self
    }
}
