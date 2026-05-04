use std::fmt;

/// # OpenIdResponseType
///
/// Specifies what kind of response type is used in the authorization callback.
#[derive(Debug, Clone)]
pub enum OpenIdResponseType {
    /// JWT Authorized Response Mode.
    ///
    /// The callback params are sent as a jwt in the 'response' query/fragment/body.
    Jarm,
    /// Used for `code token`, `code id_token`, `code token id_token` hybrid response types.
    Hybrid,
    /// Used for `token`, `id_token` or `token id_token` response type.
    Implicit,
    /// Used for `code` response type.
    Code,
}

impl fmt::Display for OpenIdResponseType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            OpenIdResponseType::Jarm => write!(f, "jarm"),
            OpenIdResponseType::Hybrid => write!(f, "hybrid"),
            OpenIdResponseType::Implicit => write!(f, "implicit"),
            OpenIdResponseType::Code => write!(f, "code"),
        }
    }
}
