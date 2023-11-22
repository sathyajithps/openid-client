use std::collections::HashMap;

/// # EndSessionParameters
/// Parameters for customizing [`crate::client::Client::end_session_url()`]
#[derive(Debug, Default)]
pub struct EndSessionParameters {
    /// [Id token hint](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout)
    pub id_token_hint: Option<String>,
    /// Url that the OP should redirect to after logout
    pub post_logout_redirect_uri: Option<String>,
    /// [State](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout)
    pub state: Option<String>,
    /// [Client Id](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout)
    pub client_id: Option<String>,
    /// [Logout hint](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout)
    pub logout_hint: Option<String>,
    /// Other fields
    pub other: Option<HashMap<String, String>>,
}
