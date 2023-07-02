/// # Client Options
#[derive(Default, Clone, Debug)]
pub struct ClientOptions {
    /// [Authorized Party](https://openid.net/specs/openid-connect-core-1_0.html#IDToken)
    pub additional_authorized_parties: Option<Vec<String>>,
}
