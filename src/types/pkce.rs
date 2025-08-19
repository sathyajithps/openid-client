/// # Pkce
/// Represents the Pkce
pub struct Pkce {
    /// The randomly generated PKCE code verifier
    pub verifier: String,
    /// The derived code challenge
    pub challenge: String,
}
