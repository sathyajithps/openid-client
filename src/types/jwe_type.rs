/// # JweType
/// Represents the JweType
pub enum JweType {
    /// JARM (JWT Secured Authorization Response Mode) response
    Jarm,
    /// UserInfo response
    Userinfo,
    /// ID Token
    IdToken,
    /// Introspection response
    Introspection,
    /// Request object
    RequestObject,
    /// Other unclassified JWE type
    Other,
}
