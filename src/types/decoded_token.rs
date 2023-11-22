use josekit::{jws::JwsHeader, jwt::JwtPayload};

/// # DecodedToken
/// The decoded jwt token
#[derive(Debug)]
pub struct DecodedToken {
    /// See [josekit::jws::JwsHeader]
    pub header: JwsHeader,
    /// See [josekit::jwt::JwtPayload]
    pub payload: JwtPayload,
    /// Signature of jwt
    pub signature: String,
}

impl Default for DecodedToken {
    fn default() -> Self {
        Self {
            header: JwsHeader::new(),
            payload: Default::default(),
            signature: Default::default(),
        }
    }
}
