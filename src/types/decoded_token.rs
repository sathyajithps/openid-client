use josekit::{jws::JwsHeader, jwt::JwtPayload};

#[derive(Debug)]
pub struct DecodedToken {
    pub header: JwsHeader,
    pub payload: JwtPayload,
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
