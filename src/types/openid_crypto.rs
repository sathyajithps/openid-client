#![allow(missing_docs)]

use crate::{
    jwk::Jwk,
    types::{header::Header, payload::Payload},
};

/// A trait for pluggable cryptographic operations in the OpenID Client SDK.
///
/// This trait allows users of the SDK to provide their own cryptographic backend
/// for handling JSON Web Encryption (JWE) and JSON Web Signature (JWS) operations.
/// By implementing this trait, you can customize how payloads are encrypted, decrypted,
/// signed, and verified using your preferred cryptographic libraries or hardware.
pub trait OpenIdCrypto {
    #[allow(unused)]
    fn jwe_serialize(&self, payload: String, header: Header, jwk: &Jwk) -> Result<String, String>;

    fn jwe_deserialize(&self, jwe: String, jwk: &Jwk) -> Result<String, String>;

    fn jws_serialize(&self, payload: Payload, header: Header, jwk: &Jwk) -> Result<String, String>;

    fn jws_deserialize(&self, jws: String, jwk: &Jwk) -> Result<(Header, Payload), String>;
}
