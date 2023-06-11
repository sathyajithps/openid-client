//! # Issuer struct contains the discovered OpenID Connect Issuer Metadata.

#[allow(clippy::module_inception)]
mod issuer;
mod jwks;

pub use issuer::Issuer;
