#![warn(missing_docs)]
#![doc(html_logo_url = "https://i.ibb.co/d49gz0F/oidc.png")]
#![doc(html_favicon_url = "https://i.ibb.co/1TNK5bY/oidc-1.png")]
//! # OpenID Client
//!
//! This crate is an OpenID Connect RP library based on an openid client by [panva](https://github.com/panva)
//! called [openid-client](https://github.com/panva/node-openid-cient)
//!
//! ## Issuer API
//!
//! - New Instance API:
//!     - [Issuer::new]
//!
//! - Well known Discovery API:
//!     - [Issuer::discover]
//!     - [Issuer::discover_with_interceptor]
//!     - [Issuer::discover_async]
//!     - [Issuer::discover_with_interceptor_async]
//!
//! - Webfinger Discovery API:
//!     - [Issuer::webfinger]
//!     - [Issuer::webfinger_with_interceptor]
//!     - [Issuer::webfinger_async]
//!     - [Issuer::webfinger_with_interceptor_async]
//!
//!

mod helpers;
mod http;
mod issuer;
mod tests;
mod types;

pub use issuer::{Issuer, RequestInterceptor};
pub use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
pub use types::{
    IssuerMetadata, MtlsEndpoints, OidcClientError, Request, RequestOptions, Response,
    WebFingerResponse,
};
