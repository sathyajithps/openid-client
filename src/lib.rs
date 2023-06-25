#![warn(missing_docs)]
#![doc(html_logo_url = "https://i.ibb.co/d49gz0F/oidc.png")]
#![doc(html_favicon_url = "https://i.ibb.co/1TNK5bY/oidc-1.png")]
//! # OpenID Client
//!
//! # WORK IN PROGRESS. DO NOT USE
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
//!     - [Issuer::discover_async]
//!
//! - Webfinger Discovery API:
//!     - [Issuer::webfinger]
//!     - [Issuer::webfinger_async]
//! - Client from Issuer API
//!     - [Issuer::client]
//!
//! ## Client API
//!
//! - Client Read
//!     - [Client::from_uri]
//!     - [Client::from_uri_async]
//!
//! - Dynamic Client Registration
//!     - [Client::register]
//!     - [Client::register_async]

mod client;
mod helpers;
mod http;
mod issuer;
mod tests;
mod types;

pub use client::Client;
pub use issuer::Issuer;
pub use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
pub use serde_json::{json, Value};
pub use types::{
    ClientMetadata, ClientOptions, IssuerMetadata, Jwk, Jwks, MtlsEndpoints, OidcClientError,
    Request, RequestInterceptor, RequestOptions, Response, WebFingerResponse,
};
