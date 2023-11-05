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
//! ### New Instance
//!    
//! - [issuer::Issuer::new]
//!
//! ### OIDC Discovery
//! - [issuer::Issuer::discover_async]
//!
//! ### Webfinger Discovery
//! - [issuer::Issuer::webfinger_async]
//!
//! ### Client from Issuer
//! - [issuer::Issuer::client]
//!
//! ## Client
//!
//! ### Instance methods
//! - [client::Client::callback_async]
//! - [client::Client::oauth_callback_async]
//! - [client::Client::grant_async]
//! - [client::Client::authorization_url]
//! - [client::Client::end_session_url]
//! - [client::Client::authorization_post]
//! - [client::Client::introspect_async]
//! - [client::Client::callback_params]
//! - [client::Client::request_resource_async]
//! - [client::Client::refresh_async]
//! - [client::Client::revoke_async]
//! - [client::Client::userinfo_async]
//! - [client::Client::request_object_async]
//! - [client::Client::pushed_authorization_request_async]
//! - [client::Client::device_authorization_async]
//!
//! ### Client Read
//! - [client::Client::from_uri_async]
//!
//! ### Dynamic Client Registration
//! - [client::Client::register_async]

pub mod client;
mod helpers;
mod http;
pub mod issuer;
pub mod jwks;
mod tests;
/// TokenSet Module
pub mod tokenset;
pub mod types;

/// Re exports from the crate
pub mod re_exports {
    pub use josekit::{self};
    pub use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
    pub use serde_json::{self, json, Value};
    pub use url;
}
