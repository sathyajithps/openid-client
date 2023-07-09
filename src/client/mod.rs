//! # OIDC Client module
//! Contains implementation of the client

#[allow(clippy::module_inception)]
mod client;

/// Getter & Setter method implementations for Client
pub mod client_get_set;

/// Implementaion of RP Client methods
pub mod client_impl;

pub use client::Client;
