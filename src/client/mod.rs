//! # OIDC Client module
//! Contains implementation of the client

#[allow(clippy::module_inception)]
mod client;

pub(super) mod helpers;

/// Getter & Setter method implementations for Client
pub mod client_get_set;

/// Implementaion of RP Client methods
pub mod client_impl;

/// Device flow handle returned from [Client::device_authorization_async]
pub mod device_flow_handle;

pub(super) mod dpop_nonce_cache;

pub use client::Client;
pub use device_flow_handle::DeviceFlowHandle;
