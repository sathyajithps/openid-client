//! # OIDC Client module
//! Contains implementation of the client

#[allow(clippy::module_inception)]
mod client;

pub(super) mod helpers;

/// Implementaion of RP Client methods
pub mod client_impl;

/// Device flow handle returned from [Client::device_authorization_async]
pub mod device_flow_handle;

/// CIBA handle
pub mod ciba_handle;

pub(super) mod dpop_nonce_cache;

mod validate_id_token_params;

pub use ciba_handle::CibaHandle;
pub use client::Client;
pub use device_flow_handle::DeviceFlowHandle;
