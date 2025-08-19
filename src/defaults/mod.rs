#[cfg(feature = "http_client")]
mod default_http_client;

#[cfg(feature = "jws_only_crypto")]
mod jws_only_crypto;

#[cfg(feature = "openssl_crypto")]
mod openssl_crypto;

#[cfg(feature = "jws_only_crypto")]
pub(crate) use jws_only_crypto::JwsOnlyCrypto as Crypto;

#[cfg(all(feature = "openssl_crypto", not(feature = "jws_only_crypto")))]
pub(crate) use openssl_crypto::OpenSSLCrypto as Crypto;
