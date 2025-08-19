#![warn(missing_docs)]
#![doc(html_logo_url = "https://i.ibb.co/d49gz0F/oidc.png")]
#![doc(html_favicon_url = "https://i.ibb.co/1TNK5bY/oidc-1.png")]

//! # OpenID Client
//!
//! Async, runtime-agnostic OpenID Connect / OAuth 2.0 client helpers for Rust.
//!
//! The current source tree centers on [`client::Client`] plus configuration, metadata, token,
//! JOSE, and HTTP integration types. The crate is still under active refactoring, so the public
//! API should be treated as unstable.
//!
//! ## What The Crate Covers
//!
//! [`client::Client`] currently provides helpers for:
//! - discovery: [`client::Client::discover_oidc_async`],
//!   [`client::Client::discover_oauth_async`], [`client::Client::webfinger_async`],
//!   [`client::Client::fetch_issuer_jwks`]
//! - authorization request construction: [`client::Client::authorization_url`],
//!   [`client::Client::authorization_post`], [`client::Client::endsession_url`],
//!   [`client::Client::pushed_authorization_request`], [`client::Client::request_object`]
//! - authorization response handling: [`client::Client::authorization_code_grant`],
//!   [`client::Client::implicit_authentication`], hybrid response validation, and JARM validation
//!   through [`config::OpenIdClientConfiguration`]
//! - token operations: [`client::Client::grant_async`], [`client::Client::refresh_grant`],
//!   [`client::Client::client_credentials_grant`], [`client::Client::device_code_grant`],
//!   [`client::Client::ciba_grant`], [`client::Client::token_exchange_async`]
//! - resource and account endpoints: [`client::Client::userinfo_async`],
//!   [`client::Client::request_resource_async`], [`client::Client::introspect_async`],
//!   [`client::Client::revoke_async`]
//! - dynamic client registration: [`client::Client::register`] and [`client::Client::from_uri`]
//!
//! Supporting modules include:
//! - [`config`] for client auth, DPoP, clock skew/tolerance, and assembled client configuration
//! - [`types`] for request builders, metadata models, JOSE enums, and the custom HTTP client trait
//! - [`jwk`] and [`token_set`] for key and token helpers
//! - [`errors`] for client, protocol, and OP error types
//!
//! ## Feature Support
//!
//! The current tree implements:
//!
//! - [OpenID Connect Core 1.0][feature-core]
//!   - authorization code, implicit, and hybrid response validation
//!   - UserInfo requests, including JWT responses when configured
//!   - refresh token and client credentials grants
//!   - client authentication via `none`, `client_secret_basic`, `client_secret_post`,
//!     `client_secret_jwt`, and `private_key_jwt`
//! - [OpenID Connect Discovery 1.0][feature-discovery] and [RFC 8414][feature-rfc8414]
//!   - issuer discovery
//!   - WebFinger-based issuer discovery
//!   - JWKS fetch from `jwks_uri`
//! - [OpenID Connect Dynamic Client Registration 1.0][feature-registration]
//!   - dynamic registration requests and responses
//!   - `registration_client_uri` fetch via [`client::Client::from_uri`]
//! - [RFC 7009][feature-revocation] token revocation
//! - [RFC 7662][feature-introspection] token introspection
//! - [RFC 8628][feature-device-flow] device authorization and device code grant
//! - [RFC 8693][feature-token-exchange] generic token exchange helper with required response
//!   field validation
//! - [RFC 8705][feature-mtls]
//!   - mTLS endpoint aliases
//!   - certificate-bound access tokens
//!   - `tls_client_auth` and `self_signed_tls_client_auth`
//! - [OpenID Connect Client Initiated Backchannel Authentication Flow - Core 1.0][feature-ciba]
//!   - backchannel authentication requests
//!   - CIBA polling grant
//! - [RFC 9101][feature-jar] signed request objects
//! - [RFC 9126][feature-par] pushed authorization requests
//! - [RFC 9207][feature-iss] authorization response issuer validation
//! - [JWT Secured Authorization Response Mode for OAuth 2.0][feature-jarm]
//! - [RFC 9449][feature-dpop]
//!   - DPoP proof generation
//!   - nonce extraction and caching
//!   - DPoP-bound token and resource requests
//! - [OpenID Connect RP-Initiated Logout 1.0][feature-rp-logout]
//! - FAPI-oriented helpers such as `fapi` request object shaping and hybrid `s_hash` checks
//!
//! ## Crypto And HTTP Backends
//!
//! This crate is transport-agnostic. Implement [`types::http_client::OidcHttpClient`] to use your
//! own async HTTP stack, or enable the `http_client` feature to use the bundled reqwest-based
//! client.
//!
//! Two optional crypto backends are present in the source tree:
//! - `jws_only_crypto` signs and verifies JWS values, but does not support JWE.
//! - `openssl_crypto` uses Josekit for both JWS and JWE operations.
//!
//! Important: the current default feature set enables both backends, and the crate selects
//! `jws_only_crypto` whenever it is present. If you need encrypted ID tokens, encrypted UserInfo
//! or JARM responses, or other JWE-dependent flows, build without default features and enable
//! `openssl_crypto` explicitly.
//!
//! ## Current Limitations
//!
//! - [`client::Client::request_object`] only creates signed or unsigned request objects; request
//!   object encryption is not implemented yet.
//! - JWE-dependent flows require an OpenSSL/Josekit-backed build and a populated
//!   [`config::OpenIdClientConfiguration::jwe_keys`] set.
//!
//! ## JWKs And Certificates
//!
//! The crate includes a lightweight [`jwk::Jwk`] model with helpers for structural validation,
//! public/private key extraction, DPoP keys, JWT client authentication, and JWE decryption keys.
//!
//! For mTLS, either use the bundled HTTP client or implement
//! [`types::http_client::OidcHttpClient::get_client_certificate`] so certificate-bound requests
//! can attach a PEM certificate chain and PKCS#8 private key.
//!
//! ## Useful Types
//!
//! Commonly used request, configuration, and response types include:
//! - [`config::ClientAuth`], [`config::ConfigurationOptions`],
//!   [`config::OpenIdClientConfiguration`], [`config::DPoPOptions`]
//! - [`types::AuthorizationParameters`], [`types::AuthorizationCodeGrantParameters`],
//!   [`types::ImplicitGrantParameters`], [`types::EndSessionParameters`]
//! - [`types::DeviceAuthorizationRequest`], [`types::DeviceAuthorizationResponse`],
//!   [`types::CibaAuthRequest`], [`types::CibaAuthResponse`]
//! - [`types::ClientMetadata`], [`types::IssuerMetadata`],
//!   [`types::ClientRegistrationRequest`], [`types::ClientRegistrationResponse`]
//! - [`token_set::TokenSet`], [`types::Pkce`], [`types::UserinfoTokenLocation`]
//!
//! [openid-connect]: https://openid.net/connect/
//! [feature-core]: https://openid.net/specs/openid-connect-core-1_0.html
//! [feature-discovery]: https://openid.net/specs/openid-connect-discovery-1_0.html
//! [feature-registration]: https://openid.net/specs/openid-connect-registration-1_0.html
//! [feature-revocation]: https://tools.ietf.org/html/rfc7009
//! [feature-introspection]: https://tools.ietf.org/html/rfc7662
//! [feature-mtls]: https://tools.ietf.org/html/rfc8705
//! [feature-device-flow]: https://tools.ietf.org/html/rfc8628
//! [feature-token-exchange]: https://tools.ietf.org/html/rfc8693
//! [feature-ciba]: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html
//! [feature-rp-logout]: https://openid.net/specs/openid-connect-rpinitiated-1_0.html
//! [feature-jarm]: https://openid.net/specs/oauth-v2-jarm.html
//! [feature-dpop]: https://www.rfc-editor.org/rfc/rfc9449.html
//! [feature-par]: https://www.rfc-editor.org/rfc/rfc9126.html
//! [feature-jar]: https://www.rfc-editor.org/rfc/rfc9101.html
//! [feature-iss]: https://www.rfc-editor.org/rfc/rfc9207.html
//! [feature-rfc8414]: https://www.rfc-editor.org/rfc/rfc8414.html

/// High-level OpenID Connect and OAuth 2.0 client operations.
pub mod client;
/// JWT, JWE, and authorization response validation helpers.
pub mod client_utils;
/// Client authentication, DPoP, and assembled client configuration types.
pub mod config;
/// Feature-gated default crypto and HTTP client implementations.
pub mod defaults;
/// Error types returned by the crate.
pub mod errors;
/// Shared helper utilities used across the crate.
pub mod helpers;
/// Internal HTTP request orchestration and response expectation handling.
pub mod http;
/// JSON Web Key types and key-manipulation helpers.
pub mod jwk;
/// Token response model and token claim helpers.
pub mod token_set;
/// Request builders, metadata models, JOSE enums, and HTTP integration types.
pub mod types;
