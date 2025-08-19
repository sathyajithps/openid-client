# OpenID Client

Async, runtime-agnostic OpenID Connect / OAuth 2.0 client helpers for Rust. Currently being
refactored, so the public API is still evolving.

## Usage

- Documentation: <https://docs.rs/openid-client>
- Examples: <https://github.com/sathyajithps/openid-client-examples>

## What Is Currently Implemented

The current tree includes helpers for:

- discovery: OIDC discovery, OAuth authorization server discovery, WebFinger lookup, and JWKS fetch
- authorization requests: authorization URLs, HTML form-post requests, PAR, request objects, and RP-initiated logout URLs
- callback and token flows: authorization code, implicit, hybrid, JARM, refresh token, and client credentials
- protected endpoints: UserInfo, generic resource requests, introspection, and revocation
- extension flows: device authorization, CIBA, token exchange, DPoP, and mTLS endpoint aliases
- dynamic client registration: registration plus `registration_client_uri` fetch

Supporting modules expose request builders, metadata types, JOSE helpers, JWK utilities, token
helpers, and a custom async HTTP client trait.

## Specs And Features

- [OpenID Connect Core 1.0][feature-core]
  - authorization code, implicit, and hybrid response validation
  - UserInfo requests, including JWT responses when configured
  - refresh token and client credentials grants
  - client authentication via `none`, `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, and `private_key_jwt`
- [OpenID Connect Discovery 1.0][feature-discovery] and [RFC 8414][feature-rfc8414]
  - issuer discovery
  - WebFinger-based issuer discovery
  - JWKS fetch from `jwks_uri`
- [OpenID Connect Dynamic Client Registration 1.0][feature-registration]
  - dynamic registration requests and responses
  - `registration_client_uri` fetch
- [RFC 7009][feature-revocation] token revocation
- [RFC 7662][feature-introspection] token introspection
- [RFC 8628][feature-device-flow] device authorization and device code grant
- [RFC 8693][feature-token-exchange] generic token exchange helper with required response-field validation
- [RFC 8705][feature-mtls]
  - mTLS endpoint aliases
  - certificate-bound access tokens
  - `tls_client_auth` and `self_signed_tls_client_auth`
- [OpenID Connect Client Initiated Backchannel Authentication Flow - Core 1.0][feature-ciba]
  - backchannel authentication requests
  - CIBA polling grant
- [RFC 9101][feature-jar] signed request objects
- [RFC 9126][feature-par] pushed authorization requests
- [RFC 9207][feature-iss] authorization response issuer validation
- [JWT Secured Authorization Response Mode for OAuth 2.0][feature-jarm]
- [RFC 9449][feature-dpop]
  - DPoP proof generation
  - nonce extraction and caching
  - DPoP-bound token and resource requests
- [OpenID Connect RP-Initiated Logout 1.0][feature-rp-logout]
- FAPI-oriented helpers such as `fapi` request object shaping and hybrid `s_hash` checks

## Crypto And HTTP Backend Notes

This crate is transport-agnostic. Implement the custom HTTP client trait if you want to bring your
own async HTTP stack, or enable the bundled reqwest client with the `http_client` feature.

Two optional crypto backends exist:

- `jws_only_crypto`: JWS signing and verification only, no JWE support
- `openssl_crypto`: JWS and JWE support via Josekit

Important: the current default feature set enables both backends, and the crate selects
`jws_only_crypto` whenever it is present. If you need encrypted ID tokens, encrypted UserInfo or
JARM responses, or other JWE-dependent flows, use `openssl_crypto` without default features:

## Current Limitations

- Request object encryption is not implemented yet; `Client::request_object` only creates signed or unsigned request objects.
- JWE-dependent flows require an OpenSSL/Josekit-backed build and configured decryption keys.

## Support

Issues and pull requests are welcome: <https://github.com/sathyajithps/openid-client>

## Alternatives

- [openidconnect](https://crates.io/crates/openidconnect)
- [openid](https://crates.io/crates/openid)

[openid-connect]: https://openid.net/connect/
[feature-core]: https://openid.net/specs/openid-connect-core-1_0.html
[feature-discovery]: https://openid.net/specs/openid-connect-discovery-1_0.html
[feature-registration]: https://openid.net/specs/openid-connect-registration-1_0.html
[feature-revocation]: https://tools.ietf.org/html/rfc7009
[feature-introspection]: https://tools.ietf.org/html/rfc7662
[feature-mtls]: https://tools.ietf.org/html/rfc8705
[feature-device-flow]: https://tools.ietf.org/html/rfc8628
[feature-token-exchange]: https://tools.ietf.org/html/rfc8693
[feature-ciba]: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html
[feature-rp-logout]: https://openid.net/specs/openid-connect-rpinitiated-1_0.html
[feature-jarm]: https://openid.net/specs/oauth-v2-jarm.html
[feature-dpop]: https://www.rfc-editor.org/rfc/rfc9449.html
[feature-par]: https://www.rfc-editor.org/rfc/rfc9126.html
[feature-jar]: https://www.rfc-editor.org/rfc/rfc9101.html
[feature-iss]: https://www.rfc-editor.org/rfc/rfc9207.html
[feature-rfc8414]: https://www.rfc-editor.org/rfc/rfc8414.html
