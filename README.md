# OpenID Client

A feature complete OpenID Client library for Rust. Not stable, kindly report any bugs.

**TODO**
- Code cleanup
- Thin up a lot of inefficient decisions made for the sake of completion of the library
- Test out the ported features
- Add more features


## Implemented specs & features

The following client/RP features from OpenID Connect/OAuth2.0 specifications are implemented by
openid-client.

- [OpenID Connect Core 1.0][feature-core]
  - Authorization Callback
    - Authorization Code Flow
    - Implicit Flow
    - Hybrid Flow
  - UserInfo Request
  - Offline Access / Refresh Token Grant
  - Client Credentials Grant
  - Client Authentication
    - none
    - client_secret_basic
    - client_secret_post
    - client_secret_jwt
    - private_key_jwt
  - Consuming Self-Issued OpenID Provider ID Token response
- [OpenID Connect Discovery 1.0][feature-discovery]
  - Discovery of OpenID Provider (Issuer) Metadata
  - Discovery of OpenID Provider (Issuer) Metadata via user provided inputs (via [webfinger][documentation-webfinger])
- [OpenID Connect Dynamic Client Registration 1.0][feature-registration]
  - Dynamic Client Registration request
  - Client initialization via registration client uri
- [RFC7009 - OAuth 2.0 Token revocation][feature-revocation]
  - Client Authenticated request to token revocation
- [RFC7662 - OAuth 2.0 Token introspection][feature-introspection]
  - Client Authenticated request to token introspection
- [RFC8628 - OAuth 2.0 Device Authorization Grant (Device Flow)][feature-device-flow]
- [RFC8705 - OAuth 2.0 Mutual TLS Client Authentication and Certificate-Bound Access Tokens][feature-mtls]
  - Mutual TLS Client Certificate-Bound Access Tokens
  - Metadata for Mutual TLS Endpoint Aliases
  - Client Authentication
    - tls_client_auth
    - self_signed_tls_client_auth
- [RFC9101 - OAuth 2.0 JWT-Secured Authorization Request (JAR)][feature-jar]
- [RFC9126 - OAuth 2.0 Pushed Authorization Requests (PAR)][feature-par]
- [RFC9449 - OAuth 2.0 Demonstration of Proof-of-Possession at the Application Layer (DPoP)][feature-dpop]
- [OpenID Connect RP-Initiated Logout 1.0][feature-rp-logout]
- [Financial-grade API Security Profile 1.0 - Part 2: Advanced (FAPI)][feature-fapi]
- [JWT Secured Authorization Response Mode for OAuth 2.0 (JARM)][feature-jarm]
- [OAuth 2.0 Authorization Server Issuer Identification][feature-iss]

## Documentation

[Documentation](https://docs.rs/openid-client)

## Alternatives

-   [openidconnect](https://crates.io/crates/openidconnect)
-   [openid](https://crates.io/crates/openid)

[openid-connect]: https://openid.net/connect/
[feature-core]: https://openid.net/specs/openid-connect-core-1_0.html
[feature-discovery]: https://openid.net/specs/openid-connect-discovery-1_0.html
[feature-registration]: https://openid.net/specs/openid-connect-registration-1_0.html
[feature-revocation]: https://tools.ietf.org/html/rfc7009
[feature-introspection]: https://tools.ietf.org/html/rfc7662
[feature-mtls]: https://tools.ietf.org/html/rfc8705
[feature-device-flow]: https://tools.ietf.org/html/rfc8628
[feature-rp-logout]: https://openid.net/specs/openid-connect-rpinitiated-1_0.html
[feature-jarm]: https://openid.net/specs/oauth-v2-jarm.html
[feature-fapi]: https://openid.net/specs/openid-financial-api-part-2-1_0.html
[feature-dpop]: https://www.rfc-editor.org/rfc/rfc9449.html
[feature-par]: https://www.rfc-editor.org/rfc/rfc9126.html
[feature-jar]: https://www.rfc-editor.org/rfc/rfc9101.html
[feature-iss]: https://www.rfc-editor.org/rfc/rfc9207.html