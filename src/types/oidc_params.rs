use serde::Deserialize;

/// Supported client authentication methods for interacting with OIDC endpoints.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethods {
    /// No client authentication is performed.
    None,
    /// Authentication using the client secret via the HTTP Basic scheme.
    ClientSecretBasic,
    /// Authentication using the client secret sent in the request body.
    ClientSecretPost,
    /// Authentication using a JWT signed with the client secret.
    ClientSecretJwt,
    /// Authentication using a JWT signed with the client's private key.
    PrivateKeyJwt,
    /// Authentication using Mutual TLS with a CA-issued certificate.
    TlsClientAuth,
    /// Authentication using Mutual TLS with a self-signed certificate.
    SelfSignedTlsClientAuth,
}

/// Modes for delivering tokens during a Backchannel Authentication flow.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum BackChannelTokenDeliveryMode {
    /// The Client polls the token endpoint for the token.
    Pull,
    /// The OP sends a ping to the Client when the token is ready.
    Ping,
    /// The OP pushes the token directly to the Client.
    Push,
}
