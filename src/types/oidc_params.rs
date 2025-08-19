use serde::{Deserialize, Serialize};

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

/// JSON Web Signature (JWS) algorithms used for signing JWTs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum JwtSigningAlg {
    /// HMAC using SHA-256.
    HS256,
    /// HMAC using SHA-384.
    HS384,
    /// HMAC using SHA-512.
    HS512,
    /// RSASSA-PKCS1-v1_5 using SHA-256.
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384.
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-512.
    RS512,
    /// ECDSA using P-256 and SHA-256.
    ES256,
    /// ECDSA using P-384 and SHA-384.
    ES384,
    /// ECDSA using P-521 and SHA-512.
    ES512,
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
    PS256,
    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384.
    PS384,
    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512.
    PS512,
    /// Edwards-curve Digital Signature Algorithm (Ed25519 or Ed448).
    #[serde(rename = "EdDSA")]
    EdDSA,
    /// ECDSA using secp256k1 curve and SHA-256.
    ES256K,
}

impl JwtSigningAlg {
    /// Parses a string into the corresponding [JwtSigningAlg] variant.
    pub fn from_alg_str(alg: &str) -> Option<Self> {
        match alg {
            "HS256" => Some(Self::HS256),
            "HS384" => Some(Self::HS384),
            "HS512" => Some(Self::HS512),
            "RS256" => Some(Self::RS256),
            "RS384" => Some(Self::RS384),
            "RS512" => Some(Self::RS512),
            "ES256" => Some(Self::ES256),
            "ES384" => Some(Self::ES384),
            "ES512" => Some(Self::ES512),
            "PS256" => Some(Self::PS256),
            "PS384" => Some(Self::PS384),
            "PS512" => Some(Self::PS512),
            "EdDSA" => Some(Self::EdDSA),
            "ES256K" => Some(Self::ES256K),
            _ => None,
        }
    }
}

/// Signing algorithms supported for client authentication at the Token endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TokenEndpointAuthSigningAlg {
    /// HMAC using SHA-256.
    HS256,
    /// HMAC using SHA-384.
    HS384,
    /// HMAC using SHA-512.
    HS512,
    /// RSASSA-PKCS1-v1_5 using SHA-256.
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384.
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-512.
    RS512,
    /// ECDSA using P-256 and SHA-256.
    ES256,
    /// ECDSA using P-384 and SHA-384.
    ES384,
    /// ECDSA using P-521 and SHA-512.
    ES512,
    /// RSASSA-PSS using SHA-256.
    PS256,
    /// RSASSA-PSS using SHA-384.
    PS384,
    /// RSASSA-PSS using SHA-512.
    PS512,
    /// Edwards-curve Digital Signature Algorithm.
    #[serde(rename = "EdDSA")]
    EdDSA,
    /// ECDSA using secp256k1.
    ES256K,
}

/// Signing algorithms supported for client authentication at the Introspection endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum IntrospectionEndpointAuthSigningAlg {
    /// HMAC using SHA-256.
    HS256,
    /// HMAC using SHA-384.
    HS384,
    /// HMAC using SHA-512.
    HS512,
    /// RSASSA-PKCS1-v1_5 using SHA-256.
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384.
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-512.
    RS512,
    /// ECDSA using P-256 and SHA-256.
    ES256,
    /// ECDSA using P-384 and SHA-384.
    ES384,
    /// ECDSA using P-521 and SHA-512.
    ES512,
    /// RSASSA-PSS using SHA-256.
    PS256,
    /// RSASSA-PSS using SHA-384.
    PS384,
    /// RSASSA-PSS using SHA-512.
    PS512,
    /// Edwards-curve Digital Signature Algorithm.
    #[serde(rename = "EdDSA")]
    EdDSA,
    /// ECDSA using secp256k1.
    ES256K,
}

/// Signing algorithms supported for client authentication at the Revocation endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RevocationEndpointAuthSigningAlg {
    /// HMAC using SHA-256.
    HS256,
    /// HMAC using SHA-384.
    HS384,
    /// HMAC using SHA-512.
    HS512,
    /// RSASSA-PKCS1-v1_5 using SHA-256.
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384.
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-512.
    RS512,
    /// ECDSA using P-256 and SHA-256.
    ES256,
    /// ECDSA using P-384 and SHA-384.
    ES384,
    /// ECDSA using P-521 and SHA-512.
    ES512,
    /// RSASSA-PSS using SHA-256.
    PS256,
    /// RSASSA-PSS using SHA-384.
    PS384,
    /// RSASSA-PSS using SHA-512.
    PS512,
    /// Edwards-curve Digital Signature Algorithm.
    #[serde(rename = "EdDSA")]
    EdDSA,
    /// ECDSA using secp256k1.
    ES256K,
}

/// Algorithms supported for signing DPoP (Demonstrating Proof-of-Possession) proofs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DpopSigningAlg {
    /// RSASSA-PKCS1-v1_5 using SHA-256.
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384.
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-512.
    RS512,
    /// RSASSA-PSS using SHA-256.
    PS256,
    /// RSASSA-PSS using SHA-384.
    PS384,
    /// RSASSA-PSS using SHA-512.
    PS512,
    /// ECDSA using P-256 and SHA-256.
    ES256,
    /// ECDSA using P-384 and SHA-384.
    ES384,
    /// ECDSA using P-521 and SHA-512.
    ES512,
    /// Edwards-curve Digital Signature Algorithm.
    #[serde(rename = "EdDSA")]
    EdDSA,
    /// ECDSA using secp256k1.
    ES256K,
}

/// Algorithms supported for signing Backchannel Authentication requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum BackchannelAuthenticationRequestSigningAlg {
    /// RSASSA-PKCS1-v1_5 using SHA-256.
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384.
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-512.
    RS512,
    /// RSASSA-PSS using SHA-256.
    PS256,
    /// RSASSA-PSS using SHA-384.
    PS384,
    /// RSASSA-PSS using SHA-512.
    PS512,
    /// ECDSA using P-256 and SHA-256.
    ES256,
    /// ECDSA using P-384 and SHA-384.
    ES384,
    /// ECDSA using P-521 and SHA-512.
    ES512,
    /// Edwards-curve Digital Signature Algorithm.
    #[serde(rename = "EdDSA")]
    EdDSA,
    /// ECDSA using secp256k1.
    ES256K,
}

/// JSON Web Encryption (JWE) algorithms for key management.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JweAlg {
    /// RSAES-PKCS1-v1_5.
    #[serde(rename = "RSA1_5")]
    RSA1_5,
    /// RSAES OAEP using SHA-1 and MGF1 with SHA-1.
    #[serde(rename = "RSA-OAEP")]
    RsaOaep,
    /// RSAES OAEP using SHA-256 and MGF1 with SHA-256.
    #[serde(rename = "RSA-OAEP-256")]
    RsaOaep256,
    /// AES Key Wrap with 128-bit key.
    #[serde(rename = "A128KW")]
    A128Kw,
    /// AES Key Wrap with 192-bit key.
    #[serde(rename = "A192KW")]
    A192Kw,
    /// AES Key Wrap with 256-bit key.
    #[serde(rename = "A256KW")]
    A256Kw,
    /// Direct use of a shared symmetric key as the CEK.
    #[serde(rename = "dir")]
    Dir,
    /// Elliptic Curve Diffie-Hellman Ephemeral Static key agreement.
    #[serde(rename = "ECDH-ES")]
    EcdhEs,
    /// ECDH-ES with key wrapping using AES Key Wrap 128-bit.
    #[serde(rename = "ECDH-ES+A128KW")]
    EcdhEsA128Kw,
    /// ECDH-ES with key wrapping using AES Key Wrap 192-bit.
    #[serde(rename = "ECDH-ES+A192KW")]
    EcdhEsA192Kw,
    /// ECDH-ES with key wrapping using AES Key Wrap 256-bit.
    #[serde(rename = "ECDH-ES+A256KW")]
    EcdhEsA256Kw,
    /// AES GCM Key Wrap with 128-bit key.
    #[serde(rename = "A128GCMKW")]
    A128GcmKw,
    /// AES GCM Key Wrap with 192-bit key.
    #[serde(rename = "A192GCMKW")]
    A192GcmKw,
    /// AES GCM Key Wrap with 256-bit key.
    #[serde(rename = "A256GCMKW")]
    A256GcmKw,
    /// PBES2 with HMAC SHA-256 and AES Key Wrap 128-bit.
    #[serde(rename = "PBES2-HS256+A128KW")]
    Pbes2Hs256A128Kw,
    /// PBES2 with HMAC SHA-384 and AES Key Wrap 192-bit.
    #[serde(rename = "PBES2-HS384+A192KW")]
    Pbes2Hs384A192Kw,
    /// PBES2 with HMAC SHA-512 and AES Key Wrap 256-bit.
    #[serde(rename = "PBES2-HS512+A256KW")]
    Pbes2Hs512A256Kw,
}

impl JweAlg {
    /// Parses a string into the corresponding [JweAlg] variant.
    pub fn from_alg_str(alg: &str) -> Option<Self> {
        match alg {
            "RSA1_5" => Some(Self::RSA1_5),
            "RSA-OAEP" => Some(Self::RsaOaep),
            "RSA-OAEP-256" => Some(Self::RsaOaep256),
            "A128KW" => Some(Self::A128Kw),
            "A192KW" => Some(Self::A192Kw),
            "A256KW" => Some(Self::A256Kw),
            "dir" => Some(Self::Dir),
            "ECDH-ES" => Some(Self::EcdhEs),
            "ECDH-ES+A128KW" => Some(Self::EcdhEsA128Kw),
            "ECDH-ES+A192KW" => Some(Self::EcdhEsA192Kw),
            "ECDH-ES+A256KW" => Some(Self::EcdhEsA256Kw),
            "A128GCMKW" => Some(Self::A128GcmKw),
            "A192GCMKW" => Some(Self::A192GcmKw),
            "A256GCMKW" => Some(Self::A256GcmKw),
            "PBES2-HS256+A128KW" => Some(Self::Pbes2Hs256A128Kw),
            "PBES2-HS384+A192KW" => Some(Self::Pbes2Hs384A192Kw),
            "PBES2-HS512+A256KW" => Some(Self::Pbes2Hs512A256Kw),
            _ => None,
        }
    }
}

/// JWE Content Encryption Algorithms ("enc" values).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum JweEncAlg {
    /// AES_128_CBC_HMAC_SHA_256.
    #[serde(rename = "A128CBC-HS256")]
    A128CbcHs256,
    /// AES_192_CBC_HMAC_SHA_384.
    #[serde(rename = "A192CBC-HS384")]
    A192CbcHs384,
    /// AES_256_CBC_HMAC_SHA_512.
    #[serde(rename = "A256CBC-HS512")]
    A256CbcHs512,
    /// AES GCM with 128-bit key.
    A128GCM,
    /// AES GCM with 192-bit key.
    A192GCM,
    /// AES GCM with 256-bit key.
    A256GCM,
}

impl JweEncAlg {
    /// Parses a string into the corresponding [JweEncAlg] variant.
    pub fn from_alg_str(alg: &str) -> Option<Self> {
        match alg {
            "A128CBC-HS256" => Some(Self::A128CbcHs256),
            "A192CBC-HS384" => Some(Self::A192CbcHs384),
            "A256CBC-HS512" => Some(Self::A256CbcHs512),
            "A128GCM" => Some(Self::A128GCM),
            "A192GCM" => Some(Self::A192GCM),
            "A256GCM" => Some(Self::A256GCM),
            _ => None,
        }
    }
}
