use std::{cmp::Ordering, collections::HashSet};

use serde::{Deserialize, Serialize};

use crate::types::OidcClientError;

/// RSA Other Prime Info
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq)]
pub struct Oth {
    /// Prime Factor
    r: String,
    /// Factor CRT Exponent
    d: String,
    /// Factor CRT Coefficient
    t: String,
}

/// JWK structure
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq)]
pub struct Jwk {
    /// The specific cryptographic algorithm used with the key.
    #[serde(rename = "alg", skip_serializing_if = "Option::is_none")]
    algorithm: Option<String>,
    /// The family of cryptographic algorithms used with the key.
    #[serde(rename = "kty", skip_serializing_if = "Option::is_none")]
    key_type: Option<String>,
    /// How the key was meant to be used; sig represents the signature.
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    key_use: Option<String>,
    /// The x.509 certificate chain. The first entry in the array is the certificate to use for token verification; the other certificates can be used to verify this first certificate.
    #[serde(rename = "x5c", skip_serializing_if = "Option::is_none")]
    x509_cert_chain: Option<Vec<String>>,
    /// The modulus for the RSA public key.
    #[serde(skip_serializing_if = "Option::is_none")]
    n: Option<String>,
    /// The exponent for the RSA public key.
    #[serde(skip_serializing_if = "Option::is_none")]
    e: Option<String>,
    /// The unique identifier for the key.
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    key_id: Option<String>,
    /// The thumbprint of the x.509 cert (SHA-1 thumbprint).
    #[serde(rename = "x5t", skip_serializing_if = "Option::is_none")]
    x509_sha1_thumbprint: Option<String>,
    /// Cryptographic curve used with the key.
    #[serde(rename = "crv", skip_serializing_if = "Option::is_none")]
    curve: Option<String>,
    /// x coordinate of EC
    #[serde(skip_serializing_if = "Option::is_none")]
    x: Option<String>,
    /// y coordinate of EC
    #[serde(skip_serializing_if = "Option::is_none")]
    y: Option<String>,
    /// RSA Secret Prime
    #[serde(skip_serializing_if = "Option::is_none")]
    p: Option<String>,
    /// RSA Secret Prime, p < q
    #[serde(skip_serializing_if = "Option::is_none")]
    q: Option<String>,
    /// RSA Multiplicative inverse u = p^-1 \bmod q.
    #[serde(skip_serializing_if = "Option::is_none")]
    u: Option<String>,
    /// Key of oct type key
    #[serde(skip_serializing_if = "Option::is_none")]
    k: Option<String>,
    /// Private exponent
    #[serde(skip_serializing_if = "Option::is_none")]
    d: Option<String>,
    /// First Factor CRT Exponent Parameter
    #[serde(skip_serializing_if = "Option::is_none")]
    dp: Option<String>,
    /// Second Factor CRT Exponent Parameter
    #[serde(skip_serializing_if = "Option::is_none")]
    dq: Option<String>,
    /// First CRT Coefficient
    #[serde(skip_serializing_if = "Option::is_none")]
    qi: Option<String>,
    /// Other Prime Info for RSA
    #[serde(skip_serializing_if = "Option::is_none")]
    oth: Option<Vec<Oth>>,
}

impl Jwk {
    pub(crate) fn algorithms(&self) -> HashSet<String> {
        let mut algs: HashSet<String> = HashSet::new();

        if self.algorithm.is_some() {
            algs.insert(self.algorithm.clone().unwrap());
            return algs;
        }

        return match &self.key_type {
            Some(kty) => match kty.as_str() {
                "EC" => {
                    if self.key_use == Some("enc".to_string()) || self.key_use.is_none() {
                        algs.insert("ECDH-ES".to_string());
                        algs.insert("ECDH-ES+A128KW".to_string());
                        algs.insert("ECDH-ES+A192KW".to_string());
                        algs.insert("ECDH-ES+A256KW".to_string());
                    }
                    if self.key_use == Some("sig".to_string()) || self.key_use.is_none() {
                        let n = self.curve.clone().unwrap_or("000".to_string());
                        algs.insert(format!("ES{}", &n[n.len() - 3..]).replace("21", "12"));
                    }
                    algs
                }
                "OKP" => {
                    algs.insert("ECDH-ES".to_string());
                    algs.insert("ECDH-ES+A128KW".to_string());
                    algs.insert("ECDH-ES+A192KW".to_string());
                    algs.insert("ECDH-ES+A256KW".to_string());
                    algs
                }
                "RSA" => {
                    if self.key_use == Some("enc".to_string()) || self.key_use.is_none() {
                        algs.insert("RSA-OAEP".to_string());
                        algs.insert("RSA-OAEP-256".to_string());
                        algs.insert("RSA-OAEP-384".to_string());
                        algs.insert("RSA-OAEP-512".to_string());
                        algs.insert("RSA1_5".to_string());
                    }

                    if self.key_use == Some("sig".to_string()) || self.key_use.is_none() {
                        algs.insert("PS256".to_string());
                        algs.insert("PS384".to_string());
                        algs.insert("PS512".to_string());
                        algs.insert("RS256".to_string());
                        algs.insert("RS384".to_string());
                        algs.insert("RS512".to_string());
                    }
                    algs
                }
                _ => algs,
            },
            _ => algs,
        };
    }
}

/// JWKS Structure
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq)]
pub struct Jwks {
    /// List of keys
    keys: Vec<Jwk>,
}

impl Jwks {
    #[allow(clippy::if_same_then_else)]
    pub(crate) fn get(
        &self,
        alg: Option<String>,
        key_use: Option<String>,
        kid: Option<String>,
    ) -> Result<Vec<&Jwk>, OidcClientError> {
        if key_use.is_none() || alg.is_none() {
            return Err(OidcClientError::new(
                "JwksError",
                "invalid query",
                "key_use or alg should be present",
                None,
            ));
        }

        let kty = Self::get_kty_from_alg(alg.as_ref());

        let mut keys: Vec<&Jwk> = self
            .keys
            .iter()
            .filter(|key| {
                let mut candidate = true;

                if candidate && kty.is_some() && key.key_type != kty {
                    candidate = false;
                }

                if candidate && kid.is_some() && key.key_id != kid {
                    candidate = false;
                }

                if candidate && key_use.is_some() && key.key_use.is_some() && key.key_use != key_use
                {
                    candidate = false;
                }

                if candidate && key.algorithm.is_some() && key.algorithm != alg {
                    candidate = false;
                } else if alg.is_some() && !key.algorithms().contains(alg.as_ref().unwrap()) {
                    candidate = false;
                }

                candidate
            })
            .collect();

        keys.sort_by(|first, second| {
            let score = keyscore(second, alg.is_some(), key_use.is_some())
                - keyscore(first, alg.is_some(), key_use.is_some());
            match score {
                -1 => Ordering::Less,
                0 => Ordering::Less,
                1 => Ordering::Less,
                _ => panic!("Invalid Key Score OpenID Key Store"),
            }
        });

        Ok(keys)
    }

    fn get_kty_from_alg(alg: Option<&String>) -> Option<String> {
        return match alg {
            Some(a) => match &a.as_str()[0..2] {
                "RS" | "PS" => Some("RSA".to_string()),
                "ES" => Some("EC".to_string()),
                "Ed" => Some("OKP".to_string()),
                _ => None,
            },
            _ => None,
        };
    }

    pub(crate) fn is_only_private_keys(&self) -> bool {
        self.keys
            .iter()
            .all(|j| j.d.is_some() || j.key_type == Some("oct".to_string()))
    }

    pub(crate) fn has_oct_keys(&self) -> bool {
        self.keys
            .iter()
            .any(|j| j.key_type == Some("oct".to_string()))
    }
}

fn keyscore(key: &Jwk, alg: bool, key_use: bool) -> i8 {
    let mut score: i8 = 0;
    if key.algorithm.is_some() && alg {
        score += 1;
    }

    if key.key_use.is_some() && key_use {
        score += 1;
    }

    score
}
