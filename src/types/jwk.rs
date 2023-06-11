use std::{cmp::Ordering, collections::HashSet};

use base64::engine::{general_purpose::STANDARD, Engine};
use rsa::{traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// JWK structure
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Jwk {
    /// The specific cryptographic algorithm used with the key.
    #[serde(rename = "alg")]
    algorithm: Option<String>,
    /// The family of cryptographic algorithms used with the key.
    #[serde(rename = "kty")]
    key_type: Option<String>,
    /// How the key was meant to be used; sig represents the signature.
    #[serde(rename = "use")]
    key_use: Option<String>,
    /// The x.509 certificate chain. The first entry in the array is the certificate to use for token verification; the other certificates can be used to verify this first certificate.
    #[serde(rename = "x5c")]
    x509_cert_chain: Option<Vec<String>>,
    /// The modulus for the RSA public key.
    #[serde(rename = "n")]
    rsa_modulus: Option<String>,
    /// The exponent for the RSA public key.
    #[serde(rename = "e")]
    rsa_exponent: Option<String>,
    /// The unique identifier for the key.
    #[serde(rename = "kid")]
    key_id: Option<String>,
    /// The thumbprint of the x.509 cert (SHA-1 thumbprint).
    #[serde(rename = "x5t")]
    x509_sha1_thumbprint: Option<String>,
    /// Cryptographic curve used with the key.
    #[serde(rename = "crv")]
    curve: Option<String>,
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
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Jwks {
    /// List of keys
    keys: Vec<Jwk>,
}

impl Jwks {
    /// Generates [Jwk} with specified algorithm
    /// TODO: Should be a pub method once its complete
    #[allow(dead_code)]
    pub(crate) fn generate(&mut self, alg: &str, bits: Option<usize>, kid: Option<String>) -> bool {
        return match alg {
            "RSA" => {
                let mut rng = rand::thread_rng();
                let bits = bits.unwrap_or(256);
                let key_id = kid.unwrap_or(Uuid::new_v4().to_string());
                let priv_key =
                    RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
                let pub_key = RsaPublicKey::from(&priv_key);

                let jwk = Jwk {
                    rsa_exponent: Some(STANDARD.encode(pub_key.e().to_bytes_be())),
                    rsa_modulus: Some(STANDARD.encode(pub_key.n().to_bytes_be())),
                    key_id: Some(key_id),
                    key_type: Some("RSA".to_string()),
                    /// TODO: Why?
                    algorithm: None,
                    key_use: None,
                    x509_cert_chain: None,
                    x509_sha1_thumbprint: None,
                    curve: None,
                };

                self.keys.push(jwk);

                true
            }
            _ => false,
        };
    }

    #[allow(clippy::if_same_then_else)]
    pub(crate) fn get(
        &self,
        alg: Option<String>,
        key_use: Option<String>,
        kid: Option<String>,
    ) -> Vec<&Jwk> {
        if key_use.is_none() || alg.is_none() {
            todo!()
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

        keys
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
