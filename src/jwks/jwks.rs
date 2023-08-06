use std::{cmp::Ordering, collections::HashSet};

use josekit::{
    jwk::Jwk,
    jws::{
        alg::{
            ecdsa::EcdsaJwsAlgorithm, eddsa::EddsaJwsAlgorithm, hmac::HmacJwsAlgorithm,
            rsassa::RsassaJwsAlgorithm, rsassa_pss::RsassaPssJwsAlgorithm,
        },
        JwsSigner,
    },
    jwt::alg::unsecured::UnsecuredJwsAlgorithm,
};
use serde::{Deserialize, Serialize};

use crate::types::OidcClientError;

pub(crate) trait CustomJwk {
    fn algorithms(&self) -> HashSet<String>;

    fn is_private_key(&self) -> bool;

    fn to_signer(&self) -> Result<Box<dyn JwsSigner>, OidcClientError>;
}

impl CustomJwk for Jwk {
    fn algorithms(&self) -> HashSet<String> {
        let mut algs: HashSet<String> = HashSet::new();

        if let Some(alg) = self.algorithm() {
            algs.insert(alg.to_string());
            return algs;
        }

        return match self.key_type() {
            "EC" => {
                let key_use = self.key_use();
                if key_use == Some("enc") || key_use.is_none() {
                    algs.insert("ECDH-ES".to_string());
                    algs.insert("ECDH-ES+A128KW".to_string());
                    algs.insert("ECDH-ES+A192KW".to_string());
                    algs.insert("ECDH-ES+A256KW".to_string());
                }

                if key_use == Some("sig") || key_use.is_none() {
                    let n = self.curve().unwrap_or("000").to_string();
                    algs.insert(format!("ES{}", &n[n.len() - 3..]).replace("21", "12"));
                }
                algs
            }
            "RSA" => {
                let key_use = self.key_use();
                if key_use == Some("enc") || key_use.is_none() {
                    algs.insert("RSA-OAEP".to_string());
                    algs.insert("RSA-OAEP-256".to_string());
                    algs.insert("RSA-OAEP-384".to_string());
                    algs.insert("RSA-OAEP-512".to_string());
                    algs.insert("RSA1_5".to_string());
                }

                if key_use == Some("sig") || key_use.is_none() {
                    algs.insert("PS256".to_string());
                    algs.insert("PS384".to_string());
                    algs.insert("PS512".to_string());
                    algs.insert("RS256".to_string());
                    algs.insert("RS384".to_string());
                    algs.insert("RS512".to_string());
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
            _ => algs,
        };
    }

    fn is_private_key(&self) -> bool {
        self.key_type() == "oct" || self.parameter("d").is_some()
    }

    fn to_signer(&self) -> Result<Box<dyn JwsSigner>, OidcClientError> {
        let alg = match self.algorithm() {
            Some(a) => a,
            None => {
                return Err(OidcClientError::new_error(
                    "jwk does not have algorithm",
                    None,
                ))
            }
        };

        let error = OidcClientError::new_error("error when creating a jws signer", None);

        match alg {
            "HS256" => {
                let algorithm = HmacJwsAlgorithm::Hs256;
                Ok(Box::new(
                    algorithm.signer_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "HS384" => {
                let algorithm = HmacJwsAlgorithm::Hs384;
                Ok(Box::new(
                    algorithm.signer_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "HS512" => {
                let algorithm = HmacJwsAlgorithm::Hs512;
                Ok(Box::new(
                    algorithm.signer_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "RS256" => {
                let algorithm = RsassaJwsAlgorithm::Rs256;
                Ok(Box::new(
                    algorithm.signer_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "RS384" => {
                let algorithm = RsassaJwsAlgorithm::Rs384;
                Ok(Box::new(
                    algorithm.signer_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "RS512" => {
                let algorithm = RsassaJwsAlgorithm::Rs512;
                Ok(Box::new(
                    algorithm.signer_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "PS256" => {
                let algorithm = RsassaPssJwsAlgorithm::Ps256;
                Ok(Box::new(
                    algorithm.signer_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "PS384" => {
                let algorithm = RsassaPssJwsAlgorithm::Ps384;
                Ok(Box::new(
                    algorithm.signer_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "PS512" => {
                let algorithm = RsassaPssJwsAlgorithm::Ps512;
                Ok(Box::new(
                    algorithm.signer_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "ES256" => {
                let algorithm = EcdsaJwsAlgorithm::Es256;
                Ok(Box::new(
                    algorithm.signer_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "ES384" => {
                let algorithm = EcdsaJwsAlgorithm::Es384;
                Ok(Box::new(
                    algorithm.signer_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "ES512" => {
                let algorithm = EcdsaJwsAlgorithm::Es512;
                Ok(Box::new(
                    algorithm.signer_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "ES256K" => {
                let algorithm = EcdsaJwsAlgorithm::Es256k;
                Ok(Box::new(
                    algorithm.signer_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "EdDSA" => {
                let algorithm = EddsaJwsAlgorithm::Eddsa;
                Ok(Box::new(
                    algorithm.signer_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "none" => Ok(Box::new(UnsecuredJwsAlgorithm::None.signer())),
            _ => Err(OidcClientError::new_error(
                "invalid algorithm for creating a signer",
                None,
            )),
        }
    }
}

/// Jwks that wraps [josekit::jwk::JwkSet]
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Jwks {
    /// [josekit::jwk::JwkSet]
    keys: Vec<Jwk>,
}

impl From<Vec<Jwk>> for Jwks {
    fn from(value: Vec<Jwk>) -> Self {
        Self { keys: value }
    }
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
            return Err(OidcClientError::new_error(
                "key_use or alg should be present",
                None,
            ));
        }
        let kty = get_kty_from_alg(alg.as_ref())?;

        let mut keys: Vec<&Jwk> = self
            .keys
            .iter()
            .filter(|key| {
                let mut candidate = true;

                if candidate && key.key_type() != kty {
                    candidate = false;
                }

                if candidate && kid.is_some() && key.key_id() != kid.as_deref() {
                    candidate = false;
                }

                if candidate
                    && key_use.is_some()
                    && key.key_use().is_some()
                    && key.key_use() != key_use.as_deref()
                {
                    candidate = false;
                }

                if candidate && key.algorithm().is_some() && key.algorithm() != alg.as_deref() {
                    candidate = false;
                } else if alg.is_some() && !key.algorithms().contains(alg.as_ref().unwrap()) {
                    candidate = false;
                }

                candidate
            })
            .collect();

        keys.sort_by(|first, second| {
            let score = keyscore_jose(second, alg.is_some(), key_use.is_some())
                - keyscore_jose(first, alg.is_some(), key_use.is_some());
            match score {
                -1 => Ordering::Less,
                0 => Ordering::Less,
                1 => Ordering::Less,
                _ => panic!("Invalid Key Score OpenID Key Store"),
            }
        });

        Ok(keys)
    }

    pub(crate) fn is_only_private_keys(&self) -> bool {
        self.keys.iter().all(|j| j.is_private_key())
    }

    pub(crate) fn has_oct_keys(&self) -> bool {
        self.keys.iter().any(|j| j.key_type() == "oct")
    }

    pub(crate) fn get_public_jwks(&self) -> Self {
        Self {
            keys: self
                .keys
                .iter()
                .filter_map(|k| k.to_public_key().ok())
                .collect(),
        }
    }
}

fn get_kty_from_alg(alg: Option<&String>) -> Result<&str, OidcClientError> {
    let kty = match alg {
        Some(a) => match &a.as_str()[0..2] {
            "RS" | "PS" => Some("RSA"),
            "ES" => Some("EC"),
            "Ed" => Some("OKP"),
            _ => None,
        },
        _ => None,
    };

    kty.ok_or(OidcClientError::new_error(
        "key_use or alg should be present",
        None,
    ))
}

fn keyscore_jose(key: &Jwk, alg: bool, key_use: bool) -> i8 {
    let mut score: i8 = 0;
    if key.algorithm().is_some() && alg {
        score += 1;
    }

    if key.key_use().is_some() && key_use {
        score += 1;
    }

    score
}
