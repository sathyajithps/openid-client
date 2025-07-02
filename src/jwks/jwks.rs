use std::{cmp::Ordering, collections::HashSet};

use josekit::{
    jwe::{self, JweDecrypter, JweEncrypter},
    jwk::Jwk,
    jws::{
        alg::{
            ecdsa::EcdsaJwsAlgorithm, eddsa::EddsaJwsAlgorithm, hmac::HmacJwsAlgorithm,
            rsassa::RsassaJwsAlgorithm, rsassa_pss::RsassaPssJwsAlgorithm,
        },
        JwsSigner, JwsVerifier,
    },
    jwt::alg::unsecured::UnsecuredJwsAlgorithm,
};
use serde::{Deserialize, Serialize};

use crate::types::{OidcClientError, OidcReturnType};

pub(crate) trait CustomJwk {
    fn algorithms(&self) -> HashSet<String>;

    fn is_private_key(&self) -> bool;

    fn to_signer(&self) -> OidcReturnType<Box<dyn JwsSigner>>;

    fn to_verifier(&self) -> OidcReturnType<Box<dyn JwsVerifier>>;

    fn to_jwe_decrypter(&self) -> OidcReturnType<Box<dyn JweDecrypter>>;

    fn to_jwe_encrypter(&self) -> OidcReturnType<Box<dyn JweEncrypter>>;
}

impl CustomJwk for Jwk {
    fn algorithms(&self) -> HashSet<String> {
        let mut algs: HashSet<String> = HashSet::new();

        if let Some(alg) = self.algorithm() {
            algs.insert(alg.to_string());
            return algs;
        }

        match self.key_type() {
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
        }
    }

    fn is_private_key(&self) -> bool {
        self.key_type() == "oct" || self.parameter("d").is_some()
    }

    fn to_signer(&self) -> OidcReturnType<Box<dyn JwsSigner>> {
        let alg = match self.algorithm() {
            Some(a) => a,
            None => {
                return Err(Box::new(OidcClientError::new_error(
                    "jwk does not have algorithm",
                    None,
                )))
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
            _ => Err(Box::new(OidcClientError::new_error(
                "invalid algorithm for creating a signer",
                None,
            ))),
        }
    }

    fn to_verifier(&self) -> OidcReturnType<Box<dyn JwsVerifier>> {
        let alg = match self.algorithm() {
            Some(a) => a,
            None => {
                return Err(Box::new(OidcClientError::new_error(
                    "jwk does not have algorithm",
                    None,
                )))
            }
        };

        let error = OidcClientError::new_error("error when creating a jws signer", None);

        match alg {
            "HS256" => {
                let algorithm = HmacJwsAlgorithm::Hs256;
                Ok(Box::new(
                    algorithm.verifier_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "HS384" => {
                let algorithm = HmacJwsAlgorithm::Hs384;
                Ok(Box::new(
                    algorithm.verifier_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "HS512" => {
                let algorithm = HmacJwsAlgorithm::Hs512;
                Ok(Box::new(
                    algorithm.verifier_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "RS256" => {
                let algorithm = RsassaJwsAlgorithm::Rs256;
                Ok(Box::new(
                    algorithm.verifier_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "RS384" => {
                let algorithm = RsassaJwsAlgorithm::Rs384;
                Ok(Box::new(
                    algorithm.verifier_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "RS512" => {
                let algorithm = RsassaJwsAlgorithm::Rs512;
                Ok(Box::new(
                    algorithm.verifier_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "PS256" => {
                let algorithm = RsassaPssJwsAlgorithm::Ps256;
                Ok(Box::new(
                    algorithm.verifier_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "PS384" => {
                let algorithm = RsassaPssJwsAlgorithm::Ps384;
                Ok(Box::new(
                    algorithm.verifier_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "PS512" => {
                let algorithm = RsassaPssJwsAlgorithm::Ps512;
                Ok(Box::new(
                    algorithm.verifier_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "ES256" => {
                let algorithm = EcdsaJwsAlgorithm::Es256;
                Ok(Box::new(
                    algorithm.verifier_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "ES384" => {
                let algorithm = EcdsaJwsAlgorithm::Es384;
                Ok(Box::new(
                    algorithm.verifier_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "ES512" => {
                let algorithm = EcdsaJwsAlgorithm::Es512;
                Ok(Box::new(
                    algorithm.verifier_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "ES256K" => {
                let algorithm = EcdsaJwsAlgorithm::Es256k;
                Ok(Box::new(
                    algorithm.verifier_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "EdDSA" => {
                let algorithm = EddsaJwsAlgorithm::Eddsa;
                Ok(Box::new(
                    algorithm.verifier_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "none" => Ok(Box::new(UnsecuredJwsAlgorithm::None.verifier())),
            _ => Err(Box::new(OidcClientError::new_error(
                "invalid algorithm for creating a signer",
                None,
            ))),
        }
    }

    fn to_jwe_decrypter(&self) -> OidcReturnType<Box<dyn JweDecrypter>> {
        if let Ok(decrypter) = jwe::A128GCMKW.decrypter_from_jwk(self) {
            return Ok(Box::new(decrypter));
        }

        if let Ok(decrypter) = jwe::A128KW.decrypter_from_jwk(self) {
            return Ok(Box::new(decrypter));
        }

        if let Ok(decrypter) = jwe::A192GCMKW.decrypter_from_jwk(self) {
            return Ok(Box::new(decrypter));
        }

        if let Ok(decrypter) = jwe::A192KW.decrypter_from_jwk(self) {
            return Ok(Box::new(decrypter));
        }

        if let Ok(decrypter) = jwe::A256GCMKW.decrypter_from_jwk(self) {
            return Ok(Box::new(decrypter));
        }

        if let Ok(decrypter) = jwe::A256KW.decrypter_from_jwk(self) {
            return Ok(Box::new(decrypter));
        }

        if let Ok(decrypter) = jwe::Dir.decrypter_from_jwk(self) {
            return Ok(Box::new(decrypter));
        }

        if let Ok(decrypter) = jwe::ECDH_ES.decrypter_from_jwk(self) {
            return Ok(Box::new(decrypter));
        }

        if let Ok(decrypter) = jwe::ECDH_ES_A128KW.decrypter_from_jwk(self) {
            return Ok(Box::new(decrypter));
        }

        if let Ok(decrypter) = jwe::ECDH_ES_A192KW.decrypter_from_jwk(self) {
            return Ok(Box::new(decrypter));
        }

        if let Ok(decrypter) = jwe::ECDH_ES_A256KW.decrypter_from_jwk(self) {
            return Ok(Box::new(decrypter));
        }

        if let Ok(decrypter) = jwe::PBES2_HS256_A128KW.decrypter_from_jwk(self) {
            return Ok(Box::new(decrypter));
        }

        if let Ok(decrypter) = jwe::PBES2_HS384_A192KW.decrypter_from_jwk(self) {
            return Ok(Box::new(decrypter));
        }

        if let Ok(decrypter) = jwe::PBES2_HS512_A256KW.decrypter_from_jwk(self) {
            return Ok(Box::new(decrypter));
        }

        #[allow(deprecated)]
        if let Ok(decrypter) = jwe::RSA1_5.decrypter_from_jwk(self) {
            return Ok(Box::new(decrypter));
        }

        if let Ok(decrypter) = jwe::RSA_OAEP.decrypter_from_jwk(self) {
            return Ok(Box::new(decrypter));
        }

        if let Ok(decrypter) = jwe::RSA_OAEP_256.decrypter_from_jwk(self) {
            return Ok(Box::new(decrypter));
        }

        if let Ok(decrypter) = jwe::RSA_OAEP_384.decrypter_from_jwk(self) {
            return Ok(Box::new(decrypter));
        }

        if let Ok(decrypter) = jwe::RSA_OAEP_512.decrypter_from_jwk(self) {
            return Ok(Box::new(decrypter));
        }

        Err(Box::new(OidcClientError::new_error(
            "Could not convert Jwk to a JWE Decrpter",
            None,
        )))
    }

    fn to_jwe_encrypter(&self) -> OidcReturnType<Box<dyn JweEncrypter>> {
        if let Ok(encrypter) = jwe::A128GCMKW.encrypter_from_jwk(self) {
            return Ok(Box::new(encrypter));
        }

        if let Ok(encrypter) = jwe::A128KW.encrypter_from_jwk(self) {
            return Ok(Box::new(encrypter));
        }

        if let Ok(encrypter) = jwe::A192GCMKW.encrypter_from_jwk(self) {
            return Ok(Box::new(encrypter));
        }

        if let Ok(encrypter) = jwe::A192KW.encrypter_from_jwk(self) {
            return Ok(Box::new(encrypter));
        }

        if let Ok(encrypter) = jwe::A256GCMKW.encrypter_from_jwk(self) {
            return Ok(Box::new(encrypter));
        }

        if let Ok(encrypter) = jwe::A256KW.encrypter_from_jwk(self) {
            return Ok(Box::new(encrypter));
        }

        if let Ok(encrypter) = jwe::Dir.encrypter_from_jwk(self) {
            return Ok(Box::new(encrypter));
        }

        if let Ok(encrypter) = jwe::ECDH_ES.encrypter_from_jwk(self) {
            return Ok(Box::new(encrypter));
        }

        if let Ok(encrypter) = jwe::ECDH_ES_A128KW.encrypter_from_jwk(self) {
            return Ok(Box::new(encrypter));
        }

        if let Ok(encrypter) = jwe::ECDH_ES_A192KW.encrypter_from_jwk(self) {
            return Ok(Box::new(encrypter));
        }

        if let Ok(decrypter) = jwe::ECDH_ES_A256KW.encrypter_from_jwk(self) {
            return Ok(Box::new(decrypter));
        }

        if let Ok(decrypter) = jwe::PBES2_HS256_A128KW.encrypter_from_jwk(self) {
            return Ok(Box::new(decrypter));
        }

        if let Ok(decrypter) = jwe::PBES2_HS384_A192KW.encrypter_from_jwk(self) {
            return Ok(Box::new(decrypter));
        }

        if let Ok(decrypter) = jwe::PBES2_HS512_A256KW.encrypter_from_jwk(self) {
            return Ok(Box::new(decrypter));
        }

        #[allow(deprecated)]
        if let Ok(decrypter) = jwe::RSA1_5.encrypter_from_jwk(self) {
            return Ok(Box::new(decrypter));
        }

        if let Ok(decrypter) = jwe::RSA_OAEP.encrypter_from_jwk(self) {
            return Ok(Box::new(decrypter));
        }

        if let Ok(decrypter) = jwe::RSA_OAEP_256.encrypter_from_jwk(self) {
            return Ok(Box::new(decrypter));
        }

        if let Ok(decrypter) = jwe::RSA_OAEP_384.encrypter_from_jwk(self) {
            return Ok(Box::new(decrypter));
        }

        if let Ok(decrypter) = jwe::RSA_OAEP_512.encrypter_from_jwk(self) {
            return Ok(Box::new(decrypter));
        }

        Err(Box::new(OidcClientError::new_error(
            "Could not convert Jwk to a JWE Decrpter",
            None,
        )))
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
    /// Number of keys present in [Jwks]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Returns if [Jwks] is empty or not
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub(crate) fn get_keys(&self) -> Vec<Jwk> {
        self.keys.clone()
    }

    #[allow(clippy::if_same_then_else)]
    pub(crate) fn get(
        &self,
        alg: Option<String>,
        key_use: Option<String>,
        kid: Option<String>,
    ) -> OidcReturnType<Vec<&Jwk>> {
        if key_use.is_none() || alg.is_none() {
            return Err(Box::new(OidcClientError::new_error(
                "key_use or alg should be present",
                None,
            )));
        }
        let kty = get_kty_from_alg(alg.as_ref());

        let mut keys: Vec<&Jwk> = self
            .keys
            .iter()
            .filter(|key| {
                let mut candidate = true;

                if candidate && kty.as_ref().is_some_and(|x| x != key.key_type()) {
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
                .filter_map(|k| {
                    let mut pub_key = k.to_public_key().ok();

                    if let Some(pk) = &mut pub_key {
                        if let Some(alg) = k.algorithm() {
                            pk.set_algorithm(alg);
                        }
                        if let Some(kid) = k.key_id() {
                            pk.set_key_id(kid);
                        }
                    }

                    pub_key
                })
                .collect(),
        }
    }
}

fn get_kty_from_alg(alg: Option<&String>) -> Option<String> {
    match alg {
        Some(a) => match &a.as_str()[0..2] {
            "RS" | "PS" => Some("RSA".to_string()),
            "ES" => Some("EC".to_string()),
            "Ed" => Some("OKP".to_string()),
            _ => None,
        },
        _ => None,
    }
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
