use crate::{
    jwk::Jwk,
    types::{Header, OpenIdCrypto, Payload},
};

/// Default Crypto
pub struct OpenSSLCrypto;

impl OpenIdCrypto for OpenSSLCrypto {
    fn jwe_serialize(&self, payload: String, header: Header, jwk: &Jwk) -> Result<String, String> {
        let jwe_header =
            josekit::jwe::JweHeader::from_map(header.params).map_err(|e| e.to_string())?;

        let jwk = josekit::jwk::Jwk::from_map(jwk.as_map()).map_err(|e| e.to_string())?;

        josekit::jwe::serialize_compact(payload.as_bytes(), &jwe_header, &*jwk.to_jwe_encrypter()?)
            .map_err(|e| e.to_string())
    }

    fn jwe_deserialize(&self, jwe: String, jwk: &Jwk) -> Result<String, String> {
        let jwk = josekit::jwk::Jwk::from_map(jwk.as_map()).map_err(|e| e.to_string())?;

        let result = josekit::jwe::deserialize_compact(&jwe, &*jwk.to_jwe_decrypter()?)
            .map_err(|e| e.to_string())?;

        String::from_utf8(result.0).map_err(|e| e.to_string())
    }

    fn jws_serialize(&self, payload: Payload, header: Header, jwk: &Jwk) -> Result<String, String> {
        let jwk = josekit::jwk::Jwk::from_map(jwk.as_map()).map_err(|e| e.to_string())?;

        let jws_header =
            josekit::jws::JwsHeader::from_map(header.params).map_err(|e| e.to_string())?;

        let jwt_payload =
            josekit::jwt::JwtPayload::from_map(payload.params).map_err(|e| e.to_string())?;

        josekit::jws::serialize_compact(
            serde_json::to_string(jwt_payload.claims_set())
                .map_err(|e| e.to_string())?
                .as_bytes(),
            &jws_header,
            &*jwk.to_signer()?,
        )
        .map_err(|e| e.to_string())
    }

    fn jws_deserialize(&self, jws: String, jwk: &Jwk) -> Result<(Header, Payload), String> {
        let jwk = josekit::jwk::Jwk::from_map(jwk.as_map()).map_err(|e| e.to_string())?;

        let (payload, header) = josekit::jws::deserialize_compact(jws, &*jwk.to_verifier()?)
            .map_err(|e| e.to_string())?;

        let header = Header {
            params: header.into_map(),
        };

        let payload_map =
            serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(&payload)
                .map_err(|e| e.to_string())?;

        Ok((
            header,
            Payload {
                params: payload_map,
            },
        ))
    }
}

trait CustomJwk {
    fn to_signer(&self) -> Result<Box<dyn josekit::jws::JwsSigner>, &'static str>;

    fn to_verifier(&self) -> Result<Box<dyn josekit::jws::JwsVerifier>, &'static str>;

    fn to_jwe_decrypter(&self) -> Result<Box<dyn josekit::jwe::JweDecrypter>, &'static str>;

    fn to_jwe_encrypter(&self) -> Result<Box<dyn josekit::jwe::JweEncrypter>, &'static str>;
}

impl CustomJwk for josekit::jwk::Jwk {
    fn to_signer(&self) -> Result<Box<dyn josekit::jws::JwsSigner>, &'static str> {
        let alg = match self.algorithm() {
            Some(a) => a,
            None => return Err("jwk does not have algorithm"),
        };

        let error = "error when creating a jws signer";

        match alg {
            "HS256" => {
                let algorithm = josekit::jws::alg::hmac::HmacJwsAlgorithm::Hs256;
                Ok(Box::new(
                    algorithm.signer_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "HS384" => {
                let algorithm = josekit::jws::alg::hmac::HmacJwsAlgorithm::Hs384;
                Ok(Box::new(
                    algorithm.signer_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "HS512" => {
                let algorithm = josekit::jws::alg::hmac::HmacJwsAlgorithm::Hs512;
                Ok(Box::new(
                    algorithm.signer_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "RS256" => {
                let algorithm = josekit::jws::alg::rsassa::RsassaJwsAlgorithm::Rs256;
                Ok(Box::new(
                    algorithm.signer_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "RS384" => {
                let algorithm = josekit::jws::alg::rsassa::RsassaJwsAlgorithm::Rs384;
                Ok(Box::new(
                    algorithm.signer_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "RS512" => {
                let algorithm = josekit::jws::alg::rsassa::RsassaJwsAlgorithm::Rs512;
                Ok(Box::new(
                    algorithm.signer_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "PS256" => {
                let algorithm = josekit::jws::alg::rsassa_pss::RsassaPssJwsAlgorithm::Ps256;
                Ok(Box::new(
                    algorithm.signer_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "PS384" => {
                let algorithm = josekit::jws::alg::rsassa_pss::RsassaPssJwsAlgorithm::Ps384;
                Ok(Box::new(
                    algorithm.signer_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "PS512" => {
                let algorithm = josekit::jws::alg::rsassa_pss::RsassaPssJwsAlgorithm::Ps512;
                Ok(Box::new(
                    algorithm.signer_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "ES256" => {
                let algorithm = josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm::Es256;
                Ok(Box::new(
                    algorithm.signer_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "ES384" => {
                let algorithm = josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm::Es384;
                Ok(Box::new(
                    algorithm.signer_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "ES512" => {
                let algorithm = josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm::Es512;
                Ok(Box::new(
                    algorithm.signer_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "ES256K" => {
                let algorithm = josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm::Es256k;
                Ok(Box::new(
                    algorithm.signer_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "EdDSA" => {
                let algorithm = josekit::jws::alg::eddsa::EddsaJwsAlgorithm::Eddsa;
                Ok(Box::new(
                    algorithm.signer_from_jwk(self).map_err(|_| error)?,
                ))
            }
            _ => Err("invalid algorithm for creating a signer"),
        }
    }

    fn to_verifier(&self) -> Result<Box<dyn josekit::jws::JwsVerifier>, &'static str> {
        let alg = match self.algorithm() {
            Some(a) => a,
            None => return Err("jwk does not have algorithm"),
        };

        let error = "error when creating a jws signer";

        match alg {
            "HS256" => {
                let algorithm = josekit::jws::alg::hmac::HmacJwsAlgorithm::Hs256;
                Ok(Box::new(
                    algorithm.verifier_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "HS384" => {
                let algorithm = josekit::jws::alg::hmac::HmacJwsAlgorithm::Hs384;
                Ok(Box::new(
                    algorithm.verifier_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "HS512" => {
                let algorithm = josekit::jws::alg::hmac::HmacJwsAlgorithm::Hs512;
                Ok(Box::new(
                    algorithm.verifier_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "RS256" => {
                let algorithm = josekit::jws::alg::rsassa::RsassaJwsAlgorithm::Rs256;
                Ok(Box::new(
                    algorithm.verifier_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "RS384" => {
                let algorithm = josekit::jws::alg::rsassa::RsassaJwsAlgorithm::Rs384;
                Ok(Box::new(
                    algorithm.verifier_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "RS512" => {
                let algorithm = josekit::jws::alg::rsassa::RsassaJwsAlgorithm::Rs512;
                Ok(Box::new(
                    algorithm.verifier_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "PS256" => {
                let algorithm = josekit::jws::alg::rsassa_pss::RsassaPssJwsAlgorithm::Ps256;
                Ok(Box::new(
                    algorithm.verifier_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "PS384" => {
                let algorithm = josekit::jws::alg::rsassa_pss::RsassaPssJwsAlgorithm::Ps384;
                Ok(Box::new(
                    algorithm.verifier_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "PS512" => {
                let algorithm = josekit::jws::alg::rsassa_pss::RsassaPssJwsAlgorithm::Ps512;
                Ok(Box::new(
                    algorithm.verifier_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "ES256" => {
                let algorithm = josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm::Es256;
                Ok(Box::new(
                    algorithm.verifier_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "ES384" => {
                let algorithm = josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm::Es384;
                Ok(Box::new(
                    algorithm.verifier_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "ES512" => {
                let algorithm = josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm::Es512;
                Ok(Box::new(
                    algorithm.verifier_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "ES256K" => {
                let algorithm = josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm::Es256k;
                Ok(Box::new(
                    algorithm.verifier_from_jwk(self).map_err(|_| error)?,
                ))
            }
            "EdDSA" => {
                let algorithm = josekit::jws::alg::eddsa::EddsaJwsAlgorithm::Eddsa;
                Ok(Box::new(
                    algorithm.verifier_from_jwk(self).map_err(|_| error)?,
                ))
            }
            _ => Err("invalid algorithm for creating a signer"),
        }
    }
    fn to_jwe_decrypter(&self) -> Result<Box<dyn josekit::jwe::JweDecrypter>, &'static str> {
        let alg = match self.algorithm() {
            Some(a) => a,
            None => return Err("jwk does not have algorithm"),
        };

        let error = "error when creating a jwe decrypter";

        match alg {
            "A128GCMKW" => Ok(Box::new(
                josekit::jwe::A128GCMKW
                    .decrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "A128KW" => Ok(Box::new(
                josekit::jwe::A128KW
                    .decrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "A192GCMKW" => Ok(Box::new(
                josekit::jwe::A192GCMKW
                    .decrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "A192KW" => Ok(Box::new(
                josekit::jwe::A192KW
                    .decrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "A256GCMKW" => Ok(Box::new(
                josekit::jwe::A256GCMKW
                    .decrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "A256KW" => Ok(Box::new(
                josekit::jwe::A256KW
                    .decrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "dir" => Ok(Box::new(
                josekit::jwe::Dir
                    .decrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "ECDH-ES" => Ok(Box::new(
                josekit::jwe::ECDH_ES
                    .decrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "ECDH-ES+A128KW" => Ok(Box::new(
                josekit::jwe::ECDH_ES_A128KW
                    .decrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "ECDH-ES+A192KW" => Ok(Box::new(
                josekit::jwe::ECDH_ES_A192KW
                    .decrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "ECDH-ES+A256KW" => Ok(Box::new(
                josekit::jwe::ECDH_ES_A256KW
                    .decrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "PBES2-HS256+A128KW" => Ok(Box::new(
                josekit::jwe::PBES2_HS256_A128KW
                    .decrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "PBES2-HS384+A192KW" => Ok(Box::new(
                josekit::jwe::PBES2_HS384_A192KW
                    .decrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "PBES2-HS512+A256KW" => Ok(Box::new(
                josekit::jwe::PBES2_HS512_A256KW
                    .decrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "RSA1_5" => Ok(Box::new(
                #[allow(deprecated)]
                josekit::jwe::RSA1_5
                    .decrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "RSA-OAEP" => Ok(Box::new(
                josekit::jwe::RSA_OAEP
                    .decrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "RSA-OAEP-256" => Ok(Box::new(
                josekit::jwe::RSA_OAEP_256
                    .decrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "RSA-OAEP-384" => Ok(Box::new(
                josekit::jwe::RSA_OAEP_384
                    .decrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "RSA-OAEP-512" => Ok(Box::new(
                josekit::jwe::RSA_OAEP_512
                    .decrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            _ => Err("invalid algorithm for creating a jwe decrypter"),
        }
    }

    fn to_jwe_encrypter(&self) -> Result<Box<dyn josekit::jwe::JweEncrypter>, &'static str> {
        let alg = match self.algorithm() {
            Some(a) => a,
            None => return Err("jwk does not have algorithm"),
        };

        let error = "error when creating a jwe encrypter";

        match alg {
            "A128GCMKW" => Ok(Box::new(
                josekit::jwe::A128GCMKW
                    .encrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "A128KW" => Ok(Box::new(
                josekit::jwe::A128KW
                    .encrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "A192GCMKW" => Ok(Box::new(
                josekit::jwe::A192GCMKW
                    .encrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "A192KW" => Ok(Box::new(
                josekit::jwe::A192KW
                    .encrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "A256GCMKW" => Ok(Box::new(
                josekit::jwe::A256GCMKW
                    .encrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "A256KW" => Ok(Box::new(
                josekit::jwe::A256KW
                    .encrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "dir" => Ok(Box::new(
                josekit::jwe::Dir
                    .encrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "ECDH-ES" => Ok(Box::new(
                josekit::jwe::ECDH_ES
                    .encrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "ECDH-ES+A128KW" => Ok(Box::new(
                josekit::jwe::ECDH_ES_A128KW
                    .encrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "ECDH-ES+A192KW" => Ok(Box::new(
                josekit::jwe::ECDH_ES_A192KW
                    .encrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "ECDH-ES+A256KW" => Ok(Box::new(
                josekit::jwe::ECDH_ES_A256KW
                    .encrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "PBES2-HS256+A128KW" => Ok(Box::new(
                josekit::jwe::PBES2_HS256_A128KW
                    .encrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "PBES2-HS384+A192KW" => Ok(Box::new(
                josekit::jwe::PBES2_HS384_A192KW
                    .encrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "PBES2-HS512+A256KW" => Ok(Box::new(
                josekit::jwe::PBES2_HS512_A256KW
                    .encrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "RSA1_5" => Ok(Box::new(
                #[allow(deprecated)]
                josekit::jwe::RSA1_5
                    .encrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "RSA-OAEP" => Ok(Box::new(
                josekit::jwe::RSA_OAEP
                    .encrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "RSA-OAEP-256" => Ok(Box::new(
                josekit::jwe::RSA_OAEP_256
                    .encrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "RSA-OAEP-384" => Ok(Box::new(
                josekit::jwe::RSA_OAEP_384
                    .encrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            "RSA-OAEP-512" => Ok(Box::new(
                josekit::jwe::RSA_OAEP_512
                    .encrypter_from_jwk(self)
                    .map_err(|_| error)?,
            )),
            _ => Err("invalid algorithm for creating a jwe encrypter"),
        }
    }
}
