//! # OpenSSL crypto

use crate::{
    jwk::Jwk,
    types::{Header, OpenIdCrypto, Payload},
};

/// Default Crypto
pub struct OpenSSLCrypto;

impl OpenIdCrypto for OpenSSLCrypto {
    fn jwe_serialize(&self, payload: String, header: Header, jwk: &Jwk) -> Result<String, String> {
        let alg_str = match jwk.get_param("alg").and_then(|v| v.as_str()) {
            Some(alg) => alg.to_owned(),
            None => header
                .params
                .get("alg")
                .and_then(|v| v.as_str())
                .ok_or("neither JWK nor JWE header contain an 'alg' parameter")?
                .to_owned(),
        };

        if let Some(header_alg) = header.params.get("alg").and_then(|v| v.as_str()) {
            if header_alg != alg_str {
                return Err(format!(
                    "header alg '{}' does not match JWK alg '{}'",
                    header_alg, alg_str
                ));
            }
        }

        let jwe_header =
            josekit::jwe::JweHeader::from_map(header.params).map_err(|e| e.to_string())?;

        let jwk_jose = josekit::jwk::Jwk::from_map(jwk.as_map()).map_err(|e| e.to_string())?;

        josekit::jwe::serialize_compact(
            payload.as_bytes(),
            &jwe_header,
            &*jwk_jose.to_jwe_encrypter(Some(&alg_str))?,
        )
        .map_err(|e| e.to_string())
    }

    fn jwe_deserialize(&self, jwe: String, jwk: &Jwk) -> Result<String, String> {
        let parts: Vec<&str> = jwe.split('.').collect();
        if parts.len() != 5 {
            return Err("Invalid JWE".to_owned());
        }
        let header_b64 = parts[0];
        let header_decoded =
            crate::helpers::base64_url_decode(header_b64).map_err(|e| e.to_string())?;
        let parsed_header: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&header_decoded).map_err(|e| e.to_string())?;

        let alg_str = match jwk.get_param("alg").and_then(|v| v.as_str()) {
            Some(alg) => alg.to_owned(),
            None => parsed_header
                .get("alg")
                .and_then(|v| v.as_str())
                .ok_or("neither JWK nor JWE header contain an 'alg' parameter")?
                .to_owned(),
        };

        if let (Some(header_alg), Some(jwk_alg)) = (
            parsed_header.get("alg").and_then(|v| v.as_str()),
            jwk.get_param("alg").and_then(|v| v.as_str()),
        ) {
            if header_alg != jwk_alg {
                return Err(format!(
                    "header alg '{}' does not match JWK alg '{}'",
                    header_alg, jwk_alg
                ));
            }
        }

        let jwk_jose = josekit::jwk::Jwk::from_map(jwk.as_map()).map_err(|e| e.to_string())?;

        let result =
            josekit::jwe::deserialize_compact(&jwe, &*jwk_jose.to_jwe_decrypter(Some(&alg_str))?)
                .map_err(|e| e.to_string())?;

        String::from_utf8(result.0).map_err(|e| e.to_string())
    }

    fn jws_serialize(&self, payload: Payload, header: Header, jwk: &Jwk) -> Result<String, String> {
        let alg_str = match jwk.get_param("alg").and_then(|v| v.as_str()) {
            Some(alg) => alg.to_owned(),
            None => header
                .params
                .get("alg")
                .and_then(|v| v.as_str())
                .ok_or("neither JWK nor JWT header contain an 'alg' parameter")?
                .to_owned(),
        };

        if let Some(header_alg) = header.params.get("alg").and_then(|v| v.as_str()) {
            if header_alg != alg_str {
                return Err(format!(
                    "header alg '{}' does not match JWK alg '{}'",
                    header_alg, alg_str
                ));
            }
        }

        let jwk_jose = josekit::jwk::Jwk::from_map(jwk.as_map()).map_err(|e| e.to_string())?;

        let jws_header =
            josekit::jws::JwsHeader::from_map(header.params).map_err(|e| e.to_string())?;

        let jwt_payload =
            josekit::jwt::JwtPayload::from_map(payload.params).map_err(|e| e.to_string())?;

        josekit::jws::serialize_compact(
            serde_json::to_string(jwt_payload.claims_set())
                .map_err(|e| e.to_string())?
                .as_bytes(),
            &jws_header,
            &*jwk_jose.to_signer(Some(&alg_str))?,
        )
        .map_err(|e| e.to_string())
    }

    fn jws_deserialize(&self, jws: String, jwk: &Jwk) -> Result<(Header, Payload), String> {
        let parts: Vec<&str> = jws.split('.').collect();
        if parts.len() != 3 {
            return Err("Invalid JWS".to_owned());
        }
        let header_b64 = parts[0];
        let header_decoded =
            crate::helpers::base64_url_decode(header_b64).map_err(|e| e.to_string())?;
        let parsed_header: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&header_decoded).map_err(|e| e.to_string())?;

        let alg_str = match jwk.get_param("alg").and_then(|v| v.as_str()) {
            Some(alg) => alg.to_owned(),
            None => parsed_header
                .get("alg")
                .and_then(|v| v.as_str())
                .ok_or("neither JWK nor JWT header contain an 'alg' parameter")?
                .to_owned(),
        };

        if let (Some(header_alg), Some(jwk_alg)) = (
            parsed_header.get("alg").and_then(|v| v.as_str()),
            jwk.get_param("alg").and_then(|v| v.as_str()),
        ) {
            if header_alg != jwk_alg {
                return Err(format!(
                    "header alg '{}' does not match JWK alg '{}'",
                    header_alg, jwk_alg
                ));
            }
        }

        let jwk_jose = josekit::jwk::Jwk::from_map(jwk.as_map()).map_err(|e| e.to_string())?;

        let (payload, header) =
            josekit::jws::deserialize_compact(&jws, &*jwk_jose.to_verifier(Some(&alg_str))?)
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
    fn to_signer(
        &self,
        fallback_alg: Option<&str>,
    ) -> Result<Box<dyn josekit::jws::JwsSigner>, &'static str>;

    fn to_verifier(
        &self,
        fallback_alg: Option<&str>,
    ) -> Result<Box<dyn josekit::jws::JwsVerifier>, &'static str>;

    fn to_jwe_decrypter(
        &self,
        fallback_alg: Option<&str>,
    ) -> Result<Box<dyn josekit::jwe::JweDecrypter>, &'static str>;

    fn to_jwe_encrypter(
        &self,
        fallback_alg: Option<&str>,
    ) -> Result<Box<dyn josekit::jwe::JweEncrypter>, &'static str>;
}

impl CustomJwk for josekit::jwk::Jwk {
    fn to_signer(
        &self,
        fallback_alg: Option<&str>,
    ) -> Result<Box<dyn josekit::jws::JwsSigner>, &'static str> {
        let alg = match self.algorithm().or(fallback_alg) {
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

    fn to_verifier(
        &self,
        fallback_alg: Option<&str>,
    ) -> Result<Box<dyn josekit::jws::JwsVerifier>, &'static str> {
        let alg = match self.algorithm().or(fallback_alg) {
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
    fn to_jwe_decrypter(
        &self,
        fallback_alg: Option<&str>,
    ) -> Result<Box<dyn josekit::jwe::JweDecrypter>, &'static str> {
        let alg = match self.algorithm().or(fallback_alg) {
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

    fn to_jwe_encrypter(
        &self,
        fallback_alg: Option<&str>,
    ) -> Result<Box<dyn josekit::jwe::JweEncrypter>, &'static str> {
        let alg = match self.algorithm().or(fallback_alg) {
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

#[cfg(test)]
mod openssl_crypto_tests {
    use super::*;
    use serde_json::{Map, Value};

    const JWK_HS256_NO_ALG: &str = r#"{
    "kty": "oct",
    "k": "n3r3cKt0c0FaRcKGb8oREXm8StLeewv5tk88gxAYnsqLEfJja4rO27loi8W3UNnXlE4tdeOXS6QNhkUU7Qk4y-iizKdyx5XsAOkOfFvIZ673EfbeT1y5oCvl8itwvy9YaxbxSoefDoSZB5fLvPFJjRySE4QNtJbSzx_z5ojpAWAxSBbHDrlHcexGbby6zsZLrQinvwDA0l5CoezDYHHc401KPD1JzXKFZ-VslF6tIbpKH_K9WpozFZwX3vF1LrHItzwVf65hvMK8prSN31eoL8opLZIeZTJy_xcoBGD3wVD8PeyustH2Mw2k6TKNEPYFx22wjXI_IDMOSMMbj57l0Q"
}"#;

    #[test]
    fn should_serialize_and_deserialize_with_no_alg() {
        let jwk = Jwk::try_from(JWK_HS256_NO_ALG).unwrap();

        let mut header_params: Map<String, Value> = Map::new();
        header_params.insert("alg".to_owned(), Value::String("HS256".to_owned()));
        let header = Header {
            params: header_params,
        };

        let mut payload_params: Map<String, Value> = Map::new();
        payload_params.insert("iss".to_owned(), Value::String("client_id".to_owned()));
        let payload = Payload {
            params: payload_params,
        };

        let crypto = OpenSSLCrypto;
        let token = crypto.jws_serialize(payload, header, &jwk).unwrap();

        let (deserialized_header, deserialized_payload) =
            crypto.jws_deserialize(token, &jwk).unwrap();

        assert_eq!(
            deserialized_header.params.get("alg"),
            Some(&Value::String("HS256".to_owned()))
        );
        assert_eq!(
            deserialized_payload.params.get("iss"),
            Some(&Value::String("client_id".to_owned()))
        );
    }

    const JWK_RSA_NO_ALG: &str = r#"{
    "p": "yuXoRLMkoiVD-M6n7xA4_CD3t0I0hmZ6YNO9Sn-dgUrh4ccRUYctyOC_uJ17Mcdlp2KALZiwVlDOWsv4Z6HsDNKgDVdB4WUiPXYfuX4pPKuNiXKQwLCcKqHkAmNZGvl9-8PH0k0H0GXUEUFRA2Dv33zbatrJnDSjnANFidEodvc",
    "kty": "RSA",
    "q": "rhvsOOz3ex8fNA20UGrrqK6vYKPP-_-H7rbOxdAfwqxxBb_MjHASbEU0S--XKprCn2zOOq_Y81pM3zrJZNGcifxwZ0VHb9Jh4uYKOF-hflovcF3l5LIz8LggBHkvHHjmwzcFUe0zesI-q3nae-_vM_sJTAd_5i3FWntgdOc4G20",
    "d": "NowbHxyoT72BeKmwPCdo6FNxdVSFsR116iWCdXHOd0aPw_P0NjFULlyfdZeS_bXIwYeEffsaXdnUeRebqMJCJo8-9BPNrgN8CLwSoyMsp70_hJ-yTG7kDhMz0rJBJlW8JZQR8KBPv-NZ0p59qznLn0qB3kqpefLvqlWb1zYI6SYhYXFhl_ryy3B-qxLK1Gj7jXeZOeZc8RM2iddKGBHFp_9V8eI033gEuQPeNriKDCsy3jihUNdsqYNnVULVAvRS-CWtlImbsGDC8G4VtjA0YpPIqFm_NjMSQf-dFbnd2ZsJfpX3ikycluwAQ8u1WO2rUI_H7shR6XqowcmOOcWBEQ",
    "e": "AQAB",
    "qi": "FFpNLRvQuLDo5cNTNsW-FR7V3cdNWlLQ7D8iOEnZh7SJstqfMeRe2p6hoH3Xn1LwQp_n3wLwOWTQL2nJX5uhfogoOMoMsznCQgCmxE0uESTuQj1Yv5yNNXeJjm1xYGEIX5-CRtdEi7XNieafFJSsw6OIAxm6FizarFC1504TeEg",
    "dp": "dstDQa3tfe35rRw54NOLubsHrklZ_XLUpgpy4sJzEncoZ4upDSXrXZiRR-MUdSG819LpH0ktvWvUVf7kcrCwRxWu1gDHttMCyB94FZ_TPw1mchocvGTrGl7s46UNT6jR5W1MeknVkGN-VZf7edHwv9YXlamBry52uGqF9Vn7qiM",
    "dq": "mG-kE3cNeoOWCzoQa_Qg3bALpn3l5Akm107AnJqKpCPcVJ9HlJGu35J7phxf6pJS4cgei21Ycj_WW_-ZQibvejRFqXUThYjZ4RFtU0wPFZQaQrRDSkbniNN8XM5I_BGyYKp0gvU9hDY7LmDidG5urMEWs7VBOqNKTd0FZ3TlP8U",
    "n": "if5lV0E8Bsb0OPNrWu33V0KuSNRK67vYT3vxzJ3pXIY52oZvSotbpDmcDoldKMfBxuKruOzucH9NNNRPS7viIBIUOz1OBoiWe8MAuTRQCFHQi8L1d5oukq3me-ZYWY7vsCgTfnN2rvCe9aqptWgBWsvGnSqq7EyzCF9mwoiRnIFoo3cyPXloLPXX2kKS6m5XrXkH55g7ZsgGB8nTJ_QbcrgD5l3dWZWWxY0o19hw3Z01ke9Rv1fz1_iClfJ1r7AYmiSw35Eqa6M6UlTkkWyFui7Y2YTuUFEcA6-0ni_UMCJo8b6Ef9dRR1hlfev313PwaOI_sbrmn81JOvDcOc60Kw"
}"#;

    #[test]
    fn should_jwe_serialize_and_deserialize_with_no_alg() {
        let jwk = Jwk::try_from(JWK_RSA_NO_ALG).unwrap();

        let mut header_params: Map<String, Value> = Map::new();
        header_params.insert("alg".to_owned(), Value::String("RSA-OAEP".to_owned()));
        header_params.insert("enc".to_owned(), Value::String("A256GCM".to_owned()));
        let header = Header {
            params: header_params,
        };

        let payload = "my_secret_payload".to_owned();

        let crypto = OpenSSLCrypto;
        let token = crypto.jwe_serialize(payload.clone(), header, &jwk).unwrap();

        let deserialized_payload = crypto.jwe_deserialize(token, &jwk).unwrap();

        assert_eq!(deserialized_payload, payload);
    }
}
