/// JWT Validation
pub mod jwt {
    use crate::{
        defaults::Crypto,
        errors::{OidcReturn, OpenIdError},
        helpers::{base64_url_decode, base64_url_encode, deserialize, unix_timestamp},
        jwk::{Jwk, JwkType},
        types::{
            Header, IssuerMetadata, JweAlg, JwtSigningAlg, OpenIdCrypto, Payload, ValidatedJwt,
        },
    };

    use serde_json::Value;
    use sha2::{Digest, Sha256, Sha384, Sha512};

    /// Configuration parameters for validating a JSON Web Token.
    pub struct JwtValidationParameters<'a> {
        /// The list of JSON Web Keys used for signature verification.
        pub signing_keys: &'a Vec<Jwk>,
        /// Whether to strictly validate the "alg" header against supported algorithms.
        pub check_header_alg: bool,
        /// Supported signing algorithms defined by the OIDC issuer.
        pub issuer_algs: &'a Option<Vec<JwtSigningAlg>>,
        /// Preferred signing algorithms configured for the client.
        pub client_algs: Option<Vec<JwtSigningAlg>>,
        /// Default signing algorithms to use if no other configuration is found.
        pub fallback_algs: Option<Vec<JwtSigningAlg>>,
        /// The allowed clock skew in seconds applied to the current time.
        pub skew: i32,
        /// The allowed tolerance in seconds for expiration and "not before" checks.
        pub tolerance: u32,
    }

    /// Checks if a string has the 5-part structure characteristic of an encrypted JWT (JWE).
    pub fn is_encrypted_jwt(jwe: &str) -> bool {
        jwe.split(".").count() == 5
    }

    /// Checks if a string has the 3-part structure characteristic of a signed JWT (JWS).
    pub fn is_jwt(jwt: &str) -> bool {
        jwt.split(".").count() == 3
    }

    /// Decodes a JWT into its header and payload components without performing cryptographic verification.
    pub fn decode_jwt(jwt: &str) -> OidcReturn<(Header, Payload, String)> {
        let split_token: Vec<&str> = jwt.split('.').collect();

        if is_encrypted_jwt(jwt) {
            return Err(OpenIdError::new_error("encrypted JWTs cannot be decoded"));
        }

        if !is_jwt(jwt) {
            return Err(OpenIdError::new_error("Invalid jwt"));
        }

        let map_err_deserialize = |_| OpenIdError::new_error("JWT is malformed");

        let decoded_header = base64_url_decode(split_token[0])?;
        let decoded_payload = base64_url_decode(split_token[1])?;
        let signature = split_token[2].to_string();

        let header = deserialize::<Header>(&decoded_header).map_err(map_err_deserialize)?;
        let payload = deserialize::<Payload>(&decoded_payload).map_err(map_err_deserialize)?;

        Ok((header, payload, signature))
    }

    /// Extracts and deserializes the header from an encrypted JWT (JWE).
    pub fn jwe_header(jwe: &str) -> OidcReturn<Header> {
        if !is_encrypted_jwt(jwe) {
            return Err(OpenIdError::new_error("not a jwe"));
        }

        let parts: Vec<&str> = jwe.split('.').collect();
        let header_b64 = parts
            .first()
            .ok_or(OpenIdError::new_error("empty header"))?;
        let decoded = base64_url_decode(header_b64)?;
        deserialize::<Header>(&decoded).map_err(OpenIdError::new_error)
    }

    /// Retrieves a single suitable JWK for signature verification based on algorithm and key ID.
    pub fn get_signing_key<'a>(
        issuer_jwks: &'a [Jwk],
        alg: JwtSigningAlg,
        kid: Option<&'a str>,
    ) -> OidcReturn<&'a Jwk> {
        let kty = JwkType::from(alg.clone());

        let candidates: Vec<&Jwk> = issuer_jwks
            .iter()
            .filter(|jwk| {
                if jwk.key_type() != kty {
                    return false;
                }

                if let Some(kid_req) = kid {
                    match jwk.get_param("kid") {
                        Some(Value::String(jwk_kid)) => {
                            if jwk_kid != kid_req {
                                return false;
                            }
                        }
                        _ => {
                            return false;
                        }
                    }
                }

                if let Some(jwk_alg) = jwk.get_param("alg") {
                    if let Ok(jwk_alg) = serde_json::from_value::<JwtSigningAlg>(jwk_alg.clone()) {
                        if alg != jwk_alg {
                            return false;
                        }
                    }
                }

                if let Some(Value::String(jwk_use)) = jwk.get_param("use") {
                    if jwk_use != "sig" {
                        return false;
                    }
                }

                if let Some(Value::Array(jwk_key_ops)) = jwk.get_param("key_ops") {
                    if jwk_key_ops
                        .iter()
                        .filter(|v| v.is_string())
                        // Will not panic
                        .map(|v| v.as_str().unwrap())
                        .find(|v| *v == "verify")
                        .is_none()
                    {
                        return false;
                    }
                }

                let crv = jwk.get_param("crv").and_then(|crv| crv.as_str());

                if alg == JwtSigningAlg::ES256 && crv != Some("P-256") {
                    return false;
                }

                if alg == JwtSigningAlg::ES384 && crv != Some("P-384") {
                    return false;
                }

                if alg == JwtSigningAlg::ES512 && crv != Some("P-521") {
                    return false;
                }

                if alg == JwtSigningAlg::EdDSA && crv != Some("Ed25519") {
                    return false;
                }

                true
            })
            .collect();

        if candidates.is_empty() {
            return Err(OpenIdError::new_error("No suitable jwk found"));
        }

        if candidates.len() > 1 {
            return Err(OpenIdError::new_error("Multiple suitable jwk found"));
        }

        Ok(candidates[0])
    }

    /// Retrieves a suitable JWK for JWE decryption based on algorithm, key ID, and curve parameters.
    pub fn get_jwe_key<'a>(
        jwe_keys: &'a [Jwk],
        alg: JweAlg,
        kid: Option<&'a str>,
        epk_crv: Option<&'a str>,
    ) -> OidcReturn<&'a Jwk> {
        let candidates: Vec<&Jwk> = jwe_keys
            .iter()
            .filter(|jwk| {
                if let Some(kid_req) = kid {
                    match jwk.get_param("kid").and_then(|v| v.as_str()) {
                        Some(jwk_kid) => {
                            if jwk_kid != kid_req {
                                return false;
                            }
                        }
                        None => return false,
                    }
                }

                if let Some(jwk_alg) = jwk
                    .params
                    .get("alg")
                    .and_then(|a| a.as_str())
                    .and_then(JweAlg::from_alg_str)
                {
                    if jwk_alg != alg {
                        return false;
                    }

                    if alg == JweAlg::RsaOaep || alg == JweAlg::RsaOaep256 {
                        return true;
                    }

                    if matches!(
                        alg,
                        JweAlg::EcdhEs
                            | JweAlg::EcdhEsA128Kw
                            | JweAlg::EcdhEsA192Kw
                            | JweAlg::EcdhEsA256Kw
                    ) {
                        match (
                            jwk.key_type(),
                            epk_crv,
                            jwk.params.get("crv").and_then(|c| c.as_str()),
                        ) {
                            (JwkType::Ec, Some(epk_crv), Some(crv)) => return epk_crv == crv,
                            (JwkType::Okp, Some(epk_crv), Some("X25519")) => {
                                return epk_crv == "X25519";
                            }
                            _ => return false,
                        };
                    } else {
                        return false;
                    }
                }

                false
            })
            .collect();

        if candidates.is_empty() {
            return Err(OpenIdError::new_client_error(
                "no applicable decryption key selected",
            ));
        }

        if candidates.len() > 1 {
            return Err(OpenIdError::new_client_error(
                "multiple applicable decryption keys selected",
            ));
        }

        Ok(candidates[0])
    }

    /// Performs complete validation of a JWT, including optional decryption, algorithm checks, and signature verification.
    pub fn validate_jwt(
        mut jwt: String,
        jwt_params: JwtValidationParameters,
        jwe_keys: &[Jwk],
    ) -> OidcReturn<ValidatedJwt> {
        if is_encrypted_jwt(&jwt) {
            let jwe_header = jwe_header(&jwt)?;

            let alg = jwe_header
                .jwe_alg()
                .ok_or(OpenIdError::new_error("JWE does not have alg parameter"))?;
            let kid = jwe_header.params.get("kid").and_then(|kid| kid.as_str());
            let epk_crv = jwe_header
                .params
                .get("epk")
                .and_then(|epk| epk.as_object())
                .and_then(|epk| epk.get("crv"))
                .and_then(|crv| crv.as_str());

            let decrypting_jwk = get_jwe_key(jwe_keys, alg, kid, epk_crv)?;

            jwt = decrypt_jwe(jwt, decrypting_jwk)?;
        }

        if !is_jwt(&jwt) {
            return Err(OpenIdError::new_error("Not a valid jwt"));
        }

        let (mut header, mut payload, _) = decode_jwt(&jwt)?;

        if jwt_params.check_header_alg {
            let algs = jwt_params
                .client_algs
                .as_ref()
                .or(jwt_params.issuer_algs.as_ref())
                .or(jwt_params.fallback_algs.as_ref())
                .ok_or_else(|| {
                    OpenIdError::new_error(
                "missing client or server configuration to verify used JWT \"alg\" header parameter"
            )
                })?;

            let alg = header
                .alg()
                .ok_or_else(|| OpenIdError::new_error("missing JWT \"alg\" header parameter"))?;

            if !algs.contains(&alg) {
                return Err(OpenIdError::new_error(
                    "unexpected JWT \"alg\" header parameter",
                ));
            }
        }

        if header.params.contains_key("crit") {
            return Err(OpenIdError::new_error(
                "no JWT \"crit\" header parameter extensions are supported",
            ));
        }

        let now = unix_timestamp()
            .checked_add_signed(jwt_params.skew as i64)
            .ok_or(OpenIdError::new_error("Could not get skewed timestamp"))?;

        if let Some(exp) = payload.params.get("exp") {
            if let Some(exp) = exp.as_u64() {
                if exp <= now - jwt_params.tolerance as u64 {
                    return Err(OpenIdError::new_error(
                        "unexpected JWT \"exp\" (expiration time) claim value, expiration is past current timestamp",
                    ));
                }
            } else {
                return Err(OpenIdError::new_error(
                    "unexpected JWT \"exp\" (expiration time) claim type",
                ));
            }
        }

        if let Some(iat) = payload.params.get("iat") {
            if !iat.is_u64() {
                return Err(OpenIdError::new_error(
                    "unexpected JWT \"iat\" (issued at) claim type",
                ));
            }
        }

        if let Some(iss) = payload.params.get("iss") {
            if !iss.is_string() {
                return Err(OpenIdError::new_error(
                    "unexpected JWT \"iss\" (issuer) claim type",
                ));
            }
        }

        if let Some(nbf) = payload.params.get("nbf") {
            if let Some(nbf) = nbf.as_u64() {
                if nbf > now + jwt_params.tolerance as u64 {
                    return Err(OpenIdError::new_error(
                        "unexpected JWT \"nbf\" (not before) claim value",
                    ));
                }
            } else {
                return Err(OpenIdError::new_error(
                    "unexpected JWT \"nbf\" (not before) claim type",
                ));
            }
        }

        if let Some(aud) = payload.params.get("aud") {
            if !aud.is_string() && !aud.is_array() {
                return Err(OpenIdError::new_error(
                    "unexpected JWT \"aud\" (audience) claim type",
                ));
            }
        }

        let alg = header
            .alg()
            .ok_or(OpenIdError::new_error("JWT does not have alg parameter"))?;
        let kid = header.params.get("kid").and_then(|kid| kid.as_str());

        let signing_key = get_signing_key(jwt_params.signing_keys, alg, kid)?;

        (header, payload) = Crypto
            .jws_deserialize(jwt, signing_key)
            .map_err(OpenIdError::new_error)?;

        Ok(ValidatedJwt { header, payload })
    }

    /// Decrypts a JWE string using the provided JSON Web Key.
    pub fn decrypt_jwe(jwe: String, jwk: &Jwk) -> OidcReturn<String> {
        Crypto
            .jwe_deserialize(jwe, jwk)
            .map_err(OpenIdError::new_error)
    }

    /// Validates that a list of required claim keys are present in the JWT payload.
    pub fn validate_presence(jwt: &ValidatedJwt, claims: &[&str]) -> OidcReturn<()> {
        for claim in claims {
            if !jwt.payload.params.contains_key(*claim) {
                return Err(OpenIdError::new_error(format!(
                    "Required claim - {claim} is missing from JWT"
                )));
            }
        }

        Ok(())
    }

    /// Verifies that the "iss" claim in the JWT matches the issuer URI from metadata.
    pub fn validate_issuer(jwt: &ValidatedJwt, issuer: &IssuerMetadata) -> OidcReturn<()> {
        match jwt.payload.params.get("iss").and_then(|iss| iss.as_str()) {
            Some(actual_issuer) if actual_issuer == issuer.issuer => Ok(()),
            _ => Err(OpenIdError::new_error(
                "unexpected JWT \"iss\" (issuer) claim value",
            )),
        }
    }

    /// Verifies that the "aud" claim in the JWT contains the expected audience identifier.
    pub fn validate_audience(jwt: &ValidatedJwt, expected: &str) -> OidcReturn<()> {
        match jwt.payload.params.get("aud") {
            Some(Value::String(aud)) => {
                if aud != expected {
                    return Err(OpenIdError::new_error(
                        "unexpected JWT \"aud\" (audience) claim value",
                    ));
                }
            }
            Some(Value::Array(auds)) => {
                let found = auds.iter().any(|v| v.as_str() == Some(expected));
                if !found {
                    return Err(OpenIdError::new_error(
                        "unexpected JWT \"aud\" (audience) claim value",
                    ));
                }
            }
            _ => {
                return Err(OpenIdError::new_error("missing or invalid \"aud\" claim"));
            }
        }

        Ok(())
    }

    /// Compares a data string against a hash value using the specified signing algorithm's hash function.
    pub fn hash_match(alg: &JwtSigningAlg, data: &str, expected: &str) -> bool {
        let hash = match alg {
            JwtSigningAlg::HS256
            | JwtSigningAlg::RS256
            | JwtSigningAlg::ES256
            | JwtSigningAlg::ES256K
            | JwtSigningAlg::PS256 => Sha256::digest(data)[..].to_vec(),
            JwtSigningAlg::HS384
            | JwtSigningAlg::RS384
            | JwtSigningAlg::ES384
            | JwtSigningAlg::PS384 => Sha384::digest(data)[..].to_vec(),
            JwtSigningAlg::HS512
            | JwtSigningAlg::RS512
            | JwtSigningAlg::ES512
            | JwtSigningAlg::PS512
            | JwtSigningAlg::EdDSA => Sha512::digest(data)[..].to_vec(),
        };

        let encoded = base64_url_encode(&hash[0..hash.len() / 2]);

        encoded == expected
    }
}

/// Authorization Code Validation
pub mod authorization_code {
    use std::{collections::HashMap, vec};

    use crate::{
        client_utils::jwt::{
            hash_match, validate_audience, validate_issuer, validate_jwt, validate_presence,
            JwtValidationParameters,
        },
        config::OpenIdClientConfiguration,
        errors::{OidcReturn, OpenIdError},
        helpers::unix_timestamp,
        token_set::TokenSet,
        types::{JwtSigningAlg, MaxAgeCheck, NonceCheck, StateCheck},
    };

    /// Validates a JWT-based Authorization Response (JARM) and returns the extracted parameters.
    pub fn validate_jarm(
        config: &OpenIdClientConfiguration,
        callback_params: HashMap<String, String>,
        state_check: StateCheck,
    ) -> OidcReturn<HashMap<String, String>> {
        let response_jwt = callback_params
            .get("response")
            .map(String::to_owned)
            .ok_or(OpenIdError::new_error(
                "callback_params does not contain a JARM response",
            ))?;

        let jwt_validation_params = JwtValidationParameters {
            signing_keys: &config.issuer_jwks,
            check_header_alg: true,
            issuer_algs: &config.issuer.authorization_signing_alg_values_supported,
            client_algs: config
                .client
                .authorization_signed_response_alg
                .clone()
                .map(|alg| vec![alg]),
            fallback_algs: Some(vec![JwtSigningAlg::RS256]),
            skew: config.options.clock_skew,
            tolerance: config.options.clock_tolerance,
        };

        let validated_jwt = validate_jwt(response_jwt, jwt_validation_params, &config.jwe_keys)?;
        validate_presence(&validated_jwt, &["aud", "exp", "iss"])?;
        validate_issuer(&validated_jwt, &config.issuer)?;
        validate_audience(&validated_jwt, &config.client.client_id)?;

        let mut callback_params = HashMap::new();

        for (key, value) in validated_jwt.payload.params {
            if key != "aud" {
                if let Some(value) = value.as_str() {
                    callback_params.insert(key, value.to_owned());
                }
            }
        }

        validate_auth_response(
            &config.issuer.issuer,
            config
                .issuer
                .authorization_response_iss_parameter_supported
                .is_some_and(|s| s),
            callback_params,
            state_check,
        )
    }

    /// Validates an OIDC hybrid flow response, ensuring the ID Token, code, and hashes are correct.
    pub fn validate_hybrid_response(
        config: &OpenIdClientConfiguration,
        mut callback_params: HashMap<String, String>,
        state_check: StateCheck,
        nonce_check: Option<NonceCheck>,
        max_age_check: Option<MaxAgeCheck>,
    ) -> OidcReturn<HashMap<String, String>> {
        let id_token = callback_params.get("id_token").map(String::to_owned);
        callback_params.remove("id_token");

        let expect_state = matches!(state_check, StateCheck::Expected(..));

        let callback_params =
            validate_auth_response(&config.issuer.issuer, false, callback_params, state_check)?;

        let id_token = match id_token {
            Some(it) => it,
            None => {
                return Err(OpenIdError::new_error(
                    "\"parameters\" does not contain an ID Token",
                ));
            }
        };

        let code = callback_params.get("code").ok_or(OpenIdError::new_error(
            "\"parameters\" does not contain Authorization Code",
        ))?;

        let mut required_claims = vec!["aud", "exp", "iat", "iss", "sub", "nonce", "c_hash"];

        let state = callback_params.get("state");

        if config.fapi && (expect_state || state.is_some()) {
            required_claims.push("s_hash");
        }

        let max_age_check = max_age_check
            .or(config.client.default_max_age.map(MaxAgeCheck::MaxAge))
            .unwrap_or(MaxAgeCheck::Skip);

        if config.client.require_auth_time.is_some_and(|rat| rat)
            || !matches!(max_age_check, MaxAgeCheck::Skip)
        {
            required_claims.push("auth_time");
        }

        let jwt_validation_params = JwtValidationParameters {
            signing_keys: &config.issuer_jwks,
            check_header_alg: true,
            issuer_algs: &config.issuer.id_token_signing_alg_values_supported,
            client_algs: config
                .client
                .id_token_signed_response_alg
                .clone()
                .map(|alg| vec![alg]),
            fallback_algs: Some(vec![JwtSigningAlg::RS256]),
            skew: config.options.clock_skew,
            tolerance: config.options.clock_tolerance,
        };

        let validated_jwt = validate_jwt(id_token, jwt_validation_params, &config.jwe_keys)?;
        validate_presence(&validated_jwt, &required_claims)?;
        validate_issuer(&validated_jwt, &config.issuer)?;
        validate_audience(&validated_jwt, &config.client.client_id)?;

        let now = unix_timestamp()
            .checked_add_signed(config.options.clock_skew as i64)
            .ok_or(OpenIdError::new_error("Could not get skewed timestamp"))?;

        match validated_jwt
            .payload
            .params
            .get("iat")
            .and_then(|iat| iat.as_u64())
        {
            Some(iat) => {
                if iat < now - 3600 {
                    return Err(OpenIdError::new_error(
                        "unexpected JWT \"iat\" (issued at) claim value, it is too far in the past",
                    ));
                }
            }
            None => {
                return Err(OpenIdError::new_error(
                    "\"iat\" claim not found in the id token",
                ))
            }
        };

        if validated_jwt
            .payload
            .params
            .get("c_hash")
            .is_some_and(|ch| !ch.is_string())
        {
            return Err(OpenIdError::new_error(
                "ID Token \"c_hash\" (code hash) claim value must be a string",
            ));
        }

        if validated_jwt.payload.params.contains_key("auth_time")
            && validated_jwt
                .payload
                .params
                .get("auth_time")
                .is_some_and(|auth_time| !auth_time.is_u64())
        {
            return Err(OpenIdError::new_error(
                "ID Token \"auth_time\" (authentication time) must be a number",
            ));
        }

        match max_age_check {
            MaxAgeCheck::Skip => {}
            MaxAgeCheck::MaxAge(max_age) => {
                let now = unix_timestamp()
                    .checked_add_signed(config.options.clock_skew as i64)
                    .ok_or(OpenIdError::new_error("Could not get skewed timestamp"))?;

                let auth_time = validated_jwt
                    .payload
                    .params
                    .get("auth_time")
                    .and_then(|at| at.as_u64())
                    .ok_or(OpenIdError::new_error("auth_time not found"))?;

                if auth_time + max_age < now - config.options.clock_tolerance as u64 {
                    return Err(OpenIdError::new_error(
                        "too much time has elapsed since the last End-User authentication",
                    ));
                }
            }
        }

        let nonce = validated_jwt
            .payload
            .params
            .get("nonce")
            .and_then(|n| n.as_str())
            .ok_or(OpenIdError::new_error(
                "unexpected ID Token \"nonce\" claim value",
            ))?;

        if let Some(NonceCheck::Nonce(expected_nonce)) = nonce_check {
            if nonce != expected_nonce {
                return Err(OpenIdError::new_error(
                    "unexpected ID Token \"nonce\" claim value",
                ));
            }
        } else {
            return Err(OpenIdError::new_error(
                "nonce_check is required for hybrid flow",
            ));
        }

        if let Some(aud_length) = validated_jwt
            .payload
            .params
            .get("aud")
            .and_then(|aud| aud.as_array())
            .map(|aud| aud.len())
        {
            if aud_length != 1 {
                let azp = validated_jwt
                    .payload
                    .params
                    .get("azp")
                    .and_then(|azp| azp.as_str())
                    .ok_or(OpenIdError::new_error(
                        "ID Token \"aud\" (audience) claim includes additional untrusted audiences",
                    ))?;

                if azp != config.client.client_id {
                    return Err(OpenIdError::new_error(
                        "unexpected ID Token \"azp\" (authorized party) claim value",
                    ));
                }
            }
        }

        let c_hash = validated_jwt
            .payload
            .params
            .get("c_hash")
            .and_then(|n| n.as_str())
            .ok_or(OpenIdError::new_error(
                "unexpected ID Token \"c_hash\" claim value",
            ))?;

        let alg = validated_jwt
            .header
            .alg()
            .ok_or(OpenIdError::new_error("did not find \"alg\" in header"))?;

        if !hash_match(&alg, code, c_hash) {
            return Err(OpenIdError::new_error(
                "invalid ID Token \"c_hash\" (code hash) claim value",
            ));
        }

        if (config.fapi && state.is_some())
            || validated_jwt
                .payload
                .params
                .get("s_hash")
                .is_some_and(|sh| sh.is_string())
        {
            let s_hash = validated_jwt
                .payload
                .params
                .get("s_hash")
                .and_then(|sh| sh.as_str())
                .ok_or(OpenIdError::new_error("invalid \"s_hash\" value"))?;

            let state = state.ok_or(OpenIdError::new_error(
                "\"parameters\" do not contain state",
            ))?;

            if !hash_match(&alg, state, s_hash) {
                return Err(OpenIdError::new_error(
                    "invalid ID Token \"s_hash\" (state hash) claim value",
                ));
            }
        }

        Ok(callback_params)
    }

    /// Performs basic validation on authorization response parameters, checking for errors, state mismatch, and issuer consistency.
    pub fn validate_auth_response(
        issuer: &str,
        auth_response_iss_supported: bool,
        callback_params: HashMap<String, String>,
        state_check: StateCheck,
    ) -> OidcReturn<HashMap<String, String>> {
        if callback_params.contains_key("response") {
            return Err(OpenIdError::new_error(
                "\"parameters\" contains a JARM response",
            ));
        }

        let iss = callback_params.get("iss");

        match iss {
            Some(iss) => {
                if iss != issuer {
                    return Err(OpenIdError::new_error(
                        "unexpected \"iss\" (issuer) response parameter value",
                    ));
                }
            }
            None => {
                if auth_response_iss_supported {
                    return Err(OpenIdError::new_error(
                        "response parameter \"iss\" (issuer) missing",
                    ));
                }
            }
        }

        let state = callback_params.get("state").map(String::as_str);

        match state_check {
            StateCheck::ExpectNoState => {
                if state.is_some() {
                    return Err(OpenIdError::new_error(
                        "unexpected \"state\" response parameter encountered",
                    ));
                }
            }
            StateCheck::Skip => {}
            StateCheck::Expected(expected_state) => {
                if state != Some(&expected_state) {
                    let message = if state.is_none() {
                        "response parameter \"state\" missing"
                    } else {
                        "unexpected \"state\" response parameter value"
                    };
                    return Err(OpenIdError::new_error(message));
                }
            }
        };

        if let Some(error) = callback_params.get("error") {
            let error_description = callback_params
                .get("error_description")
                .map(String::to_owned);
            let error_uri = callback_params.get("error_uri").map(String::to_owned);

            return Err(OpenIdError::new_op_error(
                error,
                error_description,
                error_uri,
            ));
        }

        if callback_params.contains_key("id_token") || callback_params.contains_key("token") {
            return Err(OpenIdError::new_error(
                "implicit or hybrid flows not supported",
            ));
        }

        Ok(callback_params)
    }

    /// Validates an OIDC authorization code flow response, verifying the TokenSet and its ID Token claims.
    pub fn validate_auth_code_openid_response(
        config: &OpenIdClientConfiguration,
        tokenset: TokenSet,
        nonce_check: NonceCheck,
        max_age_check: Option<MaxAgeCheck>,
    ) -> OidcReturn<TokenSet> {
        let mut required_claims = vec![];

        if matches!(nonce_check, NonceCheck::Nonce(..)) {
            required_claims.push("nonce");
        }

        let max_age_check = internal_max_age_extract(config, max_age_check, &mut required_claims);

        let token_set = validate_access_token_response(config, tokenset, &required_claims, true)?;

        internal_max_age_check(config, max_age_check, &token_set)?;

        let nonce = token_set.claims().and_then(|c| {
            c.get("nonce")
                .and_then(|n| n.as_str())
                .map(|n| n.to_owned())
        });

        match nonce_check {
            NonceCheck::ExpectNoNonce => {
                if nonce.is_some() {
                    return Err(OpenIdError::new_error(
                        "unexpected ID Token \"nonce\" claim value",
                    ));
                }
            }
            NonceCheck::Nonce(expected_nonce) => {
                if nonce != Some(expected_nonce) {
                    return Err(OpenIdError::new_error(
                        "unexpected ID Token \"nonce\" claim value",
                    ));
                }
            }
        }

        Ok(token_set)
    }

    /// Validates an OAuth 2.0 authorization code flow response that lacks standard OIDC ID Token features.
    pub fn validate_auth_code_oauth_response(
        config: &OpenIdClientConfiguration,
        tokenset: TokenSet,
    ) -> OidcReturn<TokenSet> {
        let tokenset = validate_access_token_response(config, tokenset, &[], true)?;

        if let Some(claims) = tokenset.claims() {
            if let Some(default_max_age) = config.client.default_max_age {
                let now = unix_timestamp()
                    .checked_add_signed(config.options.clock_skew as i64)
                    .ok_or(OpenIdError::new_error("Could not get skewed timestamp"))?;

                let auth_time = claims
                    .get("auth_time")
                    .and_then(|at| at.as_u64())
                    .ok_or(OpenIdError::new_error("\"auth_time\" not found in claims"))?;

                if auth_time + default_max_age < now - config.options.clock_tolerance as u64 {
                    return Err(OpenIdError::new_error(
                        "too much time has elapsed since the last End-User authentication",
                    ));
                }
            }

            if claims.contains_key("nonce") {
                return Err(OpenIdError::new_error(
                    "unexpected ID Token \"nonce\" claim value",
                ));
            }
        }

        Ok(tokenset)
    }

    /// Validates an implicit flow response, ensuring the returned tokens and nonce are valid.
    pub fn validate_implicit_response(
        config: &OpenIdClientConfiguration,
        tokenset: TokenSet,
        expect_id_token: bool,
        nonce_check: Option<NonceCheck>,
        max_age_check: Option<MaxAgeCheck>,
    ) -> OidcReturn<TokenSet> {
        let mut required_claims = vec![];

        if expect_id_token && nonce_check.is_none() {
            return Err(OpenIdError::new_error(
                "nonce_check is required for implicit grant validation when id_token is present",
            ));
        }

        if matches!(nonce_check, Some(NonceCheck::Nonce(..))) {
            required_claims.push("nonce");
        }

        let max_age_check = internal_max_age_extract(config, max_age_check, &mut required_claims);

        let token_set = validate_access_token_response(config, tokenset, &required_claims, false)?;

        internal_max_age_check(config, max_age_check, &token_set)?;

        let nonce = token_set.claims().and_then(|c| {
            c.get("nonce")
                .and_then(|n| n.as_str())
                .map(|n| n.to_owned())
        });

        match nonce_check {
            Some(NonceCheck::ExpectNoNonce) if nonce.is_some() => {
                return Err(OpenIdError::new_error(
                    "unexpected ID Token \"nonce\" claim value",
                ));
            }
            Some(NonceCheck::Nonce(expected_nonce)) if nonce.as_ref() != Some(&expected_nonce) => {
                return Err(OpenIdError::new_error(
                    "unexpected ID Token \"nonce\" claim value",
                ));
            }
            _ => {}
        }

        Ok(token_set)
    }

    /// Internal helper to validate a TokenSet's structure and the cryptographic integrity of its ID Token.
    pub fn validate_access_token_response(
        config: &OpenIdClientConfiguration,
        mut tokenset: TokenSet,
        additional_required_claims: &[&str],
        check_access_token_presence: bool,
    ) -> OidcReturn<TokenSet> {
        if check_access_token_presence && tokenset.access_token.is_none() {
            return Err(OpenIdError::new_error(
                "access_token not found in token response",
            ));
        }

        if tokenset.token_type.is_none() {
            return Err(OpenIdError::new_error(
                "token_type not found in token response",
            ));
        }

        if let Some(id_token) = tokenset.id_token {
            let mut required_claims = vec!["aud", "exp", "iat", "iss", "sub"];

            if config.client.require_auth_time.is_some_and(|rat| rat) {
                required_claims.push("auth_time");
            }

            if config.client.default_max_age.is_some() && !required_claims.contains(&"auth_time") {
                required_claims.push("auth_time");
            }

            for claim in additional_required_claims {
                if !required_claims.contains(claim) {
                    required_claims.push(*claim);
                }
            }

            let jwt_validation_params = JwtValidationParameters {
                signing_keys: &config.issuer_jwks,
                check_header_alg: true,
                issuer_algs: &config.issuer.id_token_signing_alg_values_supported,
                client_algs: config
                    .client
                    .id_token_signed_response_alg
                    .clone()
                    .map(|alg| vec![alg]),
                fallback_algs: Some(vec![JwtSigningAlg::RS256]),
                skew: config.options.clock_skew,
                tolerance: config.options.clock_tolerance,
            };

            let validated_jwt =
                validate_jwt(id_token.clone(), jwt_validation_params, &config.jwe_keys)?;
            validate_presence(&validated_jwt, &required_claims)?;
            validate_issuer(&validated_jwt, &config.issuer)?;
            validate_audience(&validated_jwt, &config.client.client_id)?;

            if let Some(aud_length) = validated_jwt
                .payload
                .params
                .get("aud")
                .and_then(|aud| aud.as_array())
                .map(|aud| aud.len())
            {
                if aud_length != 1 {
                    let azp = validated_jwt
                    .payload
                    .params
                    .get("azp")
                    .and_then(|azp| azp.as_str())
                    .ok_or(OpenIdError::new_error(
                        "ID Token \"aud\" (audience) claim includes additional untrusted audiences",
                    ))?;

                    if azp != config.client.client_id {
                        return Err(OpenIdError::new_error(
                            "unexpected ID Token \"azp\" (authorized party) claim value",
                        ));
                    }
                }
            }

            if validated_jwt
                .payload
                .params
                .get("auth_time")
                .is_some_and(|at| !at.is_u64())
            {
                return Err(OpenIdError::new_error(
                    "ID Token \"auth_time\" (authentication time)",
                ));
            }

            if let Some(ref access_token) = tokenset.access_token {
                if let Some(at_hash) = validated_jwt
                    .payload
                    .params
                    .get("at_hash")
                    .and_then(|ah| ah.as_str())
                {
                    let alg = validated_jwt.header.alg().ok_or(OpenIdError::new_error(
                        "missing JWT \"alg\" header parameter",
                    ))?;

                    if !hash_match(&alg, access_token, at_hash) {
                        return Err(OpenIdError::new_error(
                            "invalid ID Token \"at_hash\" (access token hash) claim value",
                        ));
                    }
                }
            }

            tokenset.id_token = Some(id_token);
        }

        Ok(tokenset)
    }

    fn internal_max_age_extract(
        config: &OpenIdClientConfiguration,
        max_age_check: Option<MaxAgeCheck>,
        required_claims: &mut Vec<&str>,
    ) -> MaxAgeCheck {
        let max_age_check = max_age_check
            .or(config.client.default_max_age.map(MaxAgeCheck::MaxAge))
            .unwrap_or(MaxAgeCheck::Skip);

        if matches!(max_age_check, MaxAgeCheck::MaxAge(..)) {
            required_claims.push("auth_time");
        }
        max_age_check
    }

    fn internal_max_age_check(
        config: &OpenIdClientConfiguration,
        max_age_check: MaxAgeCheck,
        token_set: &TokenSet,
    ) -> Result<(), OpenIdError> {
        match max_age_check {
            MaxAgeCheck::Skip => {}
            MaxAgeCheck::MaxAge(max_age) => {
                let now = unix_timestamp()
                    .checked_add_signed(config.options.clock_skew as i64)
                    .ok_or(OpenIdError::new_error("Could not get skewed timestamp"))?;

                let auth_time = token_set
                    .claims()
                    .and_then(|c| c.get("auth_time").and_then(|at| at.as_u64()))
                    .ok_or(OpenIdError::new_error("\"auth_time\" not found in claims"))?;

                if auth_time + max_age < now - config.options.clock_tolerance as u64 {
                    return Err(OpenIdError::new_error(
                        "too much time has elapsed since the last End-User authentication",
                    ));
                }
            }
        };
        Ok(())
    }
}
