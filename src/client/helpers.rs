use std::{
    collections::HashMap,
    time::{Duration, SystemTime},
};

use base64::{engine::general_purpose, Engine};
use josekit::{
    jwk::Jwk,
    jws::{self, JwsHeader},
    jwt::{decode_with_verifier, JwtPayload},
};
use lazy_static::lazy_static;
use regex::Regex;
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Method,
};
use serde_json::{json, Value};
use url::Url;

use crate::{
    helpers::{decode_jwt, get_jwk_thumbprint_s256, random, validate_hash, Names},
    http::request_async,
    tokenset::TokenSet,
    types::{
        query_keystore::QueryKeyStore, AuthenticationPostParams, AuthorizationParameters,
        OidcClientError, Response,
    },
};
use crate::{jwks::jwks::CustomJwk, types::Request};
use sha2::{Digest, Sha256, Sha384, Sha512};

use super::Client;

lazy_static! {
    static ref AGCMKW_REGEX: Regex = Regex::new(r"^A(\d{3})(?:GCM)?KW$").unwrap();
    static ref AGCMCBC_REGEX: Regex = Regex::new(r"^A(\d{3})(?:GCM|CBC-HS(\d{3}))$").unwrap();
    static ref HS_REGEX: Regex = Regex::new("^HS(?:256|384|512)").unwrap();
    static ref EXPECTED_ALG_REGEX: Regex = Regex::new("^(?:RSA|ECDH)").unwrap();
    static ref NQCHAR_REGEX: Regex = Regex::new(r"^[\x21\x23-\x5B\x5D-\x7E]+$").unwrap();
}

impl Client {
    pub(crate) fn secret_for_alg(&self, alg: &str) -> Result<Jwk, OidcClientError> {
        let mut jwk = Jwk::new("oct");
        jwk.set_algorithm(alg);

        if let Some(cs) = &self.client_secret {
            if let Some(first_group) = AGCMKW_REGEX.captures_iter(alg).next() {
                if let Some(extracted_alg) = first_group.get(1) {
                    jwk.set_key_use("enc");
                    jwk.set_key_value(
                        self.encryption_secret(extracted_alg.as_str().parse::<u16>().unwrap())?,
                    );
                    return Ok(jwk);
                }
            }

            if let Some(first_group) = AGCMCBC_REGEX.captures_iter(alg).next() {
                if let Some(extracted_alg) = first_group.get(2).or(first_group.get(1)) {
                    jwk.set_key_use("enc");
                    jwk.set_key_value(
                        self.encryption_secret(extracted_alg.as_str().parse::<u16>().unwrap())?,
                    );
                    jwk.set_algorithm("dir");
                    return Ok(jwk);
                }
            }

            jwk.set_key_value(cs);

            return Ok(jwk);
        }
        Err(OidcClientError::new_type_error(
            "client_secret is required",
            None,
        ))
    }

    pub(crate) fn encryption_secret(&self, len: u16) -> Result<Vec<u8>, OidcClientError> {
        if let Some(cs) = &self.client_secret {
            return match len {
                l if l <= 256 => {
                    let hasher = Sha256::new_with_prefix(cs.as_bytes());
                    Ok((hasher.finalize()[..(len / 8) as usize]).to_vec())
                }
                l if l <= 384 => {
                    let hasher = Sha384::new_with_prefix(cs.as_bytes());
                    Ok((hasher.finalize()[..(len / 8) as usize]).to_vec())
                }
                l if l <= 512 => {
                    let hasher = Sha512::new_with_prefix(cs.as_bytes());
                    Ok((hasher.finalize()[..(len / 8) as usize]).to_vec())
                }
                _ => Err(OidcClientError::new_error(
                    "unsupported symmetric encryption key derivation",
                    None,
                )),
            };
        }

        Err(OidcClientError::new_type_error(
            "client_secret is required",
            None,
        ))
    }

    pub(crate) fn authorization_params(
        &self,
        params: &AuthorizationParameters,
    ) -> AuthorizationParameters {
        let mut new_params = AuthorizationParameters {
            client_id: Some(self.client_id.clone()),
            scope: Some(vec!["openid".to_string()]),
            response_type: self.resolve_response_type().map(|x| vec![x]),
            redirect_uri: self.resolve_redirect_uri(),
            ..Default::default()
        };

        if params.client_id.is_some() {
            new_params.client_id = params.client_id.to_owned();
        }
        if params.acr_values.is_some() {
            new_params.acr_values = params.acr_values.to_owned();
        }
        if params.audience.is_some() {
            new_params.audience = params.audience.to_owned();
        }
        if params.claims.is_some() {
            new_params.claims = params.claims.to_owned();
        }
        if params.claims_locales.is_some() {
            new_params.claims_locales = params.claims_locales.to_owned();
        }
        if params.code_challenge_method.is_some() {
            new_params.code_challenge_method = params.code_challenge_method.to_owned();
        }
        if params.code_challenge.is_some() {
            new_params.code_challenge = params.code_challenge.to_owned();
        }
        if params.display.is_some() {
            new_params.display = params.display.to_owned();
        }
        if params.id_token_hint.is_some() {
            new_params.id_token_hint = params.id_token_hint.to_owned();
        }
        if params.login_hint.is_some() {
            new_params.login_hint = params.login_hint.to_owned();
        }
        if params.max_age.is_some() {
            new_params.max_age = params.max_age.to_owned();
        }
        if params.nonce.is_some() {
            new_params.nonce = params.nonce.to_owned();
        }
        if params.prompt.is_some() {
            new_params.prompt = params.prompt.to_owned();
        }
        if params.redirect_uri.is_some() {
            new_params.redirect_uri = params.redirect_uri.to_owned();
        }
        if params.registration.is_some() {
            new_params.registration = params.registration.to_owned();
        }
        if params.request_uri.is_some() {
            new_params.request_uri = params.request_uri.to_owned();
        }
        if params.request.is_some() {
            new_params.request = params.request.to_owned();
        }
        if params.response_mode.is_some() {
            new_params.response_mode = params.response_mode.to_owned();
        }
        if params.response_type.is_some() {
            new_params.response_type = params.response_type.to_owned();
        }
        if params.resource.is_some() {
            new_params.resource = params.resource.to_owned();
        }
        if params.scope.is_some() {
            new_params.scope = params.scope.to_owned();
        }
        if params.state.is_some() {
            new_params.state = params.state.to_owned();
        }
        if params.ui_locales.is_some() {
            new_params.ui_locales = params.ui_locales.to_owned();
        }
        new_params.other = params.other.to_owned();

        new_params
    }

    fn resolve_response_type(&self) -> Option<String> {
        if self.response_types.len() == 1 {
            return Some(self.response_types[0].clone());
        }
        None
    }

    fn resolve_redirect_uri(&self) -> Option<String> {
        if let Some(ru) = &self.redirect_uris {
            if ru.len() == 1 {
                return Some(ru[0].clone());
            }
        }
        None
    }

    pub(crate) fn get_auth_endpoint(&self) -> Result<Url, OidcClientError> {
        let authorization_endpiont = match &self.issuer {
            Some(i) => match &i.authorization_endpoint {
                Some(ae) => match Url::parse(ae) {
                    Ok(u) => u,
                    Err(_) => {
                        return Err(OidcClientError::new_type_error(
                            "authorization_endpiont is invalid url",
                            None,
                        ));
                    }
                },
                None => {
                    return Err(OidcClientError::new_type_error(
                        "authorization_endpiont must be configured on the issuer",
                        None,
                    ))
                }
            },
            None => return Err(OidcClientError::new_error("issuer is empty", None)),
        };
        Ok(authorization_endpiont)
    }

    pub(crate) async fn authenticated_post_async<'a>(
        &mut self,
        endpoint: &str,
        mut req: Request,
        params: AuthenticationPostParams<'a>,
    ) -> Result<Response, OidcClientError> {
        let endpoint_auth_method = params.endpoint_auth_method.unwrap_or(endpoint);

        let auth_request = self.auth_for(endpoint_auth_method, params.client_assertion_payload)?;

        req.merge_form(&auth_request);
        req.merge_headers(&auth_request);

        let auth_method = match endpoint_auth_method {
            "token" => self.token_endpoint_auth_method.as_ref(),
            "introspection" => self.introspection_endpoint_auth_method.as_ref(),
            "revocation" => self.revocation_endpoint_auth_method.as_ref(),
            _ => return Err(OidcClientError::new_error("unknown endpoint", None)),
        };

        let auth_method_has_tls = match auth_method {
            Some(values) => values.contains("tls_client_auth"),
            None => false,
        };

        let mtls = auth_method_has_tls
            || (endpoint == "token"
                && self
                    .tls_client_certificate_bound_access_tokens
                    .map_or(false, |v| v));

        let issuer = self.issuer.as_ref().ok_or(OidcClientError::new_error(
            "Issuer is required for authenticated_post",
            None,
        ))?;

        let mut target_url: Option<&String> = None;

        if mtls {
            let aliases = issuer.mtls_endpoint_aliases.as_ref();

            target_url = match endpoint {
                "token" => aliases.and_then(|a| a.token_endpoint.as_ref()),
                "introspection" => aliases.and_then(|a| a.introspection_endpoint.as_ref()),
                "revocation" => aliases.and_then(|a| a.revocation_endpoint.as_ref()),
                "device_authorization" => {
                    aliases.and_then(|a| a.device_authorization_endpoint.as_ref())
                }
                _ => return Err(OidcClientError::new_error("unknown endpoint", None)),
            };
        }

        if target_url.is_none() {
            target_url = match endpoint {
                "token" => issuer.token_endpoint.as_ref(),
                "introspection" => issuer.introspection_endpoint.as_ref(),
                "revocation" => issuer.revocation_endpoint.as_ref(),
                "device_authorization" => issuer.device_authorization_endpoint.as_ref(),
                "pushed_authorization_request" => {
                    issuer.pushed_authorization_request_endpoint.as_ref()
                }
                _ => return Err(OidcClientError::new_error("unknown endpoint", None)),
            };
        }

        req.url = target_url
            .ok_or(OidcClientError::new_error(
                "endpoint does not exist in Issuer or Client",
                None,
            ))?
            .to_owned();

        if endpoint != "revocation" {
            req.headers
                .insert("accept", HeaderValue::from_static("application/json"));
        }

        req.method = Method::POST;
        req.mtls = mtls;

        self.instance_request_async(req, params.dpop, None).await
    }

    pub(crate) fn auth_for(
        &self,
        endpoint: &str,
        client_assertion_payload: Option<&HashMap<String, Value>>,
    ) -> Result<Request, OidcClientError> {
        let endpiont_auth_method = match endpoint {
            "token" => self.token_endpoint_auth_method.as_ref(),
            "revocation" => self.revocation_endpoint_auth_method.as_ref(),
            "introspection" => self.introspection_endpoint_auth_method.as_ref(),
            _ => {
                return Err(OidcClientError::new_type_error(
                    &format!("missing, or unsupported, {}_endpoint_auth_method", endpoint),
                    None,
                ))
            }
        };

        let auth_method = endpiont_auth_method.ok_or(OidcClientError::new_type_error(
            &format!("missing, or unsupported, {}_endpoint_auth_method", endpoint),
            None,
        ))?;

        match auth_method.as_str() {
            "self_signed_tls_client_auth" | "tls_client_auth" | "none" => {
                let mut request = Request::default();

                let mut form: HashMap<String, Value> = HashMap::new();

                form.insert("client_id".to_string(), json!(self.client_id));

                request.form = Some(form);

                Ok(request)
            }
            "client_secret_post" => {
                if self.client_secret.is_none() {
                    return Err(OidcClientError::new_type_error(
                        "client_secret_post client authentication method requires a client_secret",
                        None,
                    ));
                }

                let mut request = Request::default();

                let mut form: HashMap<String, Value> = HashMap::new();

                form.insert("client_id".to_string(), json!(self.client_id));
                form.insert(
                    "client_secret".to_string(),
                    json!(self.client_secret.clone().unwrap()),
                );

                request.form = Some(form);

                Ok(request)
            }
            "private_key_jwt" | "client_secret_jwt" => {
                let iat = (self.now)();
                let exp = iat + 60;
                let mut jwt_payload = JwtPayload::new();

                if let Some(i) = SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(iat as u64))
                {
                    jwt_payload.set_issued_at(&i);
                }

                if let Some(e) = SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(exp as u64))
                {
                    jwt_payload.set_expires_at(&e);
                }

                jwt_payload.set_jwt_id(&random());
                jwt_payload.set_issuer(&self.client_id);
                jwt_payload.set_subject(&self.client_id);

                match &self.issuer {
                    Some(issuer) => {
                        let mut values = vec![issuer.issuer.clone()];

                        if let Some(token_endpoint) = &issuer.token_endpoint {
                            values.push(token_endpoint.clone());
                        }

                        jwt_payload.set_audience(values);
                    }
                    None => {}
                }

                if let Some(cap) = client_assertion_payload {
                    for (k, v) in cap {
                        jwt_payload
                            .set_claim(k, Some(v.to_owned()))
                            .map_err(|_| OidcClientError::new_error("invalid claim value", None))?;
                    }
                }

                let assertion = self.client_assertion(endpoint, jwt_payload)?;

                let mut request = Request::default();

                let mut form: HashMap<String, Value> = HashMap::new();

                form.insert("client_id".to_string(), json!(self.client_id));
                form.insert("client_assertion".to_string(), json!(assertion));
                form.insert(
                    "client_assertion_type".to_string(),
                    json!("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                );

                request.form = Some(form);

                Ok(request)
            }
            "client_secret_basic" => {
                if self.client_secret.is_none() {
                    return Err(OidcClientError::new_type_error(
                        "client_secret_basic client authentication method requires a client_secret",
                        None,
                    ));
                }

                let mut request = Request::default();

                let mut headers = HeaderMap::new();

                let encoded = format!(
                    "{}:{}",
                    urlencoding::encode(&self.client_id),
                    urlencoding::encode(&self.client_secret.clone().unwrap())
                )
                .replace("%20", "+");

                let b64 = general_purpose::STANDARD.encode(encoded);

                headers.insert(
                    "Authorization",
                    HeaderValue::from_bytes(format!("Basic {}", b64).as_bytes()).map_err(|_| {
                        OidcClientError::new_error(
                            "error converting client_secret_basic value to header value",
                            None,
                        )
                    })?,
                );

                request.headers = headers;

                Ok(request)
            }
            _ => Err(OidcClientError::new_type_error(
                &format!("missing, or unsupported, {}_endpoint_auth_method", endpoint),
                None,
            )),
        }
    }

    fn client_assertion(
        &self,
        endpoint: &str,
        payload: JwtPayload,
    ) -> Result<String, OidcClientError> {
        let (mut alg, endpiont_auth_method) = match endpoint {
            "token" => (
                self.token_endpoint_auth_signing_alg.as_ref(),
                self.token_endpoint_auth_method.as_ref(),
            ),
            "revocation" => (
                self.revocation_endpoint_auth_signing_alg.as_ref(),
                self.revocation_endpoint_auth_method.as_ref(),
            ),
            "introspection" => (
                self.introspection_endpoint_auth_signing_alg.as_ref(),
                self.introspection_endpoint_auth_method.as_ref(),
            ),
            _ => {
                return Err(OidcClientError::new_type_error(
                    &format!("missing, or unsupported, {}_endpoint_auth_method", endpoint),
                    None,
                ))
            }
        };

        let mut auth_signing_alg_values_supported: &Vec<String> = &vec![];

        if alg.is_none() {
            let issuer = self.issuer.as_ref().ok_or(OidcClientError::new_type_error("issuer is required when client does not have the respective ednpiont auth signing alg values", None))?;
            let values = match endpoint {
                "token" => issuer
                    .token_endpoint_auth_signing_alg_values_supported
                    .as_ref(),
                "revocation" => issuer
                    .revocation_endpoint_auth_signing_alg_values_supported
                    .as_ref(),
                "introspection" => issuer
                    .introspection_endpoint_auth_signing_alg_values_supported
                    .as_ref(),
                _ => {
                    return Err(OidcClientError::new_type_error(
                        &format!("missing, or unsupported, {}_endpoint_auth_method", endpoint),
                        None,
                    ))
                }
            };

            auth_signing_alg_values_supported = values.ok_or(OidcClientError::new_type_error(&format!("{}_endpoint_auth_signing_alg_values_supported must be configured on the issuer", endpoint), None))?;
        }

        if endpiont_auth_method.unwrap_or(&"".to_string()) == "client_secret_jwt" {
            if alg.is_none() {
                alg = auth_signing_alg_values_supported
                    .iter()
                    .find(|a| HS_REGEX.is_match(a));
            }

            let algorithm = alg.ok_or(OidcClientError::new_rp_error(&format!("failed to determine a JWS Algorithm to use for {}_endpoint_auth_method Client Assertion", endpoint), None, None))?;

            let mut header = JwsHeader::new();
            header.set_algorithm(algorithm);

            let signer = self.secret_for_alg(algorithm)?.to_signer()?;

            let payload_bytes = serde_json::to_vec(payload.claims_set()).map_err(|_| {
                OidcClientError::new_error("could not convert payload to bytes", None)
            })?;

            return jws::serialize_compact(&payload_bytes, &header, &*signer)
                .map_err(|_| OidcClientError::new_error("error while creating jwt", None));
        }

        let jwks = self
            .private_jwks
            .as_ref()
            .ok_or(OidcClientError::new_type_error(
                "no client jwks provided for signing a client assertion with",
                None,
            ))?;

        if alg.is_none() {
            alg = auth_signing_alg_values_supported.iter().find(|alg_value| {
                if let Ok(keys) =
                    jwks.get(Some(alg_value.to_string()), Some("sig".to_string()), None)
                {
                    return !keys.is_empty();
                }

                false
            });
        }

        let algorithm = alg.ok_or(OidcClientError::new_rp_error(&format!("failed to determine a JWS Algorithm to use for {}_endpoint_auth_method Client Assertion", endpoint), None, None))?;

        let keys = jwks.get(Some(algorithm.to_string()), Some("sig".to_string()), None)?;
        let key = keys.first().ok_or(OidcClientError::new_rp_error(
            &format!(
                "no key found in client jwks to sign a client assertion with using alg {}",
                algorithm
            ),
            None,
            None,
        ))?;

        let mut header = JwsHeader::new();

        header.set_algorithm(algorithm);

        if let Some(id) = key.key_id() {
            header.set_key_id(id);
        }

        let signer = key.to_signer()?;

        return jws::serialize_compact(
            &serde_json::to_vec(payload.claims_set()).unwrap(),
            &header,
            &*signer,
        )
        .map_err(|_| OidcClientError::new_error("error while creating jwt", None));
    }

    pub(crate) fn decrypt_jarm(&self, response: &str) -> Result<String, OidcClientError> {
        if let Some(expected_alg) = &self.authorization_encrypted_response_alg {
            let expected_enc = self.authorization_encrypted_response_enc.as_deref();
            return self.decrypt_jwe(response, expected_alg, expected_enc);
        }
        Ok(response.to_owned())
    }

    fn decrypt_jwe(
        &self,
        jwe: &str,
        expected_alg: &str,
        expected_enc: Option<&str>,
    ) -> Result<String, OidcClientError> {
        let expected_enc = expected_enc.unwrap_or("A128CBC-HS256");

        let split: Vec<String> = jwe.split('.').map(|f| f.to_owned()).collect();

        let header = split
            .first()
            .ok_or(OidcClientError::new_error("Invalid JWE", None))?;

        let decoded_header = match base64_url::decode(header) {
            Ok(v) => match serde_json::from_slice::<HashMap<String, Value>>(&v) {
                Ok(decoded) => decoded,
                Err(_) => {
                    return Err(OidcClientError::new_error(
                        "jwt header deserialization error",
                        None,
                    ))
                }
            },
            Err(_) => return Err(OidcClientError::new_error("jwt decode error", None)),
        };

        let alg = decoded_header.get("alg");

        if alg.is_none()
            || alg.is_some_and(|x| !x.is_string())
            || alg.is_some_and(|x| x.as_str().is_some_and(|y| y != expected_alg))
        {
            let mut extra_data = HashMap::<String, Value>::new();

            extra_data.insert("jwe".to_string(), json!(jwe));

            return Err(OidcClientError::new_rp_error(
                &format!(
                    "unexpected JWE alg received, expected {0}, got: {1}",
                    expected_alg,
                    alg.unwrap().as_str().unwrap()
                ),
                None,
                Some(extra_data),
            ));
        }

        let enc = decoded_header.get("enc");

        if enc.is_none()
            || enc.is_some_and(|x| !x.is_string())
            || enc.is_some_and(|x| x.as_str().is_some_and(|y| y != expected_enc))
        {
            let mut extra_data = HashMap::<String, Value>::new();

            extra_data.insert("jwe".to_string(), json!(jwe));

            return Err(OidcClientError::new_rp_error(
                &format!(
                    "unexpected JWE enc received, expected {0}, got: {1}",
                    expected_enc,
                    enc.unwrap().as_str().unwrap()
                ),
                None,
                Some(extra_data),
            ));
        }

        let mut plain_text: Option<String> = None;

        if EXPECTED_ALG_REGEX.is_match(expected_alg) {
            let jwks = match &self.private_jwks {
                Some(jwks) => jwks,
                None => return Err(OidcClientError::new_error("private_jwks is empty", None)),
            };

            let header = josekit::jwt::decode_header(jwe).unwrap();

            let kid = match header.claim("kid") {
                Some(Value::String(k)) => Some(k.to_owned()),
                _ => None,
            };
            let alg = match header.claim("alg") {
                Some(Value::String(a)) => Some(a.to_owned()),
                _ => None,
            };

            let keys = jwks.get(alg, Some("enc".to_string()), kid)?;

            for key in keys {
                let decrypter = key.to_jwe_decrypter()?;
                match josekit::jwe::deserialize_compact(jwe, &*decrypter) {
                    Ok((bytes, _)) => {
                        plain_text = String::from_utf8(bytes).ok();
                        break;
                    }
                    Err(e) => println!("{:?}", e),
                }
            }
        } else {
            let alg = if expected_alg == "dir" {
                expected_enc
            } else {
                expected_alg
            };

            let jwk = self.secret_for_alg(alg)?;

            let decrypter = jwk.to_jwe_decrypter()?;
            if let Ok((bytes, _)) = josekit::jwe::deserialize_compact(jwe, &*decrypter) {
                plain_text = String::from_utf8(bytes).ok();
            }
        }

        if let Some(pt) = plain_text {
            return Ok(pt);
        }

        let mut extra_data = HashMap::<String, Value>::new();

        extra_data.insert("jwt".to_string(), json!(jwe));

        Err(OidcClientError::new_rp_error(
            "failed to decrypt JWE",
            None,
            Some(extra_data),
        ))
    }

    pub(crate) async fn validate_jarm_async(
        &mut self,
        response: &str,
    ) -> Result<JwtPayload, OidcClientError> {
        let expected_alg = match &self.authorization_signed_response_alg {
            Some(alg) => alg.to_string(),
            None => {
                return Err(OidcClientError::new_error(
                    "authorization_signed_response_alg not found on the client",
                    None,
                ))
            }
        };

        let (payload, _, _) = self
            .validate_jwt_async(
                response,
                &expected_alg,
                Some(&["iss".to_string(), "exp".to_string(), "aud".to_string()]),
            )
            .await?;

        Ok(payload)
    }

    async fn validate_jwt_async(
        &mut self,
        jwt: &str,
        expected_alg: &str,
        required: Option<&[String]>,
    ) -> Result<(JwtPayload, JwsHeader, Option<Jwk>), OidcClientError> {
        let mut required_claims = required
            .unwrap_or(&[
                "iss".to_string(),
                "sub".to_string(),
                "aud".to_string(),
                "exp".to_string(),
                "iat".to_string(),
            ])
            .to_vec();

        let is_self_issued = self
            .issuer
            .as_ref()
            .map_or(false, |x| x.issuer == "https://self-issued.me");

        let timestamp = (self.now)();
        let decoded_jwt = match decode_jwt(jwt) {
            Ok(t) => t,
            Err(err) => {
                let mut extra_data = HashMap::<String, Value>::new();

                extra_data.insert("jwt".to_string(), json!(jwt));

                let (name, message) = match err {
                    OidcClientError::Error(e, _) => ("Error", e.message),
                    OidcClientError::TypeError(e, _) => ("TypeError", e.message),
                    OidcClientError::RPError(e, _) => ("RPError", e.message),
                    OidcClientError::OPError(e, _) => ("OPError", e.error),
                };

                return Err(OidcClientError::new_rp_error(
                    &format!("failed to decode JWT ({}: {})", name, message),
                    None,
                    Some(extra_data),
                ));
            }
        };

        let header_alg = match decoded_jwt.header.algorithm() {
            Some(alg) => alg,
            None => {
                return Err(OidcClientError::new_error(
                    "Algorithm not found in jwt",
                    None,
                ))
            }
        };

        if header_alg != expected_alg {
            let mut extra_data = HashMap::<String, Value>::new();

            extra_data.insert("jwt".to_string(), json!(jwt));

            return Err(OidcClientError::new_rp_error(
                &format!(
                    "unexpected JWT alg received, expected {}, got: {}",
                    expected_alg, header_alg
                ),
                None,
                Some(extra_data),
            ));
        }

        if is_self_issued {
            required_claims.push("sub_jwk".to_string());
        }

        for claim in required_claims {
            verify_presence(&decoded_jwt.payload, jwt, &claim)?;
        }

        let payload_iss = decoded_jwt.payload.issuer();

        if let Some(iss) = payload_iss {
            // TODO: Return error?
            let expected_iss = self.issuer.as_ref().map_or("", |x| x.issuer.as_str());

            if iss != expected_iss {
                let mut extra_data = HashMap::<String, Value>::new();

                extra_data.insert("jwt".to_string(), json!(jwt));

                return Err(OidcClientError::new_rp_error(
                    &format!(
                        "unexpected iss value, expected {}, got: {}",
                        expected_iss, iss
                    ),
                    None,
                    Some(extra_data),
                ));
            }
        }

        let payload_iat = decoded_jwt.payload.issued_at();

        if payload_iat.is_none() {
            let mut extra_data = HashMap::<String, Value>::new();
            extra_data.insert("jwt".to_string(), json!(jwt));

            return Err(OidcClientError::new_rp_error(
                "JWT iat claim must be a JSON numeric value",
                None,
                Some(extra_data),
            ));
        }

        let payload_nbf = decoded_jwt.payload.claim("nbf");

        if let Some(nbf) = payload_nbf {
            if !nbf.is_number() {
                let mut extra_data = HashMap::<String, Value>::new();
                extra_data.insert("jwt".to_string(), json!(jwt));

                return Err(OidcClientError::new_rp_error(
                    "JWT nbf claim must be a JSON numeric value",
                    None,
                    Some(extra_data),
                ));
            }

            let nbf_value = nbf.as_i64().unwrap();

            if nbf_value > (timestamp.wrapping_add(self.clock_tolerance.as_secs() as i64)) {
                let mut extra_data = HashMap::<String, Value>::new();
                extra_data.insert("jwt".to_string(), json!(jwt));
                extra_data.insert("nbf".to_string(), json!(nbf_value));
                extra_data.insert("now".to_string(), json!(timestamp));
                extra_data.insert(
                    "tolerance".to_string(),
                    json!(self.clock_tolerance.as_secs()),
                );

                return Err(OidcClientError::new_rp_error(
                    &format!(
                        "JWT not active yet, now {}, nbf {}",
                        timestamp.wrapping_add(self.clock_tolerance.as_secs() as i64),
                        nbf_value
                    ),
                    None,
                    Some(extra_data),
                ));
            }
        }

        let payload_exp = decoded_jwt.payload.claim("exp");

        if let Some(exp) = payload_exp {
            if !exp.is_number() {
                let mut extra_data = HashMap::<String, Value>::new();
                extra_data.insert("jwt".to_string(), json!(jwt));

                return Err(OidcClientError::new_rp_error(
                    "JWT exp claim must be a JSON numeric value",
                    None,
                    Some(extra_data),
                ));
            }

            let exp_value = exp.as_i64().unwrap();

            if (timestamp.wrapping_sub(self.clock_tolerance.as_secs() as i64)) >= exp_value {
                let mut extra_data = HashMap::<String, Value>::new();
                extra_data.insert("jwt".to_string(), json!(jwt));
                extra_data.insert("exp".to_string(), json!(exp));
                extra_data.insert("now".to_string(), json!(timestamp));
                extra_data.insert(
                    "tolerance".to_string(),
                    json!(self.clock_tolerance.as_secs()),
                );

                return Err(OidcClientError::new_rp_error(
                    &format!(
                        "JWT expired, now {}, exp {}",
                        timestamp.wrapping_sub(self.clock_tolerance.as_secs() as i64),
                        exp_value
                    ),
                    None,
                    Some(extra_data),
                ));
            }
        }

        let payload_aud = decoded_jwt.payload.audience();
        let payload_azp = decoded_jwt.payload.claim("azp");

        if let Some(aud) = payload_aud {
            if aud.len() > 1 && payload_azp.is_none() {
                let mut extra_data = HashMap::<String, Value>::new();
                extra_data.insert("jwt".to_string(), json!(jwt));

                return Err(OidcClientError::new_rp_error(
                    "missing required JWT property azp",
                    None,
                    Some(extra_data),
                ));
            }

            if aud.len() > 1 && !aud.contains(&self.client_id.as_str()) {
                let mut extra_data = HashMap::<String, Value>::new();
                extra_data.insert("jwt".to_string(), json!(jwt));

                return Err(OidcClientError::new_rp_error(
                    &format!(
                        "aud is missing the client_id, expected {} to be included in {:?}",
                        self.client_id, aud
                    ),
                    None,
                    Some(extra_data),
                ));
            } else if aud.len() == 1 && !aud.contains(&self.client_id.as_str()) {
                let mut extra_data = HashMap::<String, Value>::new();
                extra_data.insert("jwt".to_string(), json!(jwt));

                return Err(OidcClientError::new_rp_error(
                    &format!("aud mismatch, expected {}, got: {}", self.client_id, aud[0]),
                    None,
                    Some(extra_data),
                ));
            }
        }

        if let Some(Value::String(azp)) = payload_azp {
            let mut additional_autorized_parties = self
                .client_options
                .as_ref()
                .map(|x| {
                    x.additional_authorized_parties
                        .to_owned()
                        .unwrap_or_default()
                })
                .unwrap_or_default();

            additional_autorized_parties.push(self.client_id.clone());

            if !additional_autorized_parties.contains(azp) {
                let mut extra_data = HashMap::<String, Value>::new();
                extra_data.insert("jwt".to_string(), json!(jwt));

                return Err(OidcClientError::new_rp_error(
                    &format!("azp mismatch, got: {}", azp),
                    None,
                    Some(extra_data),
                ));
            }
        }

        let mut keys = vec![];

        if is_self_issued {
            let payload_sub_jwk = decoded_jwt.payload.claim("sub_jwk");

            let jwk_str = match payload_sub_jwk {
                Some(sub_jwk) => {
                    if !sub_jwk.is_object() {
                        let mut extra_data = HashMap::<String, Value>::new();
                        extra_data.insert("jwt".to_string(), json!(jwt));

                        return Err(OidcClientError::new_rp_error(
                            "failed to use sub_jwk claim as an asymmetric JSON Web Key",
                            None,
                            Some(extra_data),
                        ));
                    }

                    // Shoud not throw an error?
                    let jwk_json = serde_json::to_string(&sub_jwk).or(Err(
                        OidcClientError::new_error("Error while serializing sub_jwk", None),
                    ))?;

                    let mut jwk = Jwk::from_bytes(jwk_json.as_bytes()).map_err(|_| {
                        let mut extra_data = HashMap::<String, Value>::new();
                        extra_data.insert("jwt".to_string(), json!(jwt));

                        OidcClientError::new_rp_error(
                            "failed to use sub_jwk claim as an asymmetric JSON Web Key",
                            None,
                            Some(extra_data),
                        )
                    })?;

                    if jwk.algorithm().is_none() {
                        jwk.set_algorithm(header_alg);
                    }

                    if jwk.is_private_key() {
                        let mut extra_data = HashMap::<String, Value>::new();
                        extra_data.insert("jwt".to_string(), json!(jwt));

                        return Err(OidcClientError::new_rp_error(
                            "failed to use sub_jwk claim as an asymmetric JSON Web Key",
                            None,
                            Some(extra_data),
                        ));
                    }

                    keys.push(jwk);

                    jwk_json
                }
                _ => {
                    let mut extra_data = HashMap::<String, Value>::new();
                    extra_data.insert("jwt".to_string(), json!(jwt));

                    return Err(OidcClientError::new_rp_error(
                        "failed to use sub_jwk claim as an asymmetric JSON Web Key",
                        None,
                        Some(extra_data),
                    ));
                }
            };

            let payload_sub =
                decoded_jwt
                    .payload
                    .subject()
                    .ok_or(OidcClientError::new_rp_error(
                        "sub not found in payload",
                        None,
                        None,
                    ))?;

            if get_jwk_thumbprint_s256(&jwk_str)? != payload_sub {
                let mut extra_data = HashMap::<String, Value>::new();
                extra_data.insert("jwt".to_string(), json!(jwt));

                return Err(OidcClientError::new_rp_error(
                    "failed to match the subject with sub_jwk",
                    None,
                    Some(extra_data),
                ));
            }
        } else if header_alg.starts_with("HS") {
            keys.push(self.secret_for_alg(header_alg)?);
        } else if header_alg != "none" {
            match &mut self.issuer {
                Some(i) => {
                    let mut header_kid = decoded_jwt.header.key_id().map(|x| x.to_string());

                    let mut header_kty = decoded_jwt
                        .header
                        .claim("kty")
                        .map(|x| x.as_str().unwrap_or("").to_string());

                    if header_kid.clone().is_some_and(|x| x.is_empty()) {
                        header_kid = None
                    }

                    if header_kty.clone().is_some_and(|x| x.is_empty()) {
                        header_kty = None
                    }

                    let query = QueryKeyStore {
                        key_use: Some("sig".to_string()),
                        alg: Some(header_alg.to_string()),
                        key_id: header_kid,
                        key_type: header_kty,
                    };
                    let jwks = i.query_keystore_async(query, false).await?;

                    keys.append(&mut jwks.get_keys());
                }
                None => {
                    return Err(OidcClientError::new_error(
                        "Issuer is not configured for this client",
                        None,
                    ))
                }
            };
        }

        if keys.is_empty() && header_alg == "none" {
            return Ok((decoded_jwt.payload, decoded_jwt.header, None));
        }

        for key in keys {
            let verifier = key.to_verifier()?;

            if let Ok((payload, header)) = decode_with_verifier(jwt, &*verifier) {
                return Ok((payload, header, Some(key)));
            }
        }

        let mut extra_data = HashMap::<String, Value>::new();

        extra_data.insert("jwt".to_string(), json!(jwt));
        Err(OidcClientError::new_rp_error(
            "failed to validate JWT signature",
            None,
            Some(extra_data),
        ))
    }

    pub(crate) fn decrypt_id_token(
        &self,
        token_set: TokenSet,
    ) -> Result<TokenSet, OidcClientError> {
        if self.id_token_encrypted_response_alg.is_none() {
            return Ok(token_set);
        }

        if let Some(id_token) = token_set.get_id_token() {
            let (expected_alg, expected_enc) = match (
                &self.id_token_encrypted_response_alg,
                &self.id_token_encrypted_response_enc,
            ) {
                (Some(alg), Some(enc)) => (alg, enc),
                _ => return Err(OidcClientError::new_error("both id_token_encrypted_response_alg and id_token_encrypted_response_enc is required on the client to decrypt id_token", None))
            };

            let decrypted_id_token =
                self.decrypt_jwe(&id_token, expected_alg, Some(expected_enc))?;

            let mut new_token_set = token_set.clone();

            new_token_set.set_id_token(Some(decrypted_id_token));
            return Ok(new_token_set);
        }

        Err(OidcClientError::new_type_error(
            "id_token not present in TokenSet",
            None,
        ))
    }

    pub(crate) async fn validate_id_token_async(
        &mut self,
        token_set: TokenSet,
        nonce: Option<String>,
        returned_by: &str,
        max_age: Option<u64>,
        state: Option<String>,
    ) -> Result<TokenSet, OidcClientError> {
        if let Some(id_token) = token_set.get_id_token() {
            let expected_alg = self.id_token_signed_response_alg.clone();

            let timestamp = (self.now)();

            let (payload, header, key) = self
                .validate_jwt_async(&id_token, &expected_alg, None)
                .await?;

            if max_age.is_some()
                || (!self.skip_max_age_check && self.require_auth_time.is_some_and(|x| x))
            {
                match payload.claim("auth_time") {
                    Some(Value::Number(_)) => {}
                    Some(_) => {
                        let mut extra_data = HashMap::<String, Value>::new();

                        extra_data.insert("jwt".to_string(), json!(id_token));
                        return Err(OidcClientError::new_rp_error(
                            "JWT auth_time claim must be a JSON numeric value",
                            None,
                            Some(extra_data),
                        ));
                    }
                    None => {
                        let mut extra_data = HashMap::<String, Value>::new();

                        extra_data.insert("jwt".to_string(), json!(id_token));
                        return Err(OidcClientError::new_rp_error(
                            "missing required JWT property auth_time",
                            None,
                            Some(extra_data),
                        ));
                    }
                };
            }

            if let (Some(ma), Some(Value::Number(at))) = (max_age, payload.claim("auth_time")) {
                if let Some(auth_time) = at.as_u64() {
                    if ma.wrapping_add(auth_time)
                        < timestamp.wrapping_sub(self.clock_tolerance.as_secs() as i64) as u64
                    {
                        let mut extra_data = HashMap::<String, Value>::new();

                        extra_data.insert("jwt".to_string(), json!(id_token));
                        extra_data.insert("now".to_string(), json!(timestamp));
                        extra_data.insert("auth_time".to_string(), json!(auth_time));
                        extra_data.insert(
                            "tolerance".to_string(),
                            json!(self.clock_tolerance.as_secs()),
                        );

                        return Err(OidcClientError::new_rp_error(
                                             &format!("too much time has elapsed since the last End-User authentication, max_age {}, auth_time: {}, now {}", ma, auth_time, timestamp),
                                             None,
                                             Some(extra_data),
                                         ));
                    }
                }
            };

            if !self.skip_nonce_check {
                let payload_nonce = match payload.claim("nonce") {
                    Some(Value::String(n)) => Some(n),
                    _ => None,
                };

                if (payload_nonce.is_some() || nonce.is_some()) && payload_nonce != nonce.as_ref() {
                    let mut extra_data = HashMap::<String, Value>::new();

                    extra_data.insert("jwt".to_string(), json!(id_token));
                    return Err(OidcClientError::new_rp_error(
                        &format!(
                            "nonce mismatch, expected {}, got: {}",
                            nonce.unwrap_or_default(),
                            payload_nonce.unwrap_or(&String::new())
                        ),
                        None,
                        Some(extra_data),
                    ));
                }
            }

            if returned_by == "authorization" {
                if payload.claim("at_hash").is_none() && token_set.get_access_token().is_some() {
                    let mut extra_data = HashMap::<String, Value>::new();

                    extra_data.insert("jwt".to_string(), json!(id_token));

                    return Err(OidcClientError::new_rp_error(
                        "missing required property at_hash",
                        None,
                        Some(extra_data),
                    ));
                }

                let other_fields = token_set.get_other().unwrap_or_default();

                let code = other_fields.get("code");

                if payload.claim("c_hash").is_none() && code.is_some() {
                    let mut extra_data = HashMap::<String, Value>::new();

                    extra_data.insert("jwt".to_string(), json!(id_token));

                    return Err(OidcClientError::new_rp_error(
                        "missing required property c_hash",
                        None,
                        Some(extra_data),
                    ));
                }

                let s_hash = payload.claim("s_hash");

                if self.is_fapi() {
                    let token_set_state = other_fields.get("state");

                    if s_hash.is_none() && (token_set_state.is_some() || state.is_some()) {
                        let mut extra_data = HashMap::<String, Value>::new();

                        extra_data.insert("jwt".to_string(), json!(id_token));

                        return Err(OidcClientError::new_rp_error(
                            "missing required property s_hash",
                            None,
                            Some(extra_data),
                        ));
                    }
                }

                if let Some(Value::String(state_hash)) = s_hash {
                    if state.is_none() {
                        return Err(OidcClientError::new_type_error(
                            "cannot verify s_hash, \"checks.state\" property not provided",
                            None,
                        ));
                    }

                    let alg = header
                        .claim("alg")
                        .map(|x| x.as_str().unwrap_or_default())
                        .unwrap_or_default();

                    let crv = key.as_ref().map(|x| x.curve().unwrap_or_default());

                    let name = Names {
                        claim: "s_hash".to_string(),
                        source: "state".to_string(),
                    };

                    let state_source = state.unwrap_or_default();

                    match validate_hash(name, state_hash, alg, &state_source, crv) {
                        Ok(_) => {}
                        Err(OidcClientError::Error(e, _)) => {
                            let mut extra_data = HashMap::<String, Value>::new();

                            extra_data.insert("jwt".to_string(), json!(id_token));

                            return Err(OidcClientError::new_rp_error(
                                &e.message,
                                None,
                                Some(extra_data),
                            ));
                        }
                        Err(OidcClientError::TypeError(e, _)) => {
                            let mut extra_data = HashMap::<String, Value>::new();

                            extra_data.insert("jwt".to_string(), json!(id_token));

                            return Err(OidcClientError::new_rp_error(
                                &e.message,
                                None,
                                Some(extra_data),
                            ));
                        }
                        Err(err) => return Err(err),
                    };
                }
            }

            let payload_iat = payload
                .claim("iat")
                .map(|x| x.as_i64().unwrap_or_default())
                .unwrap_or_default();

            if self.is_fapi() && payload_iat < timestamp - 3600 {
                let mut extra_data = HashMap::<String, Value>::new();

                extra_data.insert("jwt".to_string(), json!(id_token));

                return Err(OidcClientError::new_rp_error(
                    &format!(
                        "JWT issued too far in the past, now {}, iat {}",
                        timestamp, payload_iat
                    ),
                    None,
                    Some(extra_data),
                ));
            }

            if let Some(access_token) = token_set.get_access_token() {
                if let Some(Value::String(at_hash)) = payload.claim("at_hash") {
                    let name = Names {
                        claim: "at_hash".to_string(),
                        source: "access_token".to_string(),
                    };

                    let alg = header
                        .claim("alg")
                        .map(|x| x.as_str().unwrap_or_default())
                        .unwrap_or_default();

                    let crv = key.as_ref().map(|x| x.curve().unwrap_or_default());

                    match validate_hash(name, at_hash, alg, &access_token, crv) {
                        Ok(_) => {}
                        Err(OidcClientError::Error(e, _)) => {
                            let mut extra_data = HashMap::<String, Value>::new();

                            extra_data.insert("jwt".to_string(), json!(id_token));

                            return Err(OidcClientError::new_rp_error(
                                &e.message,
                                None,
                                Some(extra_data),
                            ));
                        }
                        Err(OidcClientError::TypeError(e, _)) => {
                            let mut extra_data = HashMap::<String, Value>::new();

                            extra_data.insert("jwt".to_string(), json!(id_token));

                            return Err(OidcClientError::new_rp_error(
                                &e.message,
                                None,
                                Some(extra_data),
                            ));
                        }
                        Err(err) => return Err(err),
                    };
                }
            }

            let other_fields = token_set.get_other().unwrap_or_default();

            if let Some(Value::String(code)) = other_fields.get("code") {
                if let Some(Value::String(c_hash)) = payload.claim("c_hash") {
                    let name = Names {
                        claim: "c_hash".to_string(),
                        source: "code".to_string(),
                    };

                    let alg = header
                        .claim("alg")
                        .map(|x| x.as_str().unwrap_or_default())
                        .unwrap_or_default();

                    let crv = key.as_ref().map(|x| x.curve().unwrap_or_default());

                    match validate_hash(name, c_hash, alg, code, crv) {
                        Ok(_) => {}
                        Err(OidcClientError::Error(e, _)) => {
                            let mut extra_data = HashMap::<String, Value>::new();

                            extra_data.insert("jwt".to_string(), json!(id_token));

                            return Err(OidcClientError::new_rp_error(
                                &e.message,
                                None,
                                Some(extra_data),
                            ));
                        }
                        Err(OidcClientError::TypeError(e, _)) => {
                            let mut extra_data = HashMap::<String, Value>::new();

                            extra_data.insert("jwt".to_string(), json!(id_token));

                            return Err(OidcClientError::new_rp_error(
                                &e.message,
                                None,
                                Some(extra_data),
                            ));
                        }
                        Err(err) => return Err(err),
                    }
                }
            }

            return Ok(token_set);
        }

        Err(OidcClientError::new_type_error(
            "id_token not present in TokenSet",
            None,
        ))
    }

    pub(crate) fn decrypt_jwt_userinfo(&self, body: String) -> Result<String, OidcClientError> {
        if let Some(expected_alg) = &self.userinfo_encrypted_response_alg {
            let expected_enc = self.userinfo_encrypted_response_enc.as_deref();
            return self.decrypt_jwe(&body, expected_alg, expected_enc);
        }

        Ok(body)
    }

    pub(crate) async fn validate_jwt_userinfo_async(
        &mut self,
        body: &str,
    ) -> Result<(JwtPayload, JwsHeader, Option<Jwk>), OidcClientError> {
        let userinfo_signed_response_alg = self
            .userinfo_signed_response_alg
            .as_ref()
            .ok_or(OidcClientError::new_type_error(
                "userinfo_signed_response_alg should be present",
                None,
            ))?
            .to_owned();
        self.validate_jwt_async(body, &userinfo_signed_response_alg, Some(&[]))
            .await
    }

    pub(crate) async fn instance_request_async(
        &mut self,
        mut req: Request,
        dpop: Option<&Jwk>,
        access_token: Option<&String>,
    ) -> Result<Response, OidcClientError> {
        self.generate_dpop_header(&mut req, dpop, access_token)?;

        let res = match request_async(&req, self.request_interceptor.as_mut()).await {
            Ok(r) => r,
            Err(e) => match &e {
                OidcClientError::RPError(_, Some(r))
                | OidcClientError::TypeError(_, Some(r))
                | OidcClientError::OPError(_, Some(r))
                | OidcClientError::Error(_, Some(r)) => {
                    self.extract_server_dpop_nonce(&req.url, r);
                    return Err(e);
                }

                _ => return Err(e),
            },
        };

        self.extract_server_dpop_nonce(&req.url, &res);

        Ok(res)
    }

    pub(crate) fn dpop_proof(
        &self,
        payload: Value,
        private_key_input: &Jwk,
        access_token: Option<&String>,
    ) -> Result<String, OidcClientError> {
        let mut payload_obj = match payload {
            Value::Object(obj) => obj,
            _ => {
                return Err(OidcClientError::new_type_error(
                    "payload must be a plain object",
                    None,
                ))
            }
        };

        if !private_key_input.is_private_key() || private_key_input.key_type() == "oct" {
            return Err(OidcClientError::new_type_error(
                "dpop option must be a private key",
                None,
            ));
        }

        let alg = match private_key_input.key_type().to_lowercase().as_str() {
            "okp" => "EdDSA",
            "ec" => determine_ec_algorithm(private_key_input)?,
            "rsa" => private_key_input
                .algorithm()
                .ok_or(OidcClientError::new_type_error(
                    "alg not present in private_key_input",
                    None,
                ))?,
            _ => {
                return Err(OidcClientError::new_type_error(
                    "unsupported DPoP private key asymmetric key type",
                    None,
                ))
            }
        };

        if let Some(dsavs) = self
            .issuer
            .as_ref()
            .and_then(|x| x.dpop_signing_alg_values_supported.as_ref())
        {
            if !dsavs.contains(&alg.to_string()) {
                return Err(OidcClientError::new_type_error(
                    "unsupported DPoP signing algorithm",
                    None,
                ));
            }
        }

        if !payload_obj.contains_key("ath") {
            if let Some(at) = access_token {
                let ath = base64_url::encode(&Sha256::digest(at)[..].to_vec());
                payload_obj.insert("ath".to_string(), json!(ath));
            }
        }

        let mut jwt_payload = match JwtPayload::from_map(payload_obj) {
            Ok(p) => p,
            Err(_) => {
                return Err(OidcClientError::new_error(
                    "Error while converting serde_json::Value to JwtPayload",
                    None,
                ))
            }
        };

        jwt_payload
            .set_claim("iat", Some(json!((self.now)())))
            .map_err(|_| OidcClientError::new_error("invalid iat", None))?;
        jwt_payload
            .set_claim("jti", Some(json!(random())))
            .map_err(|_| OidcClientError::new_error("invalid jti", None))?;

        let mut jwt_header = JwsHeader::new();

        jwt_header.set_algorithm(alg);
        jwt_header.set_token_type("dpop+jwt");
        jwt_header
            .set_claim("jwk", Some(get_jwk(private_key_input)))
            .map_err(|_| OidcClientError::new_error("invalid jwk", None))?;

        let signer = private_key_input.to_signer()?;

        josekit::jwt::encode_with_signer(&jwt_payload, &jwt_header, &*signer)
            .map_err(|_| OidcClientError::new_error("error while signing jwt", None))
    }

    pub(crate) fn generate_dpop_header(
        &mut self,
        request: &mut Request,
        dpop: Option<&Jwk>,
        access_token: Option<&String>,
    ) -> Result<(), OidcClientError> {
        if let Some(dpop) = dpop.as_ref() {
            if let Some(htu) = get_dpop_htu(&request.url) {
                let htm = request.method.as_str().to_string();

                let mut payload = json!({"htu": htu, "htm": htm});
                if let Some(nonce) = self.dpop_nonce_cache.cache.get(&htu) {
                    payload["nonce"] = json!(nonce);
                }

                let dpop_header = self.dpop_proof(payload, dpop, access_token)?;

                if let Ok(dpop_header_val) = HeaderValue::from_str(&dpop_header) {
                    request.headers.insert("DPoP", dpop_header_val);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn extract_server_dpop_nonce(&mut self, url: &str, res: &Response) {
        if let Some(cache_key) = get_dpop_htu(url) {
            if let Some(dpop_nonce) = res.headers.get("dpop-nonce").and_then(|x| x.to_str().ok()) {
                if NQCHAR_REGEX.is_match(dpop_nonce) {
                    self.dpop_nonce_cache
                        .cache
                        .insert(cache_key, dpop_nonce.to_string());
                }
            }
        }
    }
}

pub(crate) fn get_dpop_htu(url_str: &str) -> Option<String> {
    Url::parse(url_str)
        .ok()
        .map(|x| x.origin().ascii_serialization() + x.path())
}

fn determine_ec_algorithm(private_key_input: &Jwk) -> Result<&'static str, OidcClientError> {
    match private_key_input.curve() {
        Some("P-256") => Ok("ES256"),
        Some("secp256k1") => Ok("ES256K"),
        Some("P-384") => Ok("ES384"),
        Some("P-512") => Ok("ES512"),
        _ => Err(OidcClientError::new_type_error(
            "unsupported DPoP private key curve",
            None,
        )),
    }
}

fn get_jwk(jwk: &Jwk) -> Value {
    // TODO: validate?
    let mut pub_jwk = json!({});

    if let Some(kty) = jwk.parameter("kty") {
        pub_jwk["kty"] = kty.to_owned();
    }
    if let Some(crv) = jwk.parameter("crv") {
        pub_jwk["crv"] = crv.to_owned();
    }
    if let Some(x) = jwk.parameter("x") {
        pub_jwk["x"] = x.to_owned();
    }
    if let Some(y) = jwk.parameter("y") {
        pub_jwk["y"] = y.to_owned();
    }
    if let Some(e) = jwk.parameter("e") {
        pub_jwk["e"] = e.to_owned();
    }
    if let Some(e) = jwk.parameter("e") {
        pub_jwk["e"] = e.to_owned();
    }
    if let Some(n) = jwk.parameter("n") {
        pub_jwk["n"] = n.to_owned();
    }

    pub_jwk
}

fn verify_presence(payload: &JwtPayload, jwt: &str, prop: &str) -> Result<(), OidcClientError> {
    if payload.claim(prop).is_none() {
        let mut extra_data = HashMap::<String, Value>::new();

        extra_data.insert("jwt".to_string(), json!(jwt));

        return Err(OidcClientError::new_rp_error(
            &format!("missing required JWT property {}", prop),
            None,
            Some(extra_data),
        ));
    }
    Ok(())
}
