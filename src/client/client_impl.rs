use std::{
    collections::HashMap,
    time::{Duration, SystemTime},
};

use base64::{engine::general_purpose, Engine};
use httpmock::Regex;
use josekit::{
    jwk::Jwk,
    jws::{self, JwsHeader},
    jwt::JwtPayload,
};
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::{json, Value};
use url::{form_urlencoded, Url};

use crate::{
    helpers::{convert_json_to, random},
    http::request,
    tokenset::{TokenSet, TokenSetParams},
    types::{
        AuthenticationPostParams, AuthorizationParameters, EndSessionParameters, OidcClientError,
        ResourceParam, Response,
    },
};
use crate::{jwks::jwks::CustomJwk, types::Request};
use sha2::{Digest, Sha256, Sha384, Sha512};

use super::Client;

/// Implementation for Client
impl Client {
    /// # Authorization Url
    /// Builds an authorization url with respect to the `params`
    ///
    /// - `params` - [AuthorizationParameters] : Customize the authorization request
    ///
    /// ### *Example:*
    ///  ```
    ///    let issuer_metadata = IssuerMetadata {
    ///        issuer: "https://auth.example.com".to_string(),
    ///        authorization_endpoint: Some("https://auth.example.com/auth".to_string()),
    ///        ..Default::default()
    ///    };
    ///
    ///    let issuer = Issuer::new(issuer_metadata, None);
    ///
    ///    let client_metadata = ClientMetadata {
    ///        client_id: Some("identifier".to_string()),
    ///        ..Default::default()
    ///    };
    ///
    ///    let client = issuer.client(client_metadata, None, None, None).unwrap();
    ///
    ///    let url = client.authorization_url(AuthorizationParameters::default()).unwrap();
    /// ```
    pub fn authorization_url(
        &self,
        mut params: AuthorizationParameters,
    ) -> Result<Url, OidcClientError> {
        let mut authorization_endpiont = self.get_auth_endpoint()?;

        let mut query_params: HashMap<String, String> = authorization_endpiont
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        params = self.authorization_params(params);

        if let Some(other) = params.other {
            for (k, v) in other {
                query_params.entry(k).or_insert(v);
            }
        }

        insert_query(&mut query_params, "client_id", params.client_id);
        insert_query(&mut query_params, "acr_values", params.acr_values);
        insert_query(&mut query_params, "audience", params.audience);
        insert_query(&mut query_params, "claims_locales", params.claims_locales);
        insert_query(
            &mut query_params,
            "code_challenge_method",
            params.code_challenge_method,
        );
        insert_query(&mut query_params, "code_challenge", params.code_challenge);
        insert_query(&mut query_params, "display", params.display);
        insert_query(&mut query_params, "id_token_hint", params.id_token_hint);
        insert_query(&mut query_params, "login_hint", params.login_hint);
        insert_query(&mut query_params, "max_age", params.max_age);
        insert_query(&mut query_params, "nonce", params.nonce);
        insert_query(&mut query_params, "prompt", params.prompt);
        insert_query(&mut query_params, "redirect_uri", params.redirect_uri);
        insert_query(&mut query_params, "registration", params.registration);
        insert_query(&mut query_params, "request_uri", params.request_uri);
        insert_query(&mut query_params, "request", params.request);
        insert_query(&mut query_params, "response_mode", params.response_mode);
        insert_query(&mut query_params, "response_type", params.response_type);
        insert_query(&mut query_params, "scope", params.scope);
        insert_query(&mut query_params, "state", params.state);
        insert_query(&mut query_params, "ui_locales", params.ui_locales);

        if let Some(c) = &params.claims {
            if let Ok(s) = serde_json::to_string(c) {
                query_params.insert("claims".to_string(), s);
            }
        }

        authorization_endpiont.set_query(None);

        let mut new_query_params = form_urlencoded::Serializer::new(String::new());

        for (query, value) in &query_params {
            new_query_params.append_pair(query, value);
        }

        if let Some(r) = &params.resource {
            match r {
                ResourceParam::String(string) => {
                    new_query_params.append_pair("resource", string);
                }
                ResourceParam::Array(array) => {
                    for v in array {
                        new_query_params.append_pair("resource", v);
                    }
                }
            };
        }

        if !query_params.is_empty() {
            authorization_endpiont.set_query(Some(&new_query_params.finish()));
        }

        Ok(authorization_endpiont)
    }

    /// # End Session Url
    /// Builds an endsession url with respect to the `params`
    ///
    /// - `params` - [EndSessionParameters] : Customize the endsession url
    ///
    /// ### *Example:*
    ///  ```
    ///    let issuer_metadata = IssuerMetadata {
    ///        end_session_endpoint: Some("https://auth.example.com/end".to_string()),
    ///        ..Default::default()
    ///    };
    ///
    ///    let issuer = Issuer::new(issuer_metadata, None);
    ///
    ///    let client_metadata = ClientMetadata {
    ///        client_id: Some("identifier".to_string()),
    ///        ..Default::default()
    ///    };
    ///
    ///    let client = issuer.client(client_metadata, None, None, None).unwrap();
    ///
    ///    let url = client.end_session_url(EndSessionParameters::default()).unwrap();
    /// ```
    pub fn end_session_url(
        &self,
        mut params: EndSessionParameters,
    ) -> Result<Url, OidcClientError> {
        let mut end_session_endpoint = match &self.issuer {
            Some(i) => match &i.end_session_endpoint {
                Some(ae) => match Url::parse(ae) {
                    Ok(u) => u,
                    Err(_) => {
                        return Err(OidcClientError::new_type_error(
                            "end_session_endpoint is invalid url",
                            None,
                        ));
                    }
                },
                None => {
                    return Err(OidcClientError::new_type_error(
                        "end_session_endpoint must be configured on the issuer",
                        None,
                    ))
                }
            },
            None => return Err(OidcClientError::new_error("issuer is empty", None)),
        };

        if params.client_id.is_none() {
            params.client_id = Some(self.client_id.clone());
        }

        let mut post_logout: Option<String> = None;

        if let Some(plrus) = &self.post_logout_redirect_uris {
            if plrus.len() == 1 {
                if let Some(first) = plrus.get(0) {
                    post_logout = Some(first.clone());
                }
            }
        }

        if let Some(plu) = params.post_logout_redirect_uri {
            post_logout = Some(plu);
        }

        let mut query_params: HashMap<String, String> = end_session_endpoint
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        if let Some(other) = params.other {
            for (k, v) in other {
                query_params.entry(k).or_insert_with(|| v.to_string());
            }
        }

        insert_query(&mut query_params, "client_id", params.client_id);
        insert_query(&mut query_params, "post_logout_redirect_uri", post_logout);
        insert_query(&mut query_params, "id_token_hint", params.id_token_hint);
        insert_query(&mut query_params, "logout_hint", params.logout_hint);
        insert_query(&mut query_params, "state", params.state);

        let mut new_query_params = form_urlencoded::Serializer::new(String::new());

        for (query, value) in &query_params {
            new_query_params.append_pair(query, value);
        }

        if !query_params.is_empty() {
            end_session_endpoint.set_query(Some(&new_query_params.finish()));
        }

        Ok(end_session_endpoint)
    }

    /// # Authorization Post
    /// Builds an authorization post page with respect to the `params`
    ///
    /// - `params` - [AuthorizationParameters] : Customize the authorization request
    ///
    /// ### *Example:*
    ///  ```
    ///    let issuer_metadata = IssuerMetadata {
    ///        authorization_endpoint: Some("https://auth.example.com/auth".to_string()),
    ///        ..Default::default()
    ///    };
    ///
    ///    let issuer = Issuer::new(issuer_metadata, None);
    ///
    ///    let client_metadata = ClientMetadata {
    ///        client_id: Some("identifier".to_string()),
    ///        ..Default::default()
    ///    };
    ///
    ///    let client = issuer.client(client_metadata, None, None, None).unwrap();
    ///
    ///    let html = client.authorization_post(AuthorizationParameters::default()).unwrap();
    /// ```
    pub fn authorization_post(
        &self,
        mut params: AuthorizationParameters,
    ) -> Result<String, OidcClientError> {
        let authorization_endpiont = self.get_auth_endpoint()?;

        let mut query_params: HashMap<String, String> = authorization_endpiont
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        params = self.authorization_params(params);

        if let Some(other) = params.other {
            for (k, v) in other {
                query_params.insert(k, v);
            }
        }

        insert_query(&mut query_params, "client_id", params.client_id);
        insert_query(&mut query_params, "acr_values", params.acr_values);
        insert_query(&mut query_params, "audience", params.audience);
        insert_query(&mut query_params, "claims_locales", params.claims_locales);
        insert_query(
            &mut query_params,
            "code_challenge_method",
            params.code_challenge_method,
        );
        insert_query(&mut query_params, "code_challenge", params.code_challenge);
        insert_query(&mut query_params, "display", params.display);
        insert_query(&mut query_params, "id_token_hint", params.id_token_hint);
        insert_query(&mut query_params, "login_hint", params.login_hint);
        insert_query(&mut query_params, "max_age", params.max_age);
        insert_query(&mut query_params, "nonce", params.nonce);
        insert_query(&mut query_params, "prompt", params.prompt);
        insert_query(&mut query_params, "redirect_uri", params.redirect_uri);
        insert_query(&mut query_params, "registration", params.registration);
        insert_query(&mut query_params, "request_uri", params.request_uri);
        insert_query(&mut query_params, "request", params.request);
        insert_query(&mut query_params, "response_mode", params.response_mode);
        insert_query(&mut query_params, "response_type", params.response_type);
        insert_query(&mut query_params, "scope", params.scope);
        insert_query(&mut query_params, "state", params.state);
        insert_query(&mut query_params, "ui_locales", params.ui_locales);

        if let Some(c) = &params.claims {
            if let Ok(s) = serde_json::to_string(c) {
                query_params.insert("claims".to_string(), s);
            }
        }

        let mut html = r#"<!DOCTYPE html>
        <head>
        <title>Requesting Authorization</title>
        </head>
        <body onload="javascript:document.forms[0].submit()">
        <form method="post" action=""#
            .to_string()
            + authorization_endpiont.as_ref()
            + r#"">"#
            + "\n";

        for (name, value) in query_params {
            html = html
                + r#"<input type="hidden" name=""#
                + &name
                + r#"" value=""#
                + &value
                + r#""/>"#
                + "\n";
        }

        if let Some(r) = &params.resource {
            match r {
                ResourceParam::String(string) => {
                    html = html
                        + r#"<input type="hidden" name="resource" value=""#
                        + string
                        + r#""/>"#
                        + "\n";
                }
                ResourceParam::Array(array) => {
                    for v in array {
                        html = html
                            + r#"<input type="hidden" name="resource" value=""#
                            + v
                            + r#""/>"#
                            + "\n";
                    }
                }
            };
        }

        html += r#"</form>
        </body>
        </html>"#;

        Ok(html)
    }

    /// # Token Grant
    /// Performs a grant at the `token_endpoint`
    ///
    /// - `body` - HashMap<String, Value> : Request body
    /// - `params` - [AuthenticationPostParams] : Parameters for customizing auth request
    /// - `retry` - Weather to retry if the request fails
    ///
    /// ### *Example:*
    ///  ```
    ///    let issuer_metadata = IssuerMetadata {
    ///        authorization_endpoint: Some("https://auth.example.com/auth".to_string()),
    ///        ..Default::default()
    ///    };
    ///
    ///    let issuer = Issuer::new(issuer_metadata, None);
    ///
    ///    let client_metadata = ClientMetadata {
    ///        client_id: Some("identifier".to_string()),
    ///        ..Default::default()
    ///    };
    ///
    ///    let client = issuer.client(client_metadata, None, None, None).unwrap();
    ///
    ///    let body: HashMap<String, Value> = HashMap::new();
    ///
    ///    let token_set = client.grant(body, AuthenticationPostParams::default(), false).unwrap();
    /// ```
    pub fn grant(
        &mut self,
        body: HashMap<String, Value>,
        params: AuthenticationPostParams,
        retry: bool,
    ) -> Result<TokenSet, OidcClientError> {
        let issuer = self.issuer.as_ref().ok_or(OidcClientError::new_error(
            "Issuer is required for authenticated_post",
            None,
        ))?;

        if issuer.token_endpoint.is_none() {
            return Err(OidcClientError::new_type_error(
                "token_endpoint must be configured on the issuer",
                None,
            ));
        }

        let req = Request {
            form: Some(body.clone()),
            response_type: Some("json".to_string()),
            ..Default::default()
        };

        let response = match self.authenticated_post("token", req, params.clone()) {
            Ok(res) => res,
            Err(err) => {
                let error_msg = match &err {
                    OidcClientError::OPError(e, _) => &e.error,
                    _ => "",
                };

                if !retry || !err.is_op_error() || error_msg != "use_dpop_nonce" {
                    return Err(err);
                }

                return self.grant(body, params, false);
            }
        };

        let body = response.body.clone().ok_or(OidcClientError::new_error(
            "body expected in grant response",
            Some(response.clone()),
        ))?;

        let token_params = convert_json_to::<TokenSetParams>(&body).or(Err(
            OidcClientError::new_error("could not convert body to TokenSetParams", Some(response)),
        ))?;

        Ok(TokenSet::new(token_params))
    }

    pub(crate) fn secret_for_alg(&self, alg: &str) -> Result<Jwk, OidcClientError> {
        let mut jwk = Jwk::new("oct");
        jwk.set_algorithm(alg);

        if let Some(cs) = &self.client_secret {
            // Should not throw
            let regex_1 = Regex::new(r#"^A(\d{3})(?:GCM)?KW$"#).unwrap();
            if let Some(first_group) = regex_1.captures_iter(alg).next() {
                if let Some(extracted_alg) = first_group.get(1) {
                    jwk.set_key_use("enc");
                    jwk.set_key_value(
                        self.encryption_secret(extracted_alg.as_str().parse::<u16>().unwrap())?,
                    );
                    return Ok(jwk);
                }
            }

            // Should not throw
            let regex_2 = Regex::new(r#"^A(\d{3})(?:GCM|CBC-HS(\d{3}))$"#).unwrap();
            if let Some(first_group) = regex_2.captures_iter(alg).next() {
                if let Some(extracted_alg) = first_group.get(1).or(first_group.get(2)) {
                    jwk.set_key_use("enc");
                    jwk.set_key_value(
                        self.encryption_secret(extracted_alg.as_str().parse::<u16>().unwrap())?,
                    );
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

    fn authorization_params(&self, params: AuthorizationParameters) -> AuthorizationParameters {
        let mut new_params = AuthorizationParameters {
            client_id: Some(self.client_id.clone()),
            scope: Some("openid".to_string()),
            response_type: self.resolve_response_type(),
            redirect_uri: self.resolve_redirect_uri(),
            ..Default::default()
        };

        if params.client_id.is_some() {
            new_params.client_id = params.client_id;
        }
        if params.acr_values.is_some() {
            new_params.acr_values = params.acr_values;
        }
        if params.audience.is_some() {
            new_params.audience = params.audience;
        }
        if params.claims.is_some() {
            new_params.claims = params.claims;
        }
        if params.claims_locales.is_some() {
            new_params.claims_locales = params.claims_locales;
        }
        if params.code_challenge_method.is_some() {
            new_params.code_challenge_method = params.code_challenge_method;
        }
        if params.code_challenge.is_some() {
            new_params.code_challenge = params.code_challenge;
        }
        if params.display.is_some() {
            new_params.display = params.display;
        }
        if params.id_token_hint.is_some() {
            new_params.id_token_hint = params.id_token_hint;
        }
        if params.login_hint.is_some() {
            new_params.login_hint = params.login_hint;
        }
        if params.max_age.is_some() {
            new_params.max_age = params.max_age;
        }
        if params.nonce.is_some() {
            new_params.nonce = params.nonce;
        }
        if params.prompt.is_some() {
            new_params.prompt = params.prompt;
        }
        if params.redirect_uri.is_some() {
            new_params.redirect_uri = params.redirect_uri;
        }
        if params.registration.is_some() {
            new_params.registration = params.registration;
        }
        if params.request_uri.is_some() {
            new_params.request_uri = params.request_uri;
        }
        if params.request.is_some() {
            new_params.request = params.request;
        }
        if params.response_mode.is_some() {
            new_params.response_mode = params.response_mode;
        }
        if params.response_type.is_some() {
            new_params.response_type = params.response_type;
        }
        if params.resource.is_some() {
            new_params.resource = params.resource;
        }
        if params.scope.is_some() {
            new_params.scope = params.scope;
        }
        if params.state.is_some() {
            new_params.state = params.state;
        }
        if params.ui_locales.is_some() {
            new_params.ui_locales = params.ui_locales;
        }

        if let Some(other) = params.other {
            let mut new_other: HashMap<String, String> = HashMap::new();
            for (k, v) in other {
                new_other.insert(k, v);
            }

            new_params.other = Some(new_other);
        }

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

    fn get_auth_endpoint(&self) -> Result<Url, OidcClientError> {
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

    fn authenticated_post(
        &mut self,
        endpoint: &str,
        mut req: Request,
        params: AuthenticationPostParams,
    ) -> Result<Response, OidcClientError> {
        let auth_request = self.auth_for(endpoint, params.client_assertion_payload.as_ref())?;

        req.merge_form(&auth_request);
        req.merge_headers(&auth_request);

        let endpoint_auth_method = params.endpoint_auth_method.unwrap_or(endpoint.to_string());

        let auth_method = match endpoint_auth_method.as_str() {
            "token" => Some(&self.token_endpoint_auth_method),
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
                "introspection" => aliases.and_then(|a| a.token_endpoint.as_ref()),
                "revocation" => aliases.and_then(|a| a.token_endpoint.as_ref()),
                _ => return Err(OidcClientError::new_error("unknown endpoint", None)),
            };
        }

        if target_url.is_none() {
            target_url = match endpoint {
                "token" => issuer.token_endpoint.as_ref(),
                "introspection" => issuer.introspection_endpoint.as_ref(),
                "revocation" => issuer.revocation_endpoint.as_ref(),
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

        request(req, &mut self.request_interceptor)
    }

    pub(crate) fn auth_for(
        &self,
        endpoint: &str,
        client_assertion_payload: Option<&HashMap<String, serde_json::Value>>,
    ) -> Result<Request, OidcClientError> {
        let endpiont_auth_method = match endpoint {
            "token" => Some(&self.token_endpoint_auth_method),
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

                let mut form: HashMap<String, serde_json::Value> = HashMap::new();

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

                let mut form: HashMap<String, serde_json::Value> = HashMap::new();

                form.insert("client_id".to_string(), json!(self.client_id));
                form.insert(
                    "client_secret".to_string(),
                    json!(self.client_secret.clone().unwrap()),
                );

                request.form = Some(form);

                Ok(request)
            }
            "private_key_jwt" | "client_secret_jwt" => {
                let iat = SystemTime::now();
                let exp =
                    iat.checked_add(Duration::from_secs(60))
                        .ok_or(OidcClientError::new_error(
                            "error while adding seconds to iat",
                            None,
                        ))?;
                let mut jwt_payload = JwtPayload::new();

                jwt_payload.set_issued_at(&iat);
                jwt_payload.set_expires_at(&exp);
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

                let mut form: HashMap<String, serde_json::Value> = HashMap::new();

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
                Some(&self.token_endpoint_auth_method),
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
                // should not throw
                let regex = Regex::new("^HS(?:256|384|512)").unwrap();
                alg = auth_signing_alg_values_supported
                    .iter()
                    .find(|a| regex.is_match(a));
            }

            let algorithm = alg.ok_or(OidcClientError::new_rp_error(&format!("failed to determine a JWS Algorithm to use for {}_endpoint_auth_method Client Assertion", endpoint), None))?;

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

        let algorithm = alg.ok_or(OidcClientError::new_rp_error(&format!("failed to determine a JWS Algorithm to use for {}_endpoint_auth_method Client Assertion", endpoint), None))?;

        let keys = jwks.get(Some(algorithm.to_string()), Some("sig".to_string()), None)?;
        let key = keys.first().ok_or(OidcClientError::new_rp_error(
            &format!(
                "no key found in client jwks to sign a client assertion with using alg {}",
                algorithm
            ),
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
}

fn insert_query(qp: &mut HashMap<String, String>, key: &str, value: Option<String>) {
    if let Some(v) = value {
        qp.insert(key.to_string(), v);
    }
}
