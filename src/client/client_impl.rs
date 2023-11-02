use josekit::jwe::JweHeader;
use josekit::jws::JwsHeader;
use josekit::jwt::JwtPayload;
use josekit::{jwe, jws};
use std::collections::HashMap;
use std::time::Duration;

use reqwest::header::HeaderValue;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use url::{form_urlencoded, Url};

use crate::helpers::{get_serde_value_as_string, now, random};
use crate::http::request_async;
use crate::jwks::jwks::CustomJwk;
use crate::types::query_keystore::QueryKeyStore;
use crate::types::{
    CallbackExtras, CallbackParams, IntrospectionParams, OAuthCallbackChecks, OpenIDCallbackChecks,
    PushedAuthorizationRequestParams, RefreshTokenRequestParams, Request, RequestResourceParams,
    Response, RevokeRequestParams, UserinfoRequestParams,
};
use crate::{
    helpers::convert_json_to,
    tokenset::{TokenSet, TokenSetParams},
    types::{
        AuthenticationPostParams, AuthorizationParameters, EndSessionParameters, OidcClientError,
        ResourceParam,
    },
};

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
                    ));
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
    ///
    /// ### *Example:*
    ///  ```
    ///    let issuer_metadata = IssuerMetadata {
    ///        token_endpoint: Some("https://auth.example.com/token".to_string()),
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
    ///    let token_set = client.grant(body, AuthenticationPostParams::default()).await.unwrap();
    /// ```
    pub async fn grant_async(
        &mut self,
        body: HashMap<String, Value>,
        params: AuthenticationPostParams,
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
            ..Default::default()
        };

        let response = self
            .authenticated_post_async("token", req, params.clone())
            .await?;

        let body = response.body.clone().ok_or(OidcClientError::new_error(
            "body expected in grant response",
            Some(response.clone()),
        ))?;

        let token_params = convert_json_to::<TokenSetParams>(&body).or(Err(
            OidcClientError::new_error("could not convert body to TokenSetParams", Some(response)),
        ))?;

        Ok(TokenSet::new(token_params))
    }

    /// # OAuth Callback
    /// Performs the callback for Authorization Server's authorization response.
    ///
    /// - `redirect_uri` - The redirect uri of the [Client]
    /// - `params` - [CallbackParams] : Parameters recieved from the callback response
    /// - `checks` - [OAuthCallbackChecks] : Checks to be performed against `params`
    /// - `extras` - [CallbackExtras] : Extra details to be used for token grant
    ///
    /// ### *Example:*
    ///  ```
    ///    let issuer_metadata = IssuerMetadata {
    ///        issuer: Some("https://auth.example.com".to_string()),
    ///        token_endpoint: Some("https://auth.example.com/token".to_string()),
    ///        ..Default::default()
    ///    };
    ///
    ///    let issuer = Issuer::new(issuer_metadata, None);
    ///
    ///    let client_metadata = ClientMetadata {
    ///        client_id: Some("identifier".to_string()),
    ///        client_secret: Some("secure".to_string()),
    ///        ..Default::default()
    ///    };
    ///
    ///    let callback_params = CallbackParams {
    ///        code: Some("code".to_string()),
    ///        ..Default::default()
    ///    };
    ///
    ///    let checks = OAuthCallbackChecks {
    ///        response_type: Some("code".to_string()),
    ///        ..Default::default()
    ///    };
    ///
    ///    let token_set = client
    ///        .oauth_callback_async(
    ///            Some("https://rp.example.com/cb".to_string()),
    ///            callback_params,
    ///            Some(checks),
    ///            None,
    ///        )
    ///        .await.unwrap();
    /// ```
    pub async fn oauth_callback_async(
        &mut self,
        redirect_uri: Option<String>,
        mut params: CallbackParams,
        checks: Option<OAuthCallbackChecks>,
        extras: Option<CallbackExtras>,
    ) -> Result<TokenSet, OidcClientError> {
        let checks = checks.unwrap_or_default();

        if checks.jarm.is_some_and(|x| x) && params.response.is_none() {
            let mut extra_data: HashMap<String, Value> = HashMap::new();

            if let Ok(p) = serde_json::to_value(params) {
                extra_data.insert("params".to_string(), p);
            };

            if let Ok(c) = serde_json::to_value(checks) {
                extra_data.insert("checks".to_string(), c);
            };

            return Err(OidcClientError::new_rp_error(
                "expected a JARM response",
                None,
                Some(extra_data),
            ));
        } else if let Some(response) = &params.response {
            let decrypted = self.decrypt_jarm(response)?;
            let payload = self.validate_jarm_async(&decrypted).await?;
            params = CallbackParams::from_jwt_payload(&payload);
        }

        if params.state.is_some() && checks.state.is_none() {
            return Err(OidcClientError::new_type_error(
                "checks.state argument is missing",
                None,
            ));
        }

        if params.state.is_none() && checks.state.is_some() {
            let mut extra_data: HashMap<String, Value> = HashMap::new();

            if let Ok(p) = serde_json::to_value(params) {
                extra_data.insert("params".to_string(), p);
            };

            if let Ok(c) = serde_json::to_value(checks) {
                extra_data.insert("checks".to_string(), c);
            };

            return Err(OidcClientError::new_rp_error(
                "state missing from the response",
                None,
                Some(extra_data),
            ));
        }

        if params.state != checks.state {
            let checks_state = checks.state.clone();
            let params_state = params.state.clone();

            let mut extra_data: HashMap<String, Value> = HashMap::new();

            if let Ok(p) = serde_json::to_value(params) {
                extra_data.insert("params".to_string(), p);
            };

            if let Ok(c) = serde_json::to_value(checks) {
                extra_data.insert("checks".to_string(), c);
            };

            return Err(OidcClientError::new_rp_error(
                &format!(
                    "state mismatch, expected {0}, got: {1}",
                    checks_state.unwrap(),
                    params_state.unwrap()
                ),
                None,
                Some(extra_data),
            ));
        }

        let issuer = match self.issuer.as_ref() {
            Some(iss) => iss,
            None => return Err(OidcClientError::new_type_error("Issuer is required", None)),
        };

        if params.iss.is_some() {
            if issuer.issuer.is_empty() {
                return Err(OidcClientError::new_type_error(
                    "issuer must be configured on the issuer",
                    None,
                ));
            }

            let params_iss = params.iss.clone().unwrap();
            if params_iss != issuer.issuer {
                let mut extra_data: HashMap<String, Value> = HashMap::new();

                if let Ok(p) = serde_json::to_value(params) {
                    extra_data.insert("params".to_string(), p);
                };

                return Err(OidcClientError::new_rp_error(
                    &format!(
                        "iss mismatch, expected {0}, got: {1}",
                        issuer.issuer, params_iss
                    ),
                    None,
                    Some(extra_data),
                ));
            }
        } else if issuer
            .authorization_response_iss_parameter_supported
            .is_some_and(|x| x)
            && params.id_token.is_none()
            && params.response.is_none()
        {
            let mut extra_data: HashMap<String, Value> = HashMap::new();

            if let Ok(p) = serde_json::to_value(params) {
                extra_data.insert("params".to_string(), p);
            };

            return Err(OidcClientError::new_rp_error(
                "iss missing from the response",
                None,
                Some(extra_data),
            ));
        }

        if params.error.is_some() {
            return Err(OidcClientError::new_op_error(
                params.error.unwrap(),
                params.error_description,
                params.error_uri,
                None,
                None,
                None,
            ));
        }

        if params.id_token.as_ref().is_some_and(|x| !x.is_empty()) {
            let mut extra_data: HashMap<String, Value> = HashMap::new();

            if let Ok(p) = serde_json::to_value(params) {
                extra_data.insert("params".to_string(), p);
            };

            return Err(OidcClientError::new_rp_error(
                "id_token detected in the response, you must use client.callback_async() instead of client.oauth_callback_async()",
                None,
                Some(extra_data),
            ));
        }

        params.id_token = None;

        if checks.response_type.is_some() {
            for res_type in checks.response_type.as_ref().unwrap().split(' ') {
                if res_type == "none"
                    && (params.code.is_some()
                        || params.id_token.is_some()
                        || params.access_token.is_some())
                {
                    let mut extra_data: HashMap<String, Value> = HashMap::new();

                    if let Ok(p) = serde_json::to_value(params) {
                        extra_data.insert("params".to_string(), p);
                    };

                    if let Ok(c) = serde_json::to_value(checks) {
                        extra_data.insert("checks".to_string(), c);
                    };

                    return Err(OidcClientError::new_rp_error(
                        "unexpected params encountered for \"none\" response",
                        None,
                        Some(extra_data),
                    ));
                }

                if res_type == "code" || res_type == "token" {
                    let mut message = "";

                    if res_type == "code" && params.code.is_none() {
                        message = "code missing from response";
                    }

                    if res_type == "token" && params.access_token.is_none() {
                        message = "access_token missing from response";
                    }

                    if res_type == "token" && params.token_type.is_none() {
                        message = "token_type missing from response";
                    }

                    if !message.is_empty() {
                        let mut extra_data: HashMap<String, Value> = HashMap::new();

                        if let Ok(p) = serde_json::to_value(params) {
                            extra_data.insert("params".to_string(), p);
                        };

                        if let Ok(c) = serde_json::to_value(checks) {
                            extra_data.insert("checks".to_string(), c);
                        };

                        return Err(OidcClientError::new_rp_error(
                            message,
                            None,
                            Some(extra_data),
                        ));
                    }
                }
            }
        }

        if params.code.is_some() {
            let mut exchange_body = match extras.as_ref() {
                Some(e) => e
                    .exchange_body
                    .clone()
                    .unwrap_or(HashMap::<String, Value>::new()),
                None => HashMap::<String, Value>::new(),
            };

            exchange_body.insert("grant_type".to_string(), json!("authorization_code"));
            exchange_body.insert("code".to_string(), json!(params.code.as_ref().unwrap()));
            if let Some(ru) = redirect_uri.as_ref() {
                exchange_body.insert("redirect_uri".to_string(), json!(ru));
            };

            if let Some(cv) = checks.code_verifier.as_ref() {
                exchange_body.insert("code_verifier".to_string(), json!(cv));
            };

            let mut auth_post_params = AuthenticationPostParams::default();

            match &extras {
                Some(e) => {
                    auth_post_params.client_assertion_payload = e.client_assertion_payload.clone();
                    auth_post_params.dpop = e.dpop.clone();
                }
                None => {}
            };

            let mut token_set = self.grant_async(exchange_body, auth_post_params).await?;

            if token_set.get_id_token().is_some_and(|x| !x.is_empty()) {
                let mut extra_data: HashMap<String, Value> = HashMap::new();

                if let Ok(p) = serde_json::to_value(params) {
                    extra_data.insert("params".to_string(), p);
                };

                return Err(OidcClientError::new_rp_error(
                    "id_token detected in the response, you must use client.callback_async() instead of client.oauth_callback_async()",
                    None,
                    Some(extra_data),
                ));
            }

            token_set.set_id_token(None);

            return Ok(token_set);
        }

        let mut other_fields = match params.other {
            Some(o) => o.clone(),
            None => HashMap::new(),
        };

        if let Some(state) = &params.state {
            other_fields.insert("state".to_string(), json!(state));
        }

        if let Some(code) = &params.code {
            other_fields.insert("code".to_string(), json!(code));
        }

        let expires_at = match other_fields.get("expires_at") {
            Some(eat) => eat.as_i64(),
            None => None,
        };
        let scope = match other_fields.get("scope") {
            Some(s) => s.as_str().map(|f| f.to_owned()),
            None => None,
        };
        let token_type = match other_fields.get("token_type") {
            Some(s) => s.as_str().map(|f| f.to_owned()),
            None => None,
        };
        let session_state = match other_fields.get("session_state") {
            Some(s) => s.as_str().map(|f| f.to_owned()),
            None => None,
        };
        let refresh_token = match other_fields.get("refresh_token") {
            Some(s) => s.as_str().map(|f| f.to_owned()),
            None => None,
        };
        let expires_in = match params.expires_in {
            Some(exp_in) => exp_in.parse::<i64>().ok(),
            None => None,
        };

        let token_params = TokenSetParams {
            access_token: params.access_token,
            id_token: params.id_token,
            expires_in,
            expires_at,
            scope,
            token_type,
            session_state,
            refresh_token,
            other: Some(other_fields),
        };

        Ok(TokenSet::new(token_params))
    }

    /// When `skip_max_age_check` is set to true, Id token's
    /// Max age wont be validated
    pub fn set_skip_max_age_check(&mut self, max_age_check: bool) {
        self.skip_max_age_check = max_age_check;
    }

    /// When `skip_nonce_check` is set to true, Id token's
    /// Nonce wont be validated
    pub fn set_skip_nonce_check(&mut self, nonce_check: bool) {
        self.skip_nonce_check = nonce_check;
    }

    /// It is possible the RP or OP environment has a system clock skew,
    /// which can result in the error "JWT not active yet".
    pub fn set_clock_skew_duration(&mut self, duration: Duration) {
        self.clock_tolerance = duration;
    }

    /// # Callback
    /// Performs the callback for Authorization Server's authorization response.
    ///
    /// - `redirect_uri` - The redirect uri of the [Client]
    /// - `params` - [CallbackParams] : Parameters recieved from the callback response
    /// - `checks` - [OpenIDCallbackChecks] : Checks to be performed against `params`
    /// - `extras` - [CallbackExtras] : Extra details to be used for token grant
    ///
    /// ### *Example:*
    ///  ```
    ///    let issuer_metadata = IssuerMetadata {
    ///        issuer: Some("https://auth.example.com".to_string()),
    ///        token_endpoint: Some("https://auth.example.com/token".to_string()),
    ///        ..Default::default()
    ///    };
    ///
    ///    let issuer = Issuer::new(issuer_metadata, None);
    ///
    ///    let client_metadata = ClientMetadata {
    ///        client_id: Some("identifier".to_string()),
    ///        client_secret: Some("secure".to_string()),
    ///        ..Default::default()
    ///    };
    ///
    ///    let callback_params = CallbackParams {
    ///        code: Some("code".to_string()),
    ///        ..Default::default()
    ///    };
    ///
    ///    let token_set = client
    ///        .callback_async(
    ///            Some("https://rp.example.com/cb".to_string()),
    ///            callback_params,
    ///            None,
    ///            None,
    ///        )
    ///        .await.unwrap();
    /// ```
    pub async fn callback_async(
        &mut self,
        redirect_uri: Option<String>,
        mut params: CallbackParams,
        checks: Option<OpenIDCallbackChecks>,
        extras: Option<CallbackExtras>,
    ) -> Result<TokenSet, OidcClientError> {
        let mut checks = checks.unwrap_or_default();

        let oauth_checks = checks.oauth_checks.clone().unwrap_or_default();

        if oauth_checks.jarm.is_some_and(|x| x) && params.response.is_none() {
            let mut extra_data: HashMap<String, Value> = HashMap::new();

            if let Ok(p) = serde_json::to_value(params) {
                extra_data.insert("params".to_string(), p);
            };

            if let Ok(c) = serde_json::to_value(checks) {
                extra_data.insert("checks".to_string(), c);
            };

            return Err(OidcClientError::new_rp_error(
                "expected a JARM response",
                None,
                Some(extra_data),
            ));
        } else if let Some(response) = &params.response {
            let decrypted = self.decrypt_jarm(response)?;
            let payload = self.validate_jarm_async(&decrypted).await?;
            params = CallbackParams::from_jwt_payload(&payload);
        }

        if self.default_max_age.is_some() && checks.max_age.is_none() {
            checks.max_age = self.default_max_age;
        }

        if params.state.is_some() && oauth_checks.state.is_none() {
            return Err(OidcClientError::new_type_error(
                "checks.state argument is missing",
                None,
            ));
        }

        if params.state.is_none() && oauth_checks.state.is_some() {
            let mut extra_data: HashMap<String, Value> = HashMap::new();

            if let Ok(p) = serde_json::to_value(params) {
                extra_data.insert("params".to_string(), p);
            };

            if let Ok(c) = serde_json::to_value(checks) {
                extra_data.insert("checks".to_string(), c);
            };

            return Err(OidcClientError::new_rp_error(
                "state missing from the response",
                None,
                Some(extra_data),
            ));
        }

        if params.state != oauth_checks.state {
            let checks_state = oauth_checks.state.clone();
            let params_state = params.state.clone();

            let mut extra_data: HashMap<String, Value> = HashMap::new();

            if let Ok(p) = serde_json::to_value(params) {
                extra_data.insert("params".to_string(), p);
            };

            if let Ok(c) = serde_json::to_value(checks) {
                extra_data.insert("checks".to_string(), c);
            };

            return Err(OidcClientError::new_rp_error(
                &format!(
                    "state mismatch, expected {0}, got: {1}",
                    checks_state.unwrap(),
                    params_state.unwrap()
                ),
                None,
                Some(extra_data),
            ));
        }

        let issuer = match self.issuer.as_ref() {
            Some(iss) => iss,
            None => return Err(OidcClientError::new_type_error("Issuer is required", None)),
        };

        if params.iss.is_some() {
            if issuer.issuer.is_empty() {
                return Err(OidcClientError::new_type_error(
                    "issuer must be configured on the issuer",
                    None,
                ));
            }

            let params_iss = params.iss.clone().unwrap();
            if params_iss != issuer.issuer {
                let mut extra_data: HashMap<String, Value> = HashMap::new();

                if let Ok(p) = serde_json::to_value(params) {
                    extra_data.insert("params".to_string(), p);
                };

                return Err(OidcClientError::new_rp_error(
                    &format!(
                        "iss mismatch, expected {0}, got: {1}",
                        issuer.issuer, params_iss
                    ),
                    None,
                    Some(extra_data),
                ));
            }
        } else if issuer
            .authorization_response_iss_parameter_supported
            .is_some_and(|x| x)
            && params.id_token.is_none()
            && params.response.is_none()
        {
            let mut extra_data: HashMap<String, Value> = HashMap::new();

            if let Ok(p) = serde_json::to_value(params) {
                extra_data.insert("params".to_string(), p);
            };

            return Err(OidcClientError::new_rp_error(
                "iss missing from the response",
                None,
                Some(extra_data),
            ));
        }

        if params.error.is_some() {
            return Err(OidcClientError::new_op_error(
                params.error.unwrap(),
                params.error_description,
                params.error_uri,
                None,
                None,
                None,
            ));
        }

        if oauth_checks.response_type.is_some() {
            for res_type in oauth_checks.response_type.as_ref().unwrap().split(' ') {
                if res_type == "none"
                    && (params.code.is_some()
                        || params.id_token.is_some()
                        || params.access_token.is_some())
                {
                    let mut extra_data: HashMap<String, Value> = HashMap::new();

                    if let Ok(p) = serde_json::to_value(params) {
                        extra_data.insert("params".to_string(), p);
                    };

                    if let Ok(c) = serde_json::to_value(checks) {
                        extra_data.insert("checks".to_string(), c);
                    };

                    return Err(OidcClientError::new_rp_error(
                        "unexpected params encountered for \"none\" response",
                        None,
                        Some(extra_data),
                    ));
                } else if res_type == "code" || res_type == "token" || res_type == "id_token" {
                    let mut message = "";

                    if res_type == "code" && params.code.is_none() {
                        message = "code missing from response";
                    }

                    if res_type == "token" && params.access_token.is_none() {
                        message = "access_token missing from response";
                    }

                    if res_type == "token" && params.token_type.is_none() {
                        message = "token_type missing from response";
                    }

                    if res_type == "id_token" && params.id_token.is_none() {
                        message = "id_token missing from response";
                    }

                    if !message.is_empty() {
                        let mut extra_data: HashMap<String, Value> = HashMap::new();

                        if let Ok(p) = serde_json::to_value(params) {
                            extra_data.insert("params".to_string(), p);
                        };

                        if let Ok(c) = serde_json::to_value(checks) {
                            extra_data.insert("checks".to_string(), c);
                        };

                        return Err(OidcClientError::new_rp_error(
                            message,
                            None,
                            Some(extra_data),
                        ));
                    }
                }
            }
        }

        if params.id_token.as_ref().is_some_and(|x| !x.is_empty()) {
            let mut other_fields = match &params.other {
                Some(o) => o.clone(),
                None => HashMap::new(),
            };

            if let Some(state) = &params.state {
                other_fields.insert("state".to_string(), json!(state));
            }

            if let Some(code) = &params.code {
                other_fields.insert("code".to_string(), json!(code));
            }

            let expires_at = match other_fields.get("expires_at") {
                Some(eat) => eat.as_i64(),
                None => None,
            };
            let scope = match other_fields.get("scope") {
                Some(s) => s.as_str().map(|f| f.to_owned()),
                None => None,
            };
            let token_type = match other_fields.get("token_type") {
                Some(s) => s.as_str().map(|f| f.to_owned()),
                None => None,
            };
            let session_state = match other_fields.get("session_state") {
                Some(s) => s.as_str().map(|f| f.to_owned()),
                None => None,
            };
            let refresh_token = match other_fields.get("refresh_token") {
                Some(s) => s.as_str().map(|f| f.to_owned()),
                None => None,
            };
            let expires_in = match &params.expires_in {
                Some(exp_in) => exp_in.parse::<i64>().ok(),
                None => None,
            };

            let token_params = TokenSetParams {
                access_token: params.access_token.clone(),
                id_token: params.id_token.clone(),
                expires_in,
                expires_at,
                scope,
                token_type,
                session_state,
                refresh_token,
                other: Some(other_fields),
            };

            let mut token_set = TokenSet::new(token_params);

            token_set = self.decrypt_id_token(token_set)?;

            token_set = self
                .validate_id_token_async(
                    token_set,
                    checks.nonce.clone(),
                    "authorization",
                    checks.max_age,
                    oauth_checks.state.clone(),
                )
                .await?;

            if params.code.is_none() {
                return Ok(token_set);
            }
        }

        if params.code.is_some() {
            let mut exchange_body = match extras.as_ref() {
                Some(e) => e
                    .exchange_body
                    .clone()
                    .unwrap_or(HashMap::<String, Value>::new()),
                None => HashMap::<String, Value>::new(),
            };

            exchange_body.insert("grant_type".to_string(), json!("authorization_code"));
            exchange_body.insert("code".to_string(), json!(params.code.as_ref().unwrap()));
            if let Some(ru) = redirect_uri.as_ref() {
                exchange_body.insert("redirect_uri".to_string(), json!(ru));
            };

            if let Some(cv) = oauth_checks.code_verifier.as_ref() {
                exchange_body.insert("code_verifier".to_string(), json!(cv));
            };

            let mut auth_post_params = AuthenticationPostParams::default();

            match &extras {
                Some(e) => {
                    auth_post_params.client_assertion_payload = e.client_assertion_payload.clone();
                    auth_post_params.dpop = e.dpop.clone();
                }
                None => {}
            };

            let mut token_set = self.grant_async(exchange_body, auth_post_params).await?;

            token_set = self.decrypt_id_token(token_set)?;
            token_set = self
                .validate_id_token_async(
                    token_set,
                    checks.nonce,
                    "token",
                    checks.max_age,
                    oauth_checks.state,
                )
                .await?;

            if params.session_state.is_some() {
                token_set.set_session_state(params.session_state);
            }

            return Ok(token_set);
        }

        let mut other_fields = match &params.other {
            Some(o) => o.clone(),
            None => HashMap::new(),
        };

        if let Some(state) = params.state {
            other_fields.insert("state".to_string(), json!(state));
        }

        if let Some(code) = params.code {
            other_fields.insert("code".to_string(), json!(code));
        }

        let expires_at = match other_fields.get("expires_at") {
            Some(eat) => eat.as_i64(),
            None => None,
        };
        let scope = match other_fields.get("scope") {
            Some(s) => s.as_str().map(|f| f.to_owned()),
            None => None,
        };
        let token_type = match other_fields.get("token_type") {
            Some(s) => s.as_str().map(|f| f.to_owned()),
            None => None,
        };
        let session_state = match other_fields.get("session_state") {
            Some(s) => s.as_str().map(|f| f.to_owned()),
            None => None,
        };
        let refresh_token = match other_fields.get("refresh_token") {
            Some(s) => s.as_str().map(|f| f.to_owned()),
            None => None,
        };
        let expires_in = match params.expires_in {
            Some(exp_in) => exp_in.parse::<i64>().ok(),
            None => None,
        };

        let token_params = TokenSetParams {
            access_token: params.access_token,
            id_token: params.id_token,
            expires_in,
            expires_at,
            scope,
            token_type,
            session_state,
            refresh_token,
            other: Some(other_fields),
        };

        Ok(TokenSet::new(token_params))
    }

    /// # Introspect
    /// Performs an introspection request at `Issuer::introspection_endpoint`
    ///
    /// - `token` : The token to introspect
    /// - `token_type_hint` : Type of the token passed in `token`. Usually `access_token` or `refresh_token`
    /// - `params`: See [IntrospectionParams]
    pub async fn introspect_async(
        &mut self,
        token: &str,
        token_type_hint: Option<String>,
        params: Option<IntrospectionParams>,
    ) -> Result<Response, OidcClientError> {
        let issuer = match self.issuer.as_ref() {
            Some(iss) => iss,
            None => return Err(OidcClientError::new_type_error("Issuer is required", None)),
        };

        if issuer.introspection_endpoint.is_none() {
            return Err(OidcClientError::new_type_error(
                "introspection_endpoint must be configured on the issuer",
                None,
            ));
        }

        let mut form = HashMap::new();

        form.insert("token".to_string(), json!(token));

        if let Some(hint) = token_type_hint {
            form.insert("token_type_hint".to_string(), json!(hint));
        }

        let mut client_assertion_payload = None;

        if let Some(p) = params {
            if let Some(body) = p.introspect_body {
                for (k, v) in body {
                    form.insert(k, v);
                }
            }

            if let Some(cap) = p.client_assertion_payload {
                client_assertion_payload = Some(cap);
            }
        }

        let req = Request {
            form: Some(form),
            ..Default::default()
        };

        self.authenticated_post_async(
            "introspection",
            req,
            AuthenticationPostParams {
                client_assertion_payload,
                ..Default::default()
            },
        )
        .await
    }

    /// # Request Resource
    /// Performs a request to fetch using the access token at `resource_url`.
    ///
    /// - `resource_url` : Url of the resource server
    /// - `token` : Token to authenticate the resource fetch request
    /// - `token_type` : Type of the `token`. Eg: `access_token`
    /// - `retry` : Whether to retry if the request failed or not
    /// - `params` : See [RequestResourceParams]
    #[async_recursion::async_recursion(? Send)]
    pub async fn request_resource_async(
        &mut self,
        resource_url: &str,
        token: &str,
        token_type: Option<String>,
        retry: bool,
        mut params: RequestResourceParams,
    ) -> Result<Response, OidcClientError> {
        let tt = token_type.unwrap_or("Bearer".to_string());

        if !params
            .headers
            .iter()
            .any(|(k, _)| k.as_str().to_lowercase() == "authorization")
        {
            if let Ok(header_val) = HeaderValue::from_str(&format!("{} {}", tt, token)) {
                params.headers.insert("Authorization", header_val);
            }
        }

        let req = Request {
            method: params.method.clone(),
            body: params.body.clone(),
            url: resource_url.to_string(),
            mtls: self
                .tls_client_certificate_bound_access_tokens
                .is_some_and(|x| x),
            headers: params.headers.clone(),
            bearer: params.bearer,
            expect_body_to_be_json: params.expect_body_to_be_json,
            ..Default::default()
        };

        match request_async(req, &mut self.request_interceptor).await {
            Ok(r) => Ok(r),
            // TODO: revisit when implementing the dpop
            Err(OidcClientError::OPError(e, Some(res))) => {
                if retry && e.error == "use_dpop_nonce" {
                    if let Some(header_val) = res.headers.get("www-authenticate") {
                        if let Some(header_val_str) =
                            header_val.to_str().ok().map(|x| x.to_lowercase())
                        {
                            if header_val_str.starts_with("dpop ") {
                                return self
                                    .request_resource_async(
                                        resource_url,
                                        token,
                                        Some(tt),
                                        false,
                                        params.clone(),
                                    )
                                    .await;
                            }
                        }
                    }
                }

                return Err(OidcClientError::new_op_error(
                    e.error,
                    e.error_description,
                    e.error_uri,
                    e.state,
                    e.scope,
                    Some(res),
                ));
            }
            Err(e) => Err(e),
        }
    }

    /// # Callback Params
    /// Tries to convert the Url or a body string to [CallbackParams]
    ///
    /// - `incoming_url` : The full url of the request ([Url]). Use this param if the request is of the type GET
    /// - `incoming_body` : Incoming body. Use this param if the request is of the type POST
    ///
    /// > Only one of the above parameter is parsed.
    pub fn callback_params(
        &self,
        incoming_url: Option<&Url>,
        incoming_body: Option<String>,
    ) -> Result<CallbackParams, OidcClientError> {
        let mut query_pairs = None;
        if let Some(url) = incoming_url {
            query_pairs = Some(
                url.query_pairs()
                    .map(|(x, y)| (x.to_string(), y.to_string()))
                    .collect::<Vec<(String, String)>>(),
            );
        } else if let Some(body) = incoming_body {
            if let Ok(decoded) = urlencoding::decode(&body) {
                query_pairs = Some(
                    querystring::querify(&decoded)
                        .iter()
                        .map(|(x, y)| (x.to_string(), y.to_string()))
                        .collect(),
                );
            }
        }

        if let Some(qp) = query_pairs {
            let mut params = CallbackParams::default();

            let mut other = HashMap::new();

            for (k, v) in qp {
                if k == "access_token" {
                    params.access_token = Some(v.to_string());
                } else if k == "code" {
                    params.code = Some(v.to_string());
                } else if k == "error" {
                    params.error = Some(v.to_string());
                } else if k == "error_description" {
                    params.error_description = Some(v.to_string());
                } else if k == "error_uri" {
                    params.error_uri = Some(v.to_string());
                } else if k == "id_token" {
                    params.id_token = Some(v.to_string());
                } else if k == "iss" {
                    params.iss = Some(v.to_string());
                } else if k == "response" {
                    params.response = Some(v.to_string());
                } else if k == "session_state" {
                    params.session_state = Some(v.to_string());
                } else if k == "state" {
                    params.state = Some(v.to_string());
                } else if k == "token_type" {
                    params.token_type = Some(v.to_string());
                } else {
                    let val = v.to_string();
                    let key = k.to_string();
                    if let Ok(u_64) = val.parse::<u64>() {
                        other.insert(key, json!(u_64));
                    } else if let Ok(i_64) = val.parse::<i64>() {
                        other.insert(key, json!(i_64));
                    } else if let Ok(f_64) = val.parse::<f64>() {
                        other.insert(key, json!(f_64));
                    } else if val == "true" || val == "false" {
                        let bool = val == "true";
                        other.insert(key, json!(bool));
                    } else if let Ok(arr) = serde_json::from_str::<Vec<Value>>(&val) {
                        other.insert(key, json!(arr));
                    } else if let Ok(obj) = serde_json::from_str::<Value>(&val) {
                        other.insert(key, obj);
                    } else {
                        other.insert(key, json!(val));
                    }
                }
            }

            if !other.is_empty() {
                params.other = Some(other);
            }
            return Ok(params);
        }

        Err(OidcClientError::new_error(
            "could not parse the request",
            None,
        ))
    }

    /// # Refresh Request
    /// Performs a Token Refresh request at Issuer's `token_endpoint`
    ///
    /// - `token_set` : [TokenSet] with refresh token that will be used to perform the request
    /// - `params` : See [RefreshTokenRequestParams]
    pub async fn refresh_async(
        &mut self,
        token_set: TokenSet,
        params: Option<RefreshTokenRequestParams>,
    ) -> Result<TokenSet, OidcClientError> {
        let refresh_token = match token_set.get_refresh_token() {
            Some(rt) => rt,
            None => {
                return Err(OidcClientError::new_type_error(
                    "refresh_token not present in TokenSet",
                    None,
                ));
            }
        };

        let mut body = HashMap::new();

        if let Some(exchange_payload) = params.as_ref().and_then(|x| x.exchange_body.as_ref()) {
            for (k, v) in exchange_payload {
                body.insert(k.to_owned(), v.to_owned());
            }
        }

        body.insert("grant_type".to_string(), json!("refresh_token"));
        body.insert("refresh_token".to_string(), json!(refresh_token));

        let auth_post_params = AuthenticationPostParams {
            client_assertion_payload: params.and_then(|x| x.client_assertion_payload),
            ..Default::default()
        };

        let mut new_token_set = self.grant_async(body, auth_post_params).await?;

        if let Some(id_token) = new_token_set.get_id_token() {
            new_token_set = self.decrypt_id_token(new_token_set)?;
            new_token_set = self
                .validate_id_token_async(new_token_set, None, "token", None, None)
                .await?;

            if let Some(Value::String(expected_sub)) = token_set.claims()?.get("sub") {
                if let Some(Value::String(new_sub)) = new_token_set.claims()?.get("sub") {
                    if expected_sub != new_sub {
                        let mut extra_data: HashMap<String, Value> = HashMap::new();

                        extra_data.insert("jwt".to_string(), json!(id_token));

                        return Err(OidcClientError::new_rp_error(
                            &format!("sub mismatch, expected {}, got: {}", expected_sub, new_sub),
                            None,
                            Some(extra_data),
                        ));
                    }
                }
            }
        }

        Ok(new_token_set)
    }

    /// # Revoke Token
    /// Performs a token revocation at Issuer's `revocation_endpoint`
    ///
    /// - `token` : The token to be revoked
    /// - `hint` : Hint to which type of token is being revoked
    /// - `params` : See [RevokeRequestParams]
    pub async fn revoke_async(
        &mut self,
        token: String,
        hint: Option<String>,
        params: Option<RevokeRequestParams>,
    ) -> Result<Response, OidcClientError> {
        let issuer = match self.issuer.as_ref() {
            Some(iss) => iss,
            None => return Err(OidcClientError::new_type_error("Issuer is required", None)),
        };

        if issuer.revocation_endpoint.is_none() {
            return Err(OidcClientError::new_type_error(
                "revocation_endpoint must be configured on the issuer",
                None,
            ));
        }

        let mut form = HashMap::new();

        form.insert("token".to_string(), json!(token));

        if let Some(h) = hint {
            form.insert("token_type_hint".to_string(), json!(h));
        }

        let mut client_assertion_payload = None;

        if let Some(p) = params {
            if let Some(body) = p.revocation_body {
                for (k, v) in body {
                    form.insert(k, v);
                }
            }

            if let Some(cap) = p.client_assertion_payload {
                client_assertion_payload = Some(cap);
            }
        }

        let req = Request {
            form: Some(form),
            expect_body: false,
            ..Default::default()
        };

        self.authenticated_post_async(
            "revocation",
            req,
            AuthenticationPostParams {
                client_assertion_payload,
                ..Default::default()
            },
        )
        .await
    }

    /// # Userinfo
    /// Performs userinfo request at Issuer's `userinfo` endpoint.
    ///
    /// - `token_set` : [TokenSet] with `access_token` that will be used to perform the request
    /// - `options` : See [UserinfoRequestParams]
    pub async fn userinfo_async(
        &mut self,
        token_set: &TokenSet,
        options: UserinfoRequestParams,
    ) -> Result<JwtPayload, OidcClientError> {
        let issuer = match self.issuer.as_ref() {
            Some(iss) => iss,
            None => return Err(OidcClientError::new_type_error("Issuer is required", None)),
        };

        let userinfo_endpoint = match &issuer.userinfo_endpoint {
            Some(e) => e.to_string(),
            None => {
                return Err(OidcClientError::new_type_error(
                    "userinfo_endpoint must be configured on the issuer",
                    None,
                ))
            }
        };

        let access_token = token_set
            .get_access_token()
            .ok_or(OidcClientError::new_type_error(
                "access_token is required in token_set",
                None,
            ))?;

        if options.via != "header" && options.via != "body" {
            return Err(OidcClientError::new_type_error(
                "via can only be body or header",
                None,
            ));
        }

        let mut req = Request::default();

        if options.method != Method::GET && options.method != Method::POST {
            return Err(OidcClientError::new_type_error(
                "userinfo_async() method can only be POST or a GET",
                None,
            ));
        }

        if options.via == "body" && options.method != Method::POST {
            return Err(OidcClientError::new_type_error(
                "can only send body on POST",
                None,
            ));
        }

        let jwt = self.userinfo_signed_response_alg.is_some()
            || self.userinfo_encrypted_response_alg.is_some();

        if jwt {
            req.headers
                .insert("Accept", HeaderValue::from_static("application/jwt"));
        } else {
            req.headers
                .insert("Accept", HeaderValue::from_static("application/json"));
        }

        let mtls = self
            .tls_client_certificate_bound_access_tokens
            .is_some_and(|x| x);

        let mut target_url = None;

        if mtls && issuer.mtls_endpoint_aliases.is_some() {
            if let Some(mtls_alias) = &issuer.mtls_endpoint_aliases {
                if mtls_alias.userinfo_endpoint.is_some() {
                    target_url = mtls_alias.userinfo_endpoint.clone();
                }
            }
        }

        let mut url = Url::parse(target_url.unwrap_or(userinfo_endpoint).as_str())
            .map_err(|_| OidcClientError::new_error("Invalid Url", None))?;

        let mut form_body = HashMap::new();

        if options.via == "body" {
            // What?
            req.headers.remove("Authorization");
            req.headers.insert(
                "Content-Type",
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            );
            form_body.insert("access_token".to_string(), json!(access_token));
        }

        if let Some(params) = &options.params {
            if options.method == Method::GET {
                for (k, v) in params {
                    if let Some(v_str) = v.as_str() {
                        url.query_pairs_mut().append_pair(k, v_str);
                    }
                }
            } else if options.via == "body" && options.method == Method::POST {
                for (k, v) in params {
                    form_body.insert(k.to_owned(), v.to_owned());
                }
            } else {
                req.headers.remove("Content-Type");
                req.headers.insert(
                    "Content-Type",
                    HeaderValue::from_static("application/x-www-form-urlencoded"),
                );
                for (k, v) in params {
                    form_body.insert(k.to_owned(), v.to_owned());
                }
            }
        }

        let mut body = None;
        if !form_body.is_empty() {
            let mut form_encoded_body = String::new();
            for (k, v) in form_body {
                let v_str = get_serde_value_as_string(&v)?;
                form_encoded_body += &format!(
                    "{}={}&",
                    urlencoding::encode(&k),
                    urlencoding::encode(&v_str)
                );
            }

            form_encoded_body = form_encoded_body.trim_end_matches('&').to_owned();
            body = Some(form_encoded_body);
        }

        let req_res_params = RequestResourceParams {
            method: options.method,
            headers: req.headers,
            bearer: true,
            expect_body_to_be_json: !jwt,
            body,
        };

        let res = self
            .request_resource_async(
                url.as_str(),
                &access_token,
                token_set.get_token_type(),
                false,
                req_res_params,
            )
            .await?;

        let payload = match jwt {
            true => {
                if !&res.headers.iter().any(|(x, v)| {
                    if let Ok(Some(val)) = v.to_str().map(|x| {
                        x.split(';')
                            .collect::<Vec<&str>>()
                            .first()
                            .map(|x| x.to_owned())
                    }) {
                        return x.as_str().to_lowercase() == "content-type"
                            && val == "application/jwt";
                    }
                    false
                }) {
                    return Err(OidcClientError::new_rp_error(
                        "expected application/jwt response from the userinfo_endpoint",
                        Some(res),
                        None,
                    ));
                }

                let body = res
                    .body
                    .as_ref()
                    .ok_or(OidcClientError::new_rp_error(
                        "body was emtpy",
                        Some(res.clone()),
                        None,
                    ))?
                    .to_owned();
                let userinfo = self.decrypt_jwt_userinfo(body)?;

                if self.userinfo_signed_response_alg.is_none() {
                    if let Ok(Value::Object(json_res)) = serde_json::from_str::<Value>(&userinfo) {
                        let mut payload = JwtPayload::new();
                        for (k, v) in json_res {
                            payload.set_claim(&k, Some(v)).unwrap_or_default();
                        }
                        payload
                    } else {
                        let mut extra_data: HashMap<String, Value> = HashMap::new();

                        extra_data.insert("jwt".to_string(), json!(userinfo));

                        return Err(OidcClientError::new_rp_error(
                            "failed to parse userinfo JWE payload as JSON",
                            Some(res),
                            Some(extra_data),
                        ));
                    }
                } else {
                    let (payload, _, _) = self.validate_jwt_userinfo_async(&userinfo).await?;
                    payload
                }
            }
            false => {
                let body = res
                    .body
                    .as_ref()
                    .ok_or(OidcClientError::new_rp_error(
                        "body was emtpy",
                        Some(res.clone()),
                        None,
                    ))?
                    .to_owned();

                if let Ok(Value::Object(json_res)) = serde_json::from_str::<Value>(&body) {
                    let mut payload = JwtPayload::new();
                    for (k, v) in json_res {
                        payload.set_claim(&k, Some(v)).unwrap_or_default();
                    }
                    payload
                } else {
                    let mut extra_data: HashMap<String, Value> = HashMap::new();

                    extra_data.insert("jwt".to_string(), json!(body));

                    return Err(OidcClientError::new_rp_error(
                        "failed to parse userinfo JWE payload as JSON",
                        Some(res),
                        Some(extra_data),
                    ));
                }
            }
        };

        if let Some(id_token) = token_set.get_id_token() {
            if let Some(Value::String(expected_sub)) = token_set.claims()?.get("sub") {
                if let Some(new_sub) = payload.subject() {
                    if expected_sub != new_sub {
                        let mut extra_data: HashMap<String, Value> = HashMap::new();

                        if let Some(Ok(b)) = res.body.map(|x| serde_json::from_str::<Value>(&x)) {
                            extra_data.insert("body".to_string(), b);
                        }

                        extra_data.insert("jwt".to_string(), json!(id_token));

                        return Err(OidcClientError::new_rp_error(
                            &format!(
                                "userinfo sub mismatch, expected {}, got: {}",
                                expected_sub, new_sub
                            ),
                            None,
                            Some(extra_data),
                        ));
                    }
                }
            }
        }

        Ok(payload)
    }

    /// # Request Object
    ///
    /// Creates a request object for JAR
    ///
    /// - `request_object` : A [Value] which should be an object
    pub async fn request_object_async(
        &mut self,
        mut request_object: Value,
    ) -> Result<String, OidcClientError> {
        if !request_object.is_object() {
            return Err(OidcClientError::new_type_error(
                "request_object must be a plain object",
                None,
            ));
        }

        let e_key_management = self.request_object_encryption_alg.clone();

        let header_alg = self
            .request_object_signing_alg
            .as_ref()
            .map(|x| x.to_owned())
            .unwrap_or("none".to_string());
        let header_typ = "oauth-authz-req+jwt";

        let unix = now();

        request_object["iss"] = json!(self.client_id);

        if let Some(aud) = self.issuer.as_ref().map(|x| x.issuer.to_owned()) {
            request_object["aud"] = json!(aud);
        }

        request_object["client_id"] = json!(self.client_id);

        request_object["jti"] = json!(random());

        request_object["iat"] = json!(unix);

        request_object["exp"] = json!(unix + 300);

        if self.is_fapi {
            request_object["nbf"] = json!(unix);
        }

        let signed;
        let mut key = None;

        let payload = request_object.to_string();

        if header_alg == "none" {
            let encoded_header = base64_url::encode(&format!(
                "{{\"alg\":\"{}\",\"typ\":\"{}\"}}",
                &header_alg, header_typ
            ));
            let encoded_payload = base64_url::encode(&payload);
            signed = format!("{}.{}.", encoded_header, encoded_payload);
        } else {
            let symmetric = &header_alg.starts_with("HS");
            if *symmetric {
                key = Some(self.secret_for_alg(&header_alg)?);
            } else {
                let keystore =
                    self.private_jwks
                        .as_ref()
                        .ok_or(OidcClientError::new_type_error(
                            &format!(
                        "no keystore present for client, cannot sign using alg {header_alg}"
                    ),
                            None,
                        ))?;

                key = keystore
                    .get(Some(header_alg.to_string()), Some("sig".to_string()), None)?
                    .first()
                    .map(|x| x.to_owned().clone());

                if key.is_none() {
                    return Err(OidcClientError::new_type_error(
                        &format!("no key to sign with found for alg {header_alg}"),
                        None,
                    ));
                }
            }

            let jwk = key.clone().ok_or(OidcClientError::new_error(
                "No key found for signing request object",
                None,
            ))?;
            let signer = jwk.to_signer()?;

            let mut header = JwsHeader::new();
            header.set_algorithm(&header_alg);
            header.set_token_type(header_typ);

            if !symmetric {
                if let Some(kid) = jwk.key_id() {
                    header.set_key_id(kid);
                }
            }

            signed = jws::serialize_compact(payload.as_bytes(), &header, &*signer)
                .map_err(|e| OidcClientError::new_error(&e.to_string(), None))?;
        }

        let field_alg = match e_key_management {
            Some(a) => a,
            None => return Ok(signed),
        };

        let field_enc = self
            .request_object_encryption_enc
            .as_ref()
            .map(|x| x.to_owned())
            .unwrap_or("A128CBC-HS256".to_string()); // e_content_encryption
        let field_cty = "oauth-authz-req+jwt";

        if field_alg.contains("RSA") || field_alg.contains("ECDH") {
            if let Some(issuer) = &mut self.issuer {
                let query_params = QueryKeyStore {
                    alg: Some(field_alg.to_string()),
                    key_use: Some("enc".to_string()),
                    ..Default::default()
                };
                key = issuer
                    .query_keystore_async(query_params, true)
                    .await?
                    .get_keys()
                    .first()
                    .map(|x| x.to_owned());
            }
        } else {
            let alg = if field_alg == "dir" {
                &field_enc
            } else {
                &field_alg
            };
            key = Some(self.secret_for_alg(alg)?);
        }

        let jwk = key.ok_or(OidcClientError::new_error(
            "No key found for encrypting request object",
            None,
        ))?;
        let encryptor = jwk.to_jwe_encrypter()?;

        let mut jwe_header = JweHeader::new();

        jwe_header.set_algorithm(&field_alg);
        jwe_header.set_content_encryption(field_enc);
        jwe_header.set_content_type(field_cty);
        if let Some(kid) = jwk.key_id() {
            jwe_header.set_key_id(kid);
        }

        jwe::serialize_compact(payload.as_bytes(), &jwe_header, &*encryptor)
            .map_err(|x| OidcClientError::new_error(&x.to_string(), None))
    }

    /// # Pushed Authorization Request
    ///
    /// Performs a PAR on the `pushed_authorization_request_endpoint`
    ///
    /// - `params` : See [AuthorizationParameters]
    /// - `par_params` : See [PushedAuthorizationRequestParams]
    pub async fn pushed_authorization_request_async(
        &mut self,
        params: Option<AuthorizationParameters>,
        par_params: Option<PushedAuthorizationRequestParams>,
    ) -> Result<Value, OidcClientError> {
        let issuer = match self.issuer.as_ref() {
            Some(iss) => iss,
            None => return Err(OidcClientError::new_type_error("Issuer is required", None)),
        };

        if issuer.pushed_authorization_request_endpoint.is_none() {
            return Err(OidcClientError::new_type_error(
                "pushed_authorization_request_endpoint must be configured on the issuer",
                None,
            ));
        }

        let auth_params = params.unwrap_or_default();

        let mut body = if auth_params.request.is_some() {
            auth_params
        } else {
            self.authorization_params(auth_params)
        };

        body.client_id = Some(self.client_id.clone());

        let mut form_body = HashMap::new();

        if let Some(other) = body.other {
            for (k, v) in other {
                form_body.insert(k, json!(v));
            }
        }

        insert_form(&mut form_body, "client_id", body.client_id);
        insert_form(&mut form_body, "acr_values", body.acr_values);
        insert_form(&mut form_body, "audience", body.audience);
        insert_form(&mut form_body, "claims_locales", body.claims_locales);
        insert_form(
            &mut form_body,
            "code_challenge_method",
            body.code_challenge_method,
        );
        insert_form(&mut form_body, "code_challenge", body.code_challenge);
        insert_form(&mut form_body, "display", body.display);
        insert_form(&mut form_body, "id_token_hint", body.id_token_hint);
        insert_form(&mut form_body, "login_hint", body.login_hint);
        insert_form(&mut form_body, "max_age", body.max_age);
        insert_form(&mut form_body, "nonce", body.nonce);
        insert_form(&mut form_body, "prompt", body.prompt);
        insert_form(&mut form_body, "redirect_uri", body.redirect_uri);
        insert_form(&mut form_body, "registration", body.registration);
        insert_form(&mut form_body, "request_uri", body.request_uri);
        insert_form(&mut form_body, "request", body.request);
        insert_form(&mut form_body, "response_mode", body.response_mode);
        insert_form(&mut form_body, "response_type", body.response_type);
        insert_form(&mut form_body, "scope", body.scope);
        insert_form(&mut form_body, "state", body.state);
        insert_form(&mut form_body, "ui_locales", body.ui_locales);

        if let Some(c) = &body.claims {
            if let Ok(v) = serde_json::to_value(c) {
                form_body.insert("claims".to_string(), v);
            }
        }

        let req = Request {
            form: Some(form_body),
            expect_body_to_be_json: true,
            expected: StatusCode::CREATED,
            ..Default::default()
        };

        let params = AuthenticationPostParams {
            client_assertion_payload: par_params.and_then(|x| x.client_assertion_payload),
            endpoint_auth_method: Some("token".to_string()),
            ..Default::default()
        };

        let res = self
            .authenticated_post_async("pushed_authorization_request", req, params)
            .await?;

        let body_obj = res.body_to_json_value()?;

        if body_obj.get("expires_in").is_none() {
            return Err(OidcClientError::new_rp_error(
                "expected expires_in in Pushed Authorization Successful Response",
                Some(res),
                None,
            ));
        }

        if !body_obj["expires_in"].is_number() {
            return Err(OidcClientError::new_rp_error(
                "invalid expires_in value in Pushed Authorization Successful Response",
                Some(res),
                None,
            ));
        }

        if body_obj.get("request_uri").is_none() {
            return Err(OidcClientError::new_rp_error(
                "expected request_uri in Pushed Authorization Successful Response",
                Some(res),
                None,
            ));
        }

        if !body_obj["request_uri"].is_string() {
            return Err(OidcClientError::new_rp_error(
                "invalid request_uri value in Pushed Authorization Successful Response",
                Some(res),
                None,
            ));
        }

        Ok(body_obj)
    }
}

fn insert_query(qp: &mut HashMap<String, String>, key: &str, value: Option<String>) {
    if let Some(v) = value {
        qp.insert(key.to_string(), v);
    }
}

fn insert_form(f: &mut HashMap<String, Value>, key: &str, value: Option<String>) {
    if let Some(v) = value {
        f.insert(key.to_string(), json!(v));
    }
}
