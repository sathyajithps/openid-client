use std::collections::HashMap;
use std::time::Duration;

use reqwest::header::HeaderValue;
use reqwest::Method;
use serde_json::{json, Value};
use url::{form_urlencoded, Url};

use crate::http::request_async;
use crate::types::{
    CallbackExtras, CallbackParams, IntrospectionParams, OAuthCallbackChecks, OpenIDCallbackChecks,
    Request, RequestResourceParams, Response,
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
            response_type: Some("json".to_string()),
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
            response_type: Some("json".to_string()),
            method: Method::POST,
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
    #[async_recursion::async_recursion(?Send)]
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
}

fn insert_query(qp: &mut HashMap<String, String>, key: &str, value: Option<String>) {
    if let Some(v) = value {
        qp.insert(key.to_string(), v);
    }
}
