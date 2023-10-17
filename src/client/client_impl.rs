use std::collections::HashMap;
use std::time::Duration;

use serde_json::{json, Value};
use url::{form_urlencoded, Url};

use crate::types::{
    CallbackExtras, CallbackParams, OAuthCallbackChecks, OpenIDCallbackChecks, Request,
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

        let other_fields = match params.other {
            Some(o) => o.clone(),
            None => HashMap::new(),
        };

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
            let other_fields = match &params.other {
                Some(o) => o.clone(),
                None => HashMap::new(),
            };

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
}

fn insert_query(qp: &mut HashMap<String, String>, key: &str, value: Option<String>) {
    if let Some(v) = value {
        qp.insert(key.to_string(), v);
    }
}
