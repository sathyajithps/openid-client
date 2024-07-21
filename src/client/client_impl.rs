use josekit::jwe::JweHeader;
use josekit::jws::JwsHeader;
use josekit::{jwe, jws};
use std::collections::HashMap;
use std::time::Duration;

use serde_json::{json, Value};
use url::{form_urlencoded, Url};

use crate::helpers::{generate_random, get_serde_value_as_string, string_map_to_form_url_encoded};
use crate::jwks::jwks::CustomJwk;
use crate::types::grant_params::GrantParams;
use crate::types::http_client::HttpMethod;
use crate::types::query_keystore::QueryKeyStore;
use crate::types::{
    CallbackParams, ClaimParam, DeviceAuthorizationExtras, DeviceAuthorizationParams,
    DeviceAuthorizationResponse, Fapi, GrantExtras, HttpRequest, HttpResponse, IntrospectionExtras,
    OAuthCallbackChecks, OAuthCallbackParams, OidcHttpClient, OidcReturnType, OpenIdCallbackParams,
    PushedAuthorizationRequestExtras, RefreshTokenExtras, RequestResourceOptions,
    RequestResourceParams, RevokeExtras, UserinfoOptions,
};
use crate::{
    helpers::convert_json_to,
    tokenset::{TokenSet, TokenSetParams},
    types::{
        authentication_post_param::AuthenticationPostParams, AuthorizationParameters,
        EndSessionParameters, OidcClientError,
    },
};

use super::{Client, DeviceFlowHandle};

/// Implementation for Client
impl Client {
    /// Returns if the client is fapi or not
    pub fn is_fapi(&self) -> bool {
        self.fapi.is_some()
    }

    /// Returns if the client is fapi 1 or not
    pub fn is_fapi1(&self) -> bool {
        self.fapi.as_ref().is_some_and(|x| matches!(x, Fapi::V1))
    }

    /// Returns if the client is fapi 2 or not
    pub fn is_fapi2(&self) -> bool {
        self.fapi.as_ref().is_some_and(|x| matches!(x, Fapi::V2))
    }

    /// # Authorization Url
    /// Builds an authorization url with respect to the `parameters`
    ///
    /// - `parameters` - [AuthorizationParameters] : Customize the authorization request
    pub fn authorization_url(
        &self,
        mut parameters: AuthorizationParameters,
    ) -> OidcReturnType<Url> {
        let mut authorization_endpiont = self.get_auth_endpoint()?;

        let mut query_params: HashMap<String, String> = authorization_endpiont
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        parameters = self.authorization_params(parameters);

        let params_query: HashMap<String, String> = parameters.into();

        query_params.extend(params_query);

        authorization_endpiont.set_query(None);

        let mut new_query_params = form_urlencoded::Serializer::new(String::new());

        let mut scope_str = None;

        for (query, value) in &query_params {
            if query == "scope" {
                scope_str = Some(urlencoding::encode(value).to_string());
                continue;
            }
            new_query_params.append_pair(query, value);
        }

        if !query_params.is_empty() {
            let mut query = new_query_params.finish();

            if let Some(scope) = scope_str {
                query.push_str(&format!("&scope={}", scope));
            }

            authorization_endpiont.set_query(Some(&query));
        }

        Ok(authorization_endpiont)
    }

    /// # End Session Url
    /// Builds an endsession url with respect to the `parameters`
    ///
    /// - `parameters` - [EndSessionParameters] : Customize the endsession url
    pub fn end_session_url(&self, mut parameters: EndSessionParameters) -> OidcReturnType<Url> {
        let mut end_session_endpoint = match &self.issuer {
            Some(i) => match &i.end_session_endpoint {
                Some(ae) => match Url::parse(ae) {
                    Ok(u) => u,
                    Err(_) => {
                        return Err(Box::new(OidcClientError::new_type_error(
                            "end_session_endpoint is invalid url",
                            None,
                        )));
                    }
                },
                None => {
                    return Err(Box::new(OidcClientError::new_type_error(
                        "end_session_endpoint must be configured on the issuer",
                        None,
                    )));
                }
            },
            None => {
                return Err(Box::new(OidcClientError::new_error(
                    "issuer is empty",
                    None,
                )))
            }
        };

        if parameters.client_id.is_none() {
            parameters.client_id = Some(self.client_id.clone());
        }

        let mut post_logout: Option<String> = None;

        if let Some(plrus) = &self.post_logout_redirect_uris {
            if let Some(first) = plrus.first() {
                post_logout = Some(first.clone());
            }
        }

        if let Some(plu) = parameters.post_logout_redirect_uri {
            post_logout = Some(plu);
        }

        let mut query_params: HashMap<String, String> = end_session_endpoint
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        if let Some(other) = parameters.other {
            for (k, v) in other {
                query_params.entry(k).or_insert(v);
            }
        }

        if let Some(client_id) = parameters.client_id {
            query_params.insert("client_id".to_string(), client_id);
        }

        if let Some(post_logout_redirect_uri) = post_logout {
            query_params.insert(
                "post_logout_redirect_uri".to_string(),
                post_logout_redirect_uri,
            );
        }

        if let Some(id_token_hint) = parameters.id_token_hint {
            query_params.insert("id_token_hint".to_string(), id_token_hint);
        }

        if let Some(logout_hint) = parameters.logout_hint {
            query_params.insert("logout_hint".to_string(), logout_hint);
        }

        if let Some(state) = parameters.state {
            query_params.insert("state".to_string(), state);
        }

        if !query_params.is_empty() {
            let new_query_params = string_map_to_form_url_encoded(&query_params)?;
            end_session_endpoint.set_query(Some(&new_query_params));
        }

        Ok(end_session_endpoint)
    }

    /// # Authorization Post
    /// Builds an authorization post page with respect to the `parameters`
    ///
    /// - `parameters` - [AuthorizationParameters] : Customize the authorization request
    pub fn authorization_post(
        &self,
        mut parameters: AuthorizationParameters,
    ) -> OidcReturnType<String> {
        let authorization_endpiont = self.get_auth_endpoint()?;

        let mut query_params: HashMap<String, String> = authorization_endpiont
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        parameters = self.authorization_params(parameters);

        let params_query: HashMap<String, String> = parameters.into();

        query_params.extend(params_query);

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

        html += r#"</form>
        </body>
        </html>"#;

        Ok(html)
    }

    /// # Token Grant
    /// Performs a grant at the token endpoint
    ///
    /// - `http_client` - The http client to make the request
    /// - `params` - Token grant params
    #[async_recursion::async_recursion(? Send)]
    pub async fn grant_async<T>(
        &mut self,
        http_client: &T,
        params: GrantParams<'async_recursion>,
    ) -> OidcReturnType<TokenSet>
    where
        T: OidcHttpClient,
    {
        let issuer = self
            .issuer
            .as_ref()
            .ok_or(Box::new(OidcClientError::new_error(
                "Issuer is required for authenticated_post",
                None,
            )))?;

        if issuer.token_endpoint.is_none() {
            return Err(Box::new(OidcClientError::new_type_error(
                "token_endpoint must be configured on the issuer",
                None,
            )));
        }

        let req = HttpRequest::new().form(params.body.clone());

        let auth_post_params = AuthenticationPostParams {
            client_assertion_payload: params.extras.client_assertion_payload.as_ref(),
            dpop: params.extras.dpop,
            endpoint_auth_method: params.extras.endpoint_auth_method,
        };

        let response = match self
            .authenticated_post_async("token", req, auth_post_params, http_client)
            .await
            .map_err(|e| *e)
        {
            Ok(r) => r,
            Err(OidcClientError::OPError(e, Some(res))) => {
                if params.retry && e.error == "use_dpop_nonce" {
                    return self.grant_async(http_client, params).await;
                }

                return Err(Box::new(OidcClientError::new_op_error(
                    e.error,
                    e.error_description,
                    e.error_uri,
                    Some(res),
                )));
            }
            Err(e) => return Err(Box::new(e)),
        };

        let body = response.body.clone().ok_or(OidcClientError::new_error(
            "body expected in grant response",
            Some(response.clone()),
        ))?;

        let token_params = convert_json_to::<TokenSetParams>(&body).or(Err(Box::new(
            OidcClientError::new_error("could not convert body to TokenSetParams", Some(response)),
        )))?;

        Ok(TokenSet::new(token_params))
    }

    /// # OAuth Callback
    /// Performs the callback for Authorization Server's authorization response.
    ///
    /// - `http_client` - The http client to make the request
    /// - `params` - OAuth callback params
    pub async fn oauth_callback_async<T>(
        &mut self,
        http_client: &T,
        mut params: OAuthCallbackParams<'_>,
    ) -> OidcReturnType<TokenSet>
    where
        T: OidcHttpClient,
    {
        let checks = params.checks.unwrap_or_default();

        if checks.jarm.is_some_and(|x| x) && params.parameters.response.is_none() {
            return Err(Box::new(OidcClientError::new_rp_error(
                "expected a JARM response",
                None,
            )));
        } else if let Some(response) = &params.parameters.response {
            let decrypted = self.decrypt_jarm(response)?;
            let payload = self.validate_jarm_async(&decrypted, http_client).await?;
            params.parameters = CallbackParams::from_jwt_payload(&payload);
        }

        if params.parameters.state.is_some() && checks.state.is_none() {
            return Err(Box::new(OidcClientError::new_type_error(
                "checks.state argument is missing",
                None,
            )));
        }

        if params.parameters.state.is_none() && checks.state.is_some() {
            return Err(Box::new(OidcClientError::new_rp_error(
                "state missing from the response",
                None,
            )));
        }

        if params.parameters.state.as_deref() != checks.state {
            let checks_state = checks.state;
            let params_state = params.parameters.state.clone();

            return Err(Box::new(OidcClientError::new_rp_error(
                &format!(
                    "state mismatch, expected {0}, got: {1}",
                    checks_state.unwrap(),
                    params_state.unwrap()
                ),
                None,
            )));
        }

        let issuer = match self.issuer.as_ref() {
            Some(iss) => iss,
            None => {
                return Err(Box::new(OidcClientError::new_type_error(
                    "Issuer is required",
                    None,
                )))
            }
        };

        if params.parameters.iss.is_some() {
            if issuer.issuer.is_empty() {
                return Err(Box::new(OidcClientError::new_type_error(
                    "issuer must be configured on the issuer",
                    None,
                )));
            }

            let params_iss = params.parameters.iss.clone().unwrap();
            if params_iss != issuer.issuer {
                return Err(Box::new(OidcClientError::new_rp_error(
                    &format!(
                        "iss mismatch, expected {}, got: {params_iss}",
                        issuer.issuer
                    ),
                    None,
                )));
            }
        } else if issuer
            .authorization_response_iss_parameter_supported
            .is_some_and(|x| x)
            && params.parameters.id_token.is_none()
            && params.parameters.response.is_none()
        {
            return Err(Box::new(OidcClientError::new_rp_error(
                "iss missing from the response",
                None,
            )));
        }

        if params.parameters.error.is_some() {
            return Err(Box::new(OidcClientError::new_op_error(
                params.parameters.error.unwrap(),
                params.parameters.error_description,
                params.parameters.error_uri,
                None,
            )));
        }

        if params
            .parameters
            .id_token
            .as_ref()
            .is_some_and(|x| !x.is_empty())
        {
            return Err(Box::new(OidcClientError::new_rp_error(
                "id_token detected in the response, you must use client.callback_async() instead of client.oauth_callback_async()",
                None,
            )));
        }

        params.parameters.id_token = None;

        if checks.response_type.is_some() {
            for res_type in checks.response_type.as_ref().unwrap().split(' ') {
                if res_type == "none"
                    && (params.parameters.code.is_some()
                        || params.parameters.id_token.is_some()
                        || params.parameters.access_token.is_some())
                {
                    return Err(Box::new(OidcClientError::new_rp_error(
                        "unexpected params encountered for \"none\" response",
                        None,
                    )));
                }

                if res_type == "code" || res_type == "token" {
                    let mut message = "";

                    if res_type == "code" && params.parameters.code.is_none() {
                        message = "code missing from response";
                    }

                    if res_type == "token" && params.parameters.access_token.is_none() {
                        message = "access_token missing from response";
                    }

                    if res_type == "token" && params.parameters.token_type.is_none() {
                        message = "token_type missing from response";
                    }

                    if !message.is_empty() {
                        return Err(Box::new(OidcClientError::new_rp_error(message, None)));
                    }
                }
            }
        }

        if params.parameters.code.is_some() {
            let mut exchange_body = match params.extras.as_ref() {
                Some(e) => e
                    .exchange_body
                    .clone()
                    .unwrap_or(HashMap::<String, String>::new()),
                None => HashMap::<String, String>::new(),
            };

            exchange_body.insert("grant_type".to_string(), "authorization_code".to_owned());
            exchange_body.insert(
                "code".to_string(),
                params.parameters.code.as_ref().unwrap().to_owned(),
            );
            if let Some(ru) = params.redirect_uri {
                exchange_body.insert("redirect_uri".to_string(), ru.to_owned());
            };

            if let Some(cv) = checks.code_verifier {
                exchange_body.insert("code_verifier".to_string(), cv.to_owned());
            };

            let mut grant_extras = GrantExtras::default();

            match &params.extras {
                Some(e) => {
                    grant_extras
                        .client_assertion_payload
                        .clone_from(&e.client_assertion_payload);
                    grant_extras.dpop = e.dpop.as_ref();
                }
                None => {}
            };

            let mut token_set = self
                .grant_async(
                    http_client,
                    GrantParams {
                        body: exchange_body,
                        extras: grant_extras,
                        retry: true,
                    },
                )
                .await?;

            if token_set.get_id_token().is_some_and(|x| !x.is_empty()) {
                return Err(Box::new(OidcClientError::new_rp_error(
                    "id_token detected in the response, you must use client.callback_async() instead of client.oauth_callback_async()",
                    None,
                )));
            }

            token_set.set_id_token(None);

            return Ok(token_set);
        }

        let mut other_fields = match params.parameters.other {
            Some(o) => o.clone(),
            None => HashMap::new(),
        };

        if let Some(state) = params.parameters.state {
            other_fields.insert("state".to_string(), state);
        }

        if let Some(code) = params.parameters.code {
            other_fields.insert("code".to_string(), code);
        }

        let expires_at = match other_fields.get("expires_at") {
            Some(eat) => eat.parse::<i64>().ok(),
            None => None,
        };
        let scope = other_fields.get("scope").map(|s| s.to_owned());
        let token_type = other_fields.get("token_type").map(|tt| tt.to_owned());
        let session_state = other_fields.get("session_state").map(|ss| ss.to_owned());
        let refresh_token = other_fields.get("refresh_token").map(|rt| rt.to_owned());
        let expires_in = match params.parameters.expires_in {
            Some(exp_in) => exp_in.parse::<i64>().ok(),
            None => None,
        };

        let mut tokenset_others = HashMap::new();

        for (k, v) in other_fields {
            if let Ok(val) = serde_json::to_value(v) {
                tokenset_others.insert(k, val);
            }
        }

        let token_params = TokenSetParams {
            access_token: params.parameters.access_token,
            id_token: params.parameters.id_token,
            expires_in,
            expires_at,
            scope,
            token_type,
            session_state,
            refresh_token,
            other: Some(tokenset_others),
        };

        Ok(TokenSet::new(token_params))
    }

    /// # Skip Max Age Check
    /// When `skip_max_age_check` is set to true, Id Token's
    /// Max age wont be validated
    pub fn set_skip_max_age_check(&mut self, max_age_check: bool) {
        self.skip_max_age_check = max_age_check;
    }

    /// # Skip Nonce Check
    /// When `skip_nonce_check` is set to true, Id token's
    /// Nonce wont be validated
    pub fn set_skip_nonce_check(&mut self, nonce_check: bool) {
        self.skip_nonce_check = nonce_check;
    }

    /// # Set Clock Skew
    /// It is possible the RP or OP environment has a system clock skew,
    /// which can result in the error "JWT not active yet".
    pub fn set_clock_skew_duration(&mut self, duration: Duration) {
        self.clock_tolerance = duration;
    }

    /// # Callback
    /// Performs the callback for Authorization Server's authorization response.
    ///
    /// - `http_cliet` - The http client to make request
    /// - `params` - OpenId callback params
    pub async fn callback_async<T>(
        &mut self,
        http_client: &T,
        mut params: OpenIdCallbackParams<'_>,
    ) -> OidcReturnType<TokenSet>
    where
        T: OidcHttpClient,
    {
        let mut checks = params.checks.unwrap_or_default();

        let default_oauth_checks = OAuthCallbackChecks::default();

        let oauth_checks = checks
            .oauth_checks
            .as_ref()
            .unwrap_or(&default_oauth_checks);

        if oauth_checks.jarm.is_some_and(|x| x) && params.parameters.response.is_none() {
            return Err(Box::new(OidcClientError::new_rp_error(
                "expected a JARM response",
                None,
            )));
        } else if let Some(response) = &params.parameters.response {
            let decrypted = self.decrypt_jarm(response)?;
            let payload = self.validate_jarm_async(&decrypted, http_client).await?;
            params.parameters = CallbackParams::from_jwt_payload(&payload);
        }

        if self.default_max_age.is_some() && checks.max_age.is_none() {
            checks.max_age = self.default_max_age;
        }

        if params.parameters.state.is_some() && oauth_checks.state.is_none() {
            return Err(Box::new(OidcClientError::new_type_error(
                "checks.state argument is missing",
                None,
            )));
        }

        if params.parameters.state.is_none() && oauth_checks.state.is_some() {
            return Err(Box::new(OidcClientError::new_rp_error(
                "state missing from the response",
                None,
            )));
        }

        if params.parameters.state.as_deref() != oauth_checks.state {
            let checks_state = oauth_checks.state;
            let params_state = params.parameters.state.clone();

            return Err(Box::new(OidcClientError::new_rp_error(
                &format!(
                    "state mismatch, expected {0}, got: {1}",
                    checks_state.unwrap(),
                    params_state.unwrap()
                ),
                None,
            )));
        }

        let issuer = match self.issuer.as_ref() {
            Some(iss) => iss,
            None => {
                return Err(Box::new(OidcClientError::new_type_error(
                    "Issuer is required",
                    None,
                )))
            }
        };

        if params.parameters.iss.is_some() {
            if issuer.issuer.is_empty() {
                return Err(Box::new(OidcClientError::new_type_error(
                    "issuer must be configured on the issuer",
                    None,
                )));
            }

            let params_iss = params.parameters.iss.clone().unwrap();
            if params_iss != issuer.issuer {
                return Err(Box::new(OidcClientError::new_rp_error(
                    &format!(
                        "iss mismatch, expected {}, got: {params_iss}",
                        issuer.issuer
                    ),
                    None,
                )));
            }
        } else if issuer
            .authorization_response_iss_parameter_supported
            .is_some_and(|x| x)
            && params.parameters.id_token.is_none()
            && params.parameters.response.is_none()
        {
            return Err(Box::new(OidcClientError::new_rp_error(
                "iss missing from the response",
                None,
            )));
        }

        if params.parameters.error.is_some() {
            return Err(Box::new(OidcClientError::new_op_error(
                params.parameters.error.unwrap(),
                params.parameters.error_description,
                params.parameters.error_uri,
                None,
            )));
        }

        if oauth_checks.response_type.is_some() {
            for res_type in oauth_checks.response_type.as_ref().unwrap().split(' ') {
                if res_type == "none"
                    && (params.parameters.code.is_some()
                        || params.parameters.id_token.is_some()
                        || params.parameters.access_token.is_some())
                {
                    return Err(Box::new(OidcClientError::new_rp_error(
                        "unexpected params encountered for \"none\" response",
                        None,
                    )));
                } else if res_type == "code" || res_type == "token" || res_type == "id_token" {
                    let mut message = "";

                    if res_type == "code" && params.parameters.code.is_none() {
                        message = "code missing from response";
                    }

                    if res_type == "token" && params.parameters.access_token.is_none() {
                        message = "access_token missing from response";
                    }

                    if res_type == "token" && params.parameters.token_type.is_none() {
                        message = "token_type missing from response";
                    }

                    if res_type == "id_token" && params.parameters.id_token.is_none() {
                        message = "id_token missing from response";
                    }

                    if !message.is_empty() {
                        return Err(Box::new(OidcClientError::new_rp_error(message, None)));
                    }
                }
            }
        }

        if params
            .parameters
            .id_token
            .as_ref()
            .is_some_and(|x| !x.is_empty())
        {
            let mut other_fields = match &params.parameters.other {
                Some(o) => o.clone(),
                None => HashMap::new(),
            };

            if let Some(state) = &params.parameters.state {
                other_fields.insert("state".to_owned(), state.to_owned());
            }

            if let Some(code) = &params.parameters.code {
                other_fields.insert("code".to_owned(), code.to_owned());
            }

            let expires_at = match other_fields.get("expires_at") {
                Some(eat) => eat.parse::<i64>().ok(),
                None => None,
            };
            let scope = other_fields.get("scope").map(|s| s.to_owned());
            let token_type = other_fields.get("token_type").map(|tt| tt.to_owned());
            let session_state = other_fields.get("session_state").map(|ss| ss.to_owned());
            let refresh_token = other_fields.get("refresh_token").map(|rt| rt.to_owned());
            let expires_in = match &params.parameters.expires_in {
                Some(exp_in) => exp_in.parse::<i64>().ok(),
                None => None,
            };

            let mut tokenset_others = HashMap::new();

            for (k, v) in other_fields {
                if let Ok(val) = serde_json::to_value(v) {
                    tokenset_others.insert(k, val);
                }
            }

            let token_params = TokenSetParams {
                access_token: params.parameters.access_token.clone(),
                id_token: params.parameters.id_token.clone(),
                expires_in,
                expires_at,
                scope,
                token_type,
                session_state,
                refresh_token,
                other: Some(tokenset_others),
            };

            let mut token_set = TokenSet::new(token_params);

            token_set = self.decrypt_id_token(token_set)?;

            token_set = self
                .validate_id_token_async(
                    token_set,
                    checks.nonce.map(|x| x.to_owned()),
                    "authorization",
                    checks.max_age,
                    oauth_checks.state.map(|x| x.to_owned()),
                    http_client,
                )
                .await?;

            if params.parameters.code.is_none() {
                return Ok(token_set);
            }
        }

        if params.parameters.code.is_some() {
            let mut exchange_body = match params.extras.as_ref() {
                Some(e) => e
                    .exchange_body
                    .clone()
                    .unwrap_or(HashMap::<String, String>::new()),
                None => HashMap::<String, String>::new(),
            };

            exchange_body.insert("grant_type".to_string(), "authorization_code".to_owned());
            exchange_body.insert(
                "code".to_string(),
                params.parameters.code.as_ref().unwrap().to_owned(),
            );
            if let Some(ru) = params.redirect_uri {
                exchange_body.insert("redirect_uri".to_string(), ru.to_owned());
            };

            if let Some(cv) = oauth_checks.code_verifier {
                exchange_body.insert("code_verifier".to_string(), cv.to_owned());
            };

            let mut grant_extras = GrantExtras::default();

            match &params.extras {
                Some(e) => {
                    grant_extras
                        .client_assertion_payload
                        .clone_from(&e.client_assertion_payload);
                    grant_extras.dpop = e.dpop.as_ref();
                }
                None => {}
            };

            let mut token_set = self
                .grant_async(
                    http_client,
                    GrantParams {
                        body: exchange_body,
                        extras: grant_extras,
                        retry: true,
                    },
                )
                .await?;

            token_set = self.decrypt_id_token(token_set)?;
            token_set = self
                .validate_id_token_async(
                    token_set,
                    checks.nonce.map(|x| x.to_owned()),
                    "token",
                    checks.max_age,
                    oauth_checks.state.map(|x| x.to_owned()),
                    http_client,
                )
                .await?;

            if params.parameters.session_state.is_some() {
                token_set.set_session_state(params.parameters.session_state);
            }

            return Ok(token_set);
        }

        let mut other_fields = match &params.parameters.other {
            Some(o) => o.clone(),
            None => HashMap::new(),
        };

        if let Some(state) = &params.parameters.state {
            other_fields.insert("state".to_string(), state.to_owned());
        }

        if let Some(code) = params.parameters.code {
            other_fields.insert("code".to_string(), code);
        }

        let expires_at = match other_fields.get("expires_at") {
            Some(eat) => eat.parse::<i64>().ok(),
            None => None,
        };
        let scope = other_fields.get("scope").map(|s| s.to_owned());
        let token_type = other_fields.get("token_type").map(|tt| tt.to_owned());
        let session_state = other_fields.get("session_state").map(|ss| ss.to_owned());
        let refresh_token = other_fields.get("refresh_token").map(|rt| rt.to_owned());
        let expires_in = match params.parameters.expires_in {
            Some(exp_in) => exp_in.parse::<i64>().ok(),
            None => None,
        };

        let mut tokenset_others = HashMap::new();

        for (k, v) in other_fields {
            if let Ok(val) = serde_json::to_value(v) {
                tokenset_others.insert(k, val);
            }
        }

        let token_params = TokenSetParams {
            access_token: params.parameters.access_token,
            id_token: params.parameters.id_token,
            expires_in,
            expires_at,
            scope,
            token_type,
            session_state,
            refresh_token,
            other: Some(tokenset_others),
        };

        Ok(TokenSet::new(token_params))
    }

    /// # Introspect
    /// Performs an introspection request at `Issuer::introspection_endpoint`
    ///
    /// - `token` : The token to introspect
    /// - `http_client` : The http client to make the request
    /// - `token_type_hint` : Type of the token passed in `token`. Usually `access_token` or `refresh_token`
    /// - `extras`: See [IntrospectionExtras]
    pub async fn introspect_async<T>(
        &mut self,
        token: String,
        http_client: &T,
        token_type_hint: Option<String>,
        extras: Option<IntrospectionExtras>,
    ) -> OidcReturnType<HttpResponse>
    where
        T: OidcHttpClient,
    {
        let issuer = match self.issuer.as_ref() {
            Some(iss) => iss,
            None => {
                return Err(Box::new(OidcClientError::new_type_error(
                    "Issuer is required",
                    None,
                )))
            }
        };

        if issuer.introspection_endpoint.is_none() {
            return Err(Box::new(OidcClientError::new_type_error(
                "introspection_endpoint must be configured on the issuer",
                None,
            )));
        }

        let mut form = HashMap::new();

        form.insert("token".to_string(), token);

        if let Some(hint) = token_type_hint {
            form.insert("token_type_hint".to_string(), hint);
        }

        if let Some(p) = &extras {
            if let Some(body) = &p.introspect_body {
                for (k, v) in body {
                    form.insert(k.to_owned(), v.to_owned());
                }
            }
        }

        let req = HttpRequest::new().form(form);

        self.authenticated_post_async(
            "introspection",
            req,
            AuthenticationPostParams {
                client_assertion_payload: extras
                    .as_ref()
                    .and_then(|x| x.client_assertion_payload.as_ref()),
                dpop: None,
                endpoint_auth_method: None,
            },
            http_client,
        )
        .await
    }

    /// # Request Resource
    /// Performs a request to fetch using the access token at `resource_url`.
    ///
    /// - `params` : [RequestResourceParams]
    /// - `http_client` : The http client to make the request
    #[async_recursion::async_recursion(? Send)]
    pub async fn request_resource_async<T>(
        &mut self,
        mut params: RequestResourceParams<'async_recursion>,
        http_client: &T,
    ) -> OidcReturnType<HttpResponse>
    where
        T: OidcHttpClient,
    {
        if self.dpop_bound_access_tokens.is_some_and(|x| x) && params.options.dpop.is_none() {
            return Err(Box::new(OidcClientError::new_type_error(
                "DPoP key not set",
                None,
            )));
        }

        let tt = if params.options.dpop.is_some() {
            "DPoP"
        } else {
            params.token_type.unwrap_or("Bearer")
        };

        if !params
            .options
            .headers
            .iter()
            .any(|(k, _)| k.as_str().to_lowercase() == "authorization")
            && ((tt == "Bearer" && params.options.bearer) || tt == "DPoP")
        {
            params.options.headers.insert(
                "authorization".to_string(),
                vec![format!("{tt} {}", params.access_token)],
            );
        }

        let mut req = HttpRequest::new()
            .url(Url::parse(params.resource_url).map_err(|e| {
                Box::new(OidcClientError::new_error(
                    &format!("Invalid Url: {}", e),
                    None,
                ))
            })?)
            .method(params.options.method.clone())
            .headers(params.options.headers.clone())
            .mtls(
                self.tls_client_certificate_bound_access_tokens
                    .is_some_and(|x| x),
            )
            .expect_bearer(params.options.bearer)
            .expect_json_body(params.options.expect_body_to_be_json);

        if let Some(body) = &params.options.body {
            req = req.body(body.clone());
        }

        match self
            .instance_request_async(
                req,
                params.options.dpop,
                Some(params.access_token),
                http_client,
            )
            .await
            .map_err(|e| *e)
        {
            Ok(r) => Ok(r),
            Err(OidcClientError::OPError(e, Some(res))) => {
                if params.retry && e.error == "use_dpop_nonce" {
                    if let Some(header_val) = res.www_authenticate.as_ref() {
                        if header_val.starts_with("dpop ") {
                            return self.request_resource_async(params, http_client).await;
                        }
                    }
                }

                return Err(Box::new(OidcClientError::new_op_error(
                    e.error,
                    e.error_description,
                    e.error_uri,
                    Some(res),
                )));
            }
            Err(e) => Err(Box::new(e)),
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
    ) -> OidcReturnType<CallbackParams> {
        let mut query_pairs = None;
        if let Some(url) = incoming_url {
            query_pairs = Some(
                url.query_pairs()
                    .map(|(x, y)| (x.to_string(), y.to_string()))
                    .collect::<Vec<(String, String)>>(),
            );
        } else if let Some(body) = incoming_body {
            query_pairs = Some(
                form_urlencoded::parse(body.as_bytes())
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            );
        }

        if let Some(qp) = query_pairs {
            let mut params = CallbackParams::default();

            let mut other = HashMap::new();

            for (k, v) in qp {
                match k.as_str() {
                    "access_token" => params.access_token = Some(v),
                    "code" => params.code = Some(v),
                    "error" => params.error = Some(v),
                    "error_description" => params.error_description = Some(v),
                    "error_uri" => params.error_uri = Some(v),
                    "id_token" => params.id_token = Some(v),
                    "iss" => params.iss = Some(v),
                    "response" => params.response = Some(v),
                    "session_state" => params.session_state = Some(v),
                    "state" => params.state = Some(v),
                    "token_type" => params.token_type = Some(v),
                    _ => {
                        other.insert(k, v);
                    }
                };
            }

            if !other.is_empty() {
                params.other = Some(other);
            }
            return Ok(params);
        }

        Err(Box::new(OidcClientError::new_error(
            "could not parse the request",
            None,
        )))
    }

    /// # Refresh Request
    /// Performs a Token Refresh request at Issuer's `token_endpoint`
    ///
    /// - `token_set` : [TokenSet] with refresh token that will be used to perform the request
    /// - `extras` : See [RefreshTokenExtras]
    /// - `http_client`: The http client to make the request
    pub async fn refresh_async<T>(
        &mut self,
        token_set: TokenSet,
        extras: Option<RefreshTokenExtras<'_>>,
        http_client: &T,
    ) -> OidcReturnType<TokenSet>
    where
        T: OidcHttpClient,
    {
        let refresh_token = match token_set.get_refresh_token() {
            Some(rt) => rt,
            None => {
                return Err(Box::new(OidcClientError::new_type_error(
                    "refresh_token not present in TokenSet",
                    None,
                )));
            }
        };

        let mut body = HashMap::new();

        if let Some(exchange_payload) = extras.as_ref().and_then(|x| x.exchange_body.as_ref()) {
            for (k, v) in exchange_payload {
                body.insert(k.to_owned(), v.to_owned());
            }
        }

        body.insert("grant_type".to_string(), "refresh_token".to_owned());
        body.insert("refresh_token".to_string(), refresh_token.to_owned());

        let grant_extras = GrantExtras {
            client_assertion_payload: extras
                .as_ref()
                .and_then(|x| x.client_assertion_payload.to_owned()),
            dpop: extras.as_ref().and_then(|x| x.dpop),
            endpoint_auth_method: None,
        };

        let mut new_token_set = self
            .grant_async(
                http_client,
                GrantParams {
                    body,
                    extras: grant_extras,
                    retry: true,
                },
            )
            .await?;

        if new_token_set.get_id_token().is_some() {
            new_token_set = self.decrypt_id_token(new_token_set)?;
            new_token_set = self
                .validate_id_token_async(new_token_set, None, "token", None, None, http_client)
                .await?;

            if let Some(Value::String(expected_sub)) =
                token_set.claims().as_ref().and_then(|x| x.get("sub"))
            {
                if let Some(Value::String(new_sub)) =
                    new_token_set.claims().as_ref().and_then(|x| x.get("sub"))
                {
                    if expected_sub != new_sub {
                        return Err(Box::new(OidcClientError::new_rp_error(
                            &format!("sub mismatch, expected {expected_sub}, got: {new_sub}"),
                            None,
                        )));
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
    /// - `token_type_hint` : Hint to which type of token is being revoked
    /// - `extras` : See [RevokeExtras]
    /// - `http_client` : The http client to make the request
    pub async fn revoke_async<T>(
        &mut self,
        token: &str,
        token_type_hint: Option<&str>,
        extras: Option<RevokeExtras>,
        http_client: &T,
    ) -> OidcReturnType<HttpResponse>
    where
        T: OidcHttpClient,
    {
        let issuer = match self.issuer.as_ref() {
            Some(iss) => iss,
            None => {
                return Err(Box::new(OidcClientError::new_type_error(
                    "Issuer is required",
                    None,
                )))
            }
        };

        if issuer.revocation_endpoint.is_none() {
            return Err(Box::new(OidcClientError::new_type_error(
                "revocation_endpoint must be configured on the issuer",
                None,
            )));
        }

        let mut form = HashMap::new();

        form.insert("token".to_string(), token.to_owned());

        if let Some(h) = token_type_hint {
            form.insert("token_type_hint".to_string(), h.to_owned());
        }

        let mut client_assertion_payload = None;

        if let Some(p) = extras {
            if let Some(body) = p.revocation_body {
                for (k, v) in body {
                    form.insert(k, v);
                }
            }

            if let Some(cap) = p.client_assertion_payload {
                client_assertion_payload = Some(cap);
            }
        }

        let req = HttpRequest::new().form(form).expect_body(false);

        self.authenticated_post_async(
            "revocation",
            req,
            AuthenticationPostParams {
                client_assertion_payload: client_assertion_payload.as_ref(),
                dpop: None,
                endpoint_auth_method: None,
            },
            http_client,
        )
        .await
    }

    /// # Userinfo
    /// Performs userinfo request at Issuer's `userinfo` endpoint.
    ///
    /// - `token_set` : [TokenSet] with `access_token` that will be used to perform the request
    /// - `options` : See [UserinfoOptions]
    /// - `http_client` : The http client to make the request
    pub async fn userinfo_async<T>(
        &mut self,
        token_set: &TokenSet,
        options: UserinfoOptions<'_>,
        http_client: &T,
    ) -> OidcReturnType<Value>
    where
        T: OidcHttpClient,
    {
        let issuer = match self.issuer.as_ref() {
            Some(iss) => iss,
            None => {
                return Err(Box::new(OidcClientError::new_type_error(
                    "Issuer is required",
                    None,
                )))
            }
        };

        let userinfo_endpoint = match &issuer.userinfo_endpoint {
            Some(e) => e.to_string(),
            None => {
                return Err(Box::new(OidcClientError::new_type_error(
                    "userinfo_endpoint must be configured on the issuer",
                    None,
                )))
            }
        };

        let access_token = token_set
            .get_access_token()
            .ok_or(OidcClientError::new_type_error(
                "access_token is required in token_set",
                None,
            ))?;

        if options.via != "header" && options.via != "body" {
            return Err(Box::new(OidcClientError::new_type_error(
                "via can only be body or header",
                None,
            )));
        }

        if options.method != "GET" && options.method != "POST" {
            return Err(Box::new(OidcClientError::new_type_error(
                "userinfo_async() method can only be POST or a GET",
                None,
            )));
        }

        if options.via == "body" && options.method != "POST" {
            return Err(Box::new(OidcClientError::new_type_error(
                "can only send body on POST",
                None,
            )));
        }

        let jwt = self.userinfo_signed_response_alg.is_some()
            || self.userinfo_encrypted_response_alg.is_some();

        let mut headers: HashMap<String, Vec<String>> = HashMap::new();

        if jwt {
            headers.insert("accept".to_string(), vec!["application/jwt".to_string()]);
        } else {
            headers.insert("accept".to_string(), vec!["application/json".to_string()]);
        }

        let mtls = self
            .tls_client_certificate_bound_access_tokens
            .is_some_and(|x| x);

        let mut target_url = None;

        if mtls && issuer.mtls_endpoint_aliases.is_some() {
            if let Some(mtls_alias) = &issuer.mtls_endpoint_aliases {
                if mtls_alias.userinfo_endpoint.is_some() {
                    target_url.clone_from(&mtls_alias.userinfo_endpoint);
                }
            }
        }

        let mut url = Url::parse(target_url.unwrap_or(userinfo_endpoint).as_str())
            .map_err(|_| OidcClientError::new_error("Invalid Url", None))?;

        let mut form_body = HashMap::new();

        if options.via == "body" {
            // What?
            headers.remove("authorization");
            headers.insert(
                "content-type".to_string(),
                vec!["application/x-www-form-urlencoded".to_string()],
            );
            form_body.insert("access_token".to_string(), access_token.to_owned());
        }

        let mut req_res_params = RequestResourceOptions {
            bearer: options.via == "header",
            expect_body_to_be_json: !jwt,
            dpop: options.dpop,
            ..Default::default()
        };

        if let Some(params) = options.params {
            if options.method == "GET" {
                for (k, v) in params {
                    url.query_pairs_mut().append_pair(&k, &v);
                }
            } else if options.via == "body" && options.method == "POST" {
                for (k, v) in params {
                    form_body.insert(k, v);
                }
            } else {
                headers.remove("content-type");
                headers.insert(
                    "content-type".to_string(),
                    vec!["application/x-www-form-urlencoded".to_string()],
                );
                for (k, v) in params {
                    form_body.insert(k, v);
                }
            }
        }

        let mut body = None;
        if !form_body.is_empty() {
            body = Some(string_map_to_form_url_encoded(&form_body)?);
        }

        req_res_params.body = body;
        req_res_params.method = if options.method == "GET" {
            HttpMethod::GET
        } else {
            HttpMethod::POST
        };
        req_res_params.headers = headers;

        let mut resource_params = RequestResourceParams::default()
            .access_token(&access_token)
            .options(req_res_params)
            .retry(true)
            .resource_url(url.as_str());

        let token_type = token_set.get_token_type();
        if let Some(tt) = token_type.as_deref() {
            resource_params = resource_params.token_type(tt);
        }

        let res = self
            .request_resource_async(resource_params, http_client)
            .await?;

        let payload = match jwt {
            true => {
                if !res
                    .content_type
                    .as_ref()
                    .is_some_and(|ct| ct.starts_with("application/jwt;"))
                {
                    return Err(Box::new(OidcClientError::new_rp_error(
                        "expected application/jwt response from the userinfo_endpoint",
                        Some(res),
                    )));
                }

                let body = res
                    .body
                    .as_ref()
                    .ok_or(OidcClientError::new_rp_error(
                        "body was emtpy",
                        Some(res.clone()),
                    ))?
                    .to_owned();
                let userinfo = self.decrypt_jwt_userinfo(body)?;

                if self.userinfo_signed_response_alg.is_none() {
                    if let Ok(Value::Object(json_res)) = serde_json::from_str::<Value>(&userinfo) {
                        let mut payload = json!({});
                        for (k, v) in json_res {
                            payload[k] = v;
                        }
                        payload
                    } else {
                        return Err(Box::new(OidcClientError::new_rp_error(
                            "failed to parse userinfo JWE payload as JSON",
                            Some(res),
                        )));
                    }
                } else {
                    let (jwt_payload, _, _) = self
                        .validate_jwt_userinfo_async(&userinfo, http_client)
                        .await?;
                    let mut payload = json!({});
                    for (k, v) in jwt_payload.claims_set() {
                        payload[k] = v.clone();
                    }
                    payload
                }
            }
            false => {
                let body = res
                    .body
                    .as_ref()
                    .ok_or(Box::new(OidcClientError::new_rp_error(
                        "body was emtpy",
                        Some(res.clone()),
                    )))?
                    .to_owned();

                if let Ok(Value::Object(json_res)) = serde_json::from_str::<Value>(&body) {
                    let mut payload = json!({});
                    for (k, v) in json_res {
                        payload[k] = v;
                    }
                    payload
                } else {
                    return Err(Box::new(OidcClientError::new_rp_error(
                        "failed to parse userinfo JWE payload as JSON",
                        Some(res),
                    )));
                }
            }
        };

        if let Some(id_token) = token_set.get_id_token() {
            if let Some(Value::String(expected_sub)) =
                token_set.claims().as_ref().and_then(|x| x.get("sub"))
            {
                if let Some(Value::String(new_sub)) = payload.get("sub") {
                    if expected_sub != new_sub {
                        let mut extra_data: HashMap<String, Value> = HashMap::new();

                        if let Some(Ok(b)) = res.body.map(|x| serde_json::from_str::<Value>(&x)) {
                            extra_data.insert("body".to_string(), b);
                        }

                        extra_data.insert("jwt".to_string(), json!(id_token));

                        return Err(Box::new(OidcClientError::new_rp_error(
                            &format!(
                                "userinfo sub mismatch, expected {expected_sub}, got: {new_sub}"
                            ),
                            None,
                        )));
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
    pub async fn request_object_async<T>(
        &mut self,
        mut request_object: Value,
        http_client: &T,
    ) -> OidcReturnType<String>
    where
        T: OidcHttpClient,
    {
        if !request_object.is_object() {
            return Err(Box::new(OidcClientError::new_type_error(
                "request_object must be a plain object",
                None,
            )));
        }

        let e_key_management = self.request_object_encryption_alg.clone();

        let header_alg = self
            .request_object_signing_alg
            .as_ref()
            .map(|x| x.to_owned())
            .unwrap_or("none".to_string());
        let header_typ = "oauth-authz-req+jwt";

        let unix = (self.now)();

        request_object["iss"] = json!(self.client_id);

        if let Some(aud) = self.issuer.as_ref().map(|x| x.issuer.to_owned()) {
            request_object["aud"] = json!(aud);
        }

        request_object["client_id"] = json!(self.client_id);

        request_object["jti"] = json!(generate_random(None));

        request_object["iat"] = json!(unix);

        request_object["exp"] = json!(unix + 300);

        if self.is_fapi() {
            request_object["nbf"] = json!(unix);
        }

        let signed;
        let mut key = None;

        let payload = request_object.to_string();

        if header_alg == "none" {
            let encoded_header = base64_url::encode(&format!(
                "{{\"alg\":\"{header_alg}\",\"typ\":\"{header_typ}\"}}"
            ));
            let encoded_payload = base64_url::encode(&payload);
            signed = format!("{encoded_header}.{encoded_payload}.");
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
                    return Err(Box::new(OidcClientError::new_type_error(
                        &format!("no key to sign with found for alg {header_alg}"),
                        None,
                    )));
                }
            }

            let jwk = key.clone().ok_or(Box::new(OidcClientError::new_error(
                "No key found for signing request object",
                None,
            )))?;
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
                    .query_keystore_async(query_params, true, http_client)
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
            .map_err(|x| Box::new(OidcClientError::new_error(&x.to_string(), None)))
    }

    /// # Pushed Authorization Request
    ///
    /// Performs a PAR on the `pushed_authorization_request_endpoint`
    ///
    /// - `parameters` : See [AuthorizationParameters]
    /// - `extras` : See [PushedAuthorizationRequestExtras]
    /// - `http_client` : The http client to make the request
    pub async fn pushed_authorization_request_async<T>(
        &mut self,
        parameters: Option<AuthorizationParameters>,
        extras: Option<PushedAuthorizationRequestExtras<'_>>,
        http_client: &T,
    ) -> OidcReturnType<Value>
    where
        T: OidcHttpClient,
    {
        let issuer = match self.issuer.as_ref() {
            Some(iss) => iss,
            None => {
                return Err(Box::new(OidcClientError::new_type_error(
                    "Issuer is required",
                    None,
                )))
            }
        };

        if issuer.pushed_authorization_request_endpoint.is_none() {
            return Err(Box::new(OidcClientError::new_type_error(
                "pushed_authorization_request_endpoint must be configured on the issuer",
                None,
            )));
        }

        let auth_params = parameters.unwrap_or_default();

        let mut body = if auth_params.request.is_some() {
            auth_params
        } else {
            self.authorization_params(auth_params)
        };

        body.client_id = Some(self.client_id.clone());

        let form_body: HashMap<String, String> = body.into();

        let req = HttpRequest::new()
            .form(form_body)
            .expect_json_body(true)
            .expect_status_code(201);

        let client_assertion_payload = extras
            .as_ref()
            .and_then(|x| x.client_assertion_payload.as_ref());

        let dpop = extras.as_ref().and_then(|x| x.dpop);

        let params = AuthenticationPostParams {
            client_assertion_payload,
            endpoint_auth_method: Some("token"),
            dpop,
        };

        let res = self
            .authenticated_post_async("pushed_authorization_request", req, params, http_client)
            .await?;

        let body_obj = match res.body.as_ref().map(|b| convert_json_to::<Value>(b)) {
            Some(Ok(json)) => json,
            _ => {
                return Err(Box::new(OidcClientError::new_error(
                    "could not convert body to serde::json value",
                    None,
                )))
            }
        };

        if body_obj.get("expires_in").is_none() {
            return Err(Box::new(OidcClientError::new_rp_error(
                "expected expires_in in Pushed Authorization Successful Response",
                Some(res),
            )));
        }

        if !body_obj["expires_in"].is_number() {
            return Err(Box::new(OidcClientError::new_rp_error(
                "invalid expires_in value in Pushed Authorization Successful Response",
                Some(res),
            )));
        }

        if body_obj.get("request_uri").is_none() {
            return Err(Box::new(OidcClientError::new_rp_error(
                "expected request_uri in Pushed Authorization Successful Response",
                Some(res),
            )));
        }

        if !body_obj["request_uri"].is_string() {
            return Err(Box::new(OidcClientError::new_rp_error(
                "invalid request_uri value in Pushed Authorization Successful Response",
                Some(res),
            )));
        }

        Ok(body_obj)
    }

    /// # Device Authorization Grant
    /// Performs a Device Authorization Grant at `device_authorization_request_endpoint`.
    ///
    /// - `params` - See [DeviceAuthorizationParams]
    /// - `extras` - See [DeviceAuthorizationExtras]
    /// - `http_client` - The http client to make the request
    pub async fn device_authorization_async<T>(
        &mut self,
        params: DeviceAuthorizationParams,
        extras: Option<DeviceAuthorizationExtras>,
        http_client: &T,
    ) -> OidcReturnType<DeviceFlowHandle>
    where
        T: OidcHttpClient,
    {
        let issuer = match self.issuer.as_ref() {
            Some(iss) => iss,
            None => {
                return Err(Box::new(OidcClientError::new_type_error(
                    "Issuer is required",
                    None,
                )))
            }
        };

        if issuer.token_endpoint.is_none() {
            return Err(Box::new(OidcClientError::new_type_error(
                "token_endpoint must be configured on the issuer",
                None,
            )));
        }

        if issuer.device_authorization_endpoint.is_none() {
            return Err(Box::new(OidcClientError::new_type_error(
                "device_authorization_endpoint must be configured on the issuer",
                None,
            )));
        }

        let mut auth_params = AuthorizationParameters {
            client_id: Some(self.client_id.clone()),
            ..Default::default()
        };

        if let Some(client_id) = params.client_id {
            auth_params.client_id = Some(client_id);
        }

        if let Some(scope) = params.scope {
            auth_params.scope = Some(scope);
        }

        for (k, v) in params.other {
            if k == "redirect_uri" || k == "response_type" || k == "client_id" || k == "scope" {
                continue;
            } else if k == "audience" {
                if let Some(audience) = v.as_array() {
                    if !audience.is_empty() {
                        let mut aud_arr = vec![];
                        for aud in audience {
                            if let Some(a) = aud.as_str() {
                                aud_arr.push(a.to_string());
                            }
                        }

                        auth_params.audience = Some(aud_arr);
                    }
                }

                if let Some(audience) = v.as_str() {
                    let aud_arr = vec![audience.to_string()];
                    auth_params.audience = Some(aud_arr);
                }
            } else if k == "claims" {
                if let Ok(claims) = serde_json::from_value::<ClaimParam>(v.clone()) {
                    auth_params.claims = Some(claims);
                }
            } else if k == "acr_values" {
                if let Some(acr_values) = v.as_array() {
                    if !acr_values.is_empty() {
                        let mut acr_arr = vec![];
                        for acr in acr_values {
                            if let Some(a) = acr.as_str() {
                                acr_arr.push(a.to_string());
                            }
                        }

                        auth_params.acr_values = Some(acr_arr);
                    }
                }
                if let Some(acr_values) = v.as_str() {
                    let acr_arr = vec![acr_values.to_string()];
                    auth_params.acr_values = Some(acr_arr);
                }
            } else if k == "claims_locales" {
                if let Some(claims_locales) = v.as_array() {
                    if !claims_locales.is_empty() {
                        let mut locale_arr = vec![];
                        for locale in claims_locales {
                            if let Some(a) = locale.as_str() {
                                locale_arr.push(a.to_string());
                            }
                        }

                        auth_params.claims_locales = Some(locale_arr);
                    }
                }

                if let Some(claims_locales) = v.as_str() {
                    let locale_arr = vec![claims_locales.to_string()];
                    auth_params.claims_locales = Some(locale_arr);
                }
            } else if k == "code_challenge_method" {
                if let Some(code_challenge_method) = v.as_str() {
                    auth_params.code_challenge_method = Some(code_challenge_method.to_string());
                }
            } else if k == "code_challenge" {
                if let Some(code_challenge) = v.as_str() {
                    auth_params.code_challenge = Some(code_challenge.to_string());
                }
            } else if k == "display" {
                if let Some(display) = v.as_str() {
                    auth_params.display = Some(display.to_string());
                }
            } else if k == "id_token_hint" {
                if let Some(id_token_hint) = v.as_str() {
                    auth_params.id_token_hint = Some(id_token_hint.to_string());
                }
            } else if k == "login_hint" {
                if let Some(login_hint) = v.as_str() {
                    auth_params.login_hint = Some(login_hint.to_string());
                }
            } else if k == "max_age" {
                if let Some(max_age) = v.as_str() {
                    auth_params.max_age = Some(max_age.to_string());
                }
            } else if k == "nonce" {
                if let Some(nonce) = v.as_str() {
                    auth_params.nonce = Some(nonce.to_string());
                }
            } else if k == "prompt" {
                if let Some(prompt) = v.as_array() {
                    if !prompt.is_empty() {
                        let mut prompt_arr = vec![];
                        for prompt in prompt {
                            if let Some(a) = prompt.as_str() {
                                prompt_arr.push(a.to_string());
                            }
                        }

                        auth_params.prompt = Some(prompt_arr);
                    }
                }

                if let Some(prompt) = v.as_str() {
                    let prompt_arr = vec![prompt.to_string()];
                    auth_params.prompt = Some(prompt_arr);
                }
            } else if k == "registration" {
                if let Some(registration) = v.as_str() {
                    auth_params.registration = Some(registration.to_string());
                }
            } else if k == "request_uri" {
                if let Some(request_uri) = v.as_str() {
                    auth_params.request_uri = Some(request_uri.to_string());
                }
            } else if k == "request" {
                if let Some(request) = v.as_str() {
                    auth_params.request = Some(request.to_string());
                }
            } else if k == "resource" {
                if let Some(resource) = v.as_array() {
                    if !resource.is_empty() {
                        let mut resource_arr = vec![];
                        for r in resource {
                            if let Some(a) = r.as_str() {
                                resource_arr.push(a.to_string());
                            }
                        }

                        auth_params.resource = Some(resource_arr);
                    }
                }

                if let Some(resource) = v.as_str() {
                    let resource_arr = vec![resource.to_string()];
                    auth_params.resource = Some(resource_arr);
                }
            } else if k == "response_mode" {
                if let Some(response_mode) = v.as_str() {
                    auth_params.response_mode = Some(response_mode.to_string());
                }
            } else if k == "state" {
                if let Some(state) = v.as_str() {
                    auth_params.state = Some(state.to_string());
                }
            } else if k == "ui_locales" {
                if let Some(ui_locales) = v.as_array() {
                    if !ui_locales.is_empty() {
                        let mut ui_locales_arr = vec![];
                        for ui_locale in ui_locales {
                            if let Some(a) = ui_locale.as_str() {
                                ui_locales_arr.push(a.to_string());
                            }
                        }

                        auth_params.ui_locales = Some(ui_locales_arr);
                    }
                }

                if let Some(ui_locales) = v.as_str() {
                    let locale_arr = vec![ui_locales.to_string()];
                    auth_params.ui_locales = Some(locale_arr);
                }
            } else if let Some(other) = &mut auth_params.other {
                other.insert(k, get_serde_value_as_string(&v)?);
            } else {
                let mut other = HashMap::new();
                other.insert(k, get_serde_value_as_string(&v)?);
                auth_params.other = Some(other);
            }
        }

        let body = self.authorization_params(auth_params);

        let form_body: HashMap<String, String> = body.into();

        let req = HttpRequest::new()
            .form(form_body)
            .expect_body(true)
            .expect_json_body(true);

        let auth_post_params = AuthenticationPostParams {
            client_assertion_payload: extras
                .as_ref()
                .and_then(|x| x.client_assertion_payload.as_ref()),
            endpoint_auth_method: Some("token"),
            dpop: None,
        };

        let res = self
            .authenticated_post_async("device_authorization", req, auth_post_params, http_client)
            .await?;

        let device_res = res
            .body
            .as_ref()
            .and_then(|x| convert_json_to::<DeviceAuthorizationResponse>(x).ok())
            .ok_or(OidcClientError::new_type_error(
                &format!(
                    "could not convert response body to device authorization response: {}",
                    res.body.clone().unwrap_or_default()
                ),
                Some(res),
            ))?;

        Ok(DeviceFlowHandle::new(
            self.clone(),
            device_res,
            extras,
            params.max_age,
        ))
    }
}
