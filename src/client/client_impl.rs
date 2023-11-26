use josekit::jwe::JweHeader;
use josekit::jws::JwsHeader;
use josekit::{jwe, jws};
use std::collections::HashMap;
use std::ops::Deref;
use std::time::Duration;

use reqwest::header::HeaderValue;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use url::{form_urlencoded, Url};

use crate::helpers::{generate_random, get_serde_value_as_string, string_map_to_form_url_encoded};
use crate::jwks::jwks::CustomJwk;
use crate::types::query_keystore::QueryKeyStore;
use crate::types::{
    CallbackExtras, CallbackParams, ClaimParam, DeviceAuthorizationExtras,
    DeviceAuthorizationParams, DeviceAuthorizationResponse, Fapi, GrantExtras, IntrospectionExtras,
    OAuthCallbackChecks, OpenIDCallbackChecks, PushedAuthorizationRequestExtras,
    RefreshTokenExtras, Request, RequestResourceOptions, Response, RevokeExtras, UserinfoOptions,
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
        mut parameters: AuthorizationParameters,
    ) -> Result<Url, OidcClientError> {
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

        for (query, value) in &query_params {
            if query == "scope" {
                new_query_params.append_pair(query, urlencoding::encode(value).deref());
            }
            new_query_params.append_pair(query, value);
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
        mut parameters: EndSessionParameters,
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

        if parameters.client_id.is_none() {
            parameters.client_id = Some(self.client_id.clone());
        }

        let mut post_logout: Option<String> = None;

        if let Some(plrus) = &self.post_logout_redirect_uris {
            if plrus.len() == 1 {
                if let Some(first) = plrus.get(0) {
                    post_logout = Some(first.clone());
                }
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
        mut parameters: AuthorizationParameters,
    ) -> Result<String, OidcClientError> {
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
    /// Performs a grant at the `token_endpoint`
    ///
    /// - `body` - HashMap<String, Value> : Request body
    /// - `params` - [GrantExtras] : Parameters for customizing auth request
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
    ///    let token_set = client.grant(body, GrantExtras::default()).await.unwrap();
    /// ```
    #[async_recursion::async_recursion(? Send)]
    pub async fn grant_async(
        &mut self,
        body: HashMap<String, String>,
        extras: GrantExtras<'async_recursion>,
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
            ..Default::default()
        };

        let auth_post_params = AuthenticationPostParams {
            client_assertion_payload: extras.client_assertion_payload.as_ref(),
            dpop: extras.dpop,
            endpoint_auth_method: extras.endpoint_auth_method,
        };

        let response = match self
            .authenticated_post_async("token", req, auth_post_params)
            .await
        {
            Ok(r) => r,
            Err(OidcClientError::OPError(e, Some(res))) => {
                if retry && e.error == "use_dpop_nonce" {
                    return self.grant_async(body, extras, false).await;
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
            Err(e) => return Err(e),
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
        redirect_uri: Option<&str>,
        mut parameters: CallbackParams,
        checks: Option<OAuthCallbackChecks<'_>>,
        extras: Option<CallbackExtras>,
    ) -> Result<TokenSet, OidcClientError> {
        let checks = checks.unwrap_or_default();

        if checks.jarm.is_some_and(|x| x) && parameters.response.is_none() {
            let mut extra_data: HashMap<String, Value> = HashMap::new();

            if let Ok(p) = serde_json::to_value(parameters) {
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
        } else if let Some(response) = &parameters.response {
            let decrypted = self.decrypt_jarm(response)?;
            let payload = self.validate_jarm_async(&decrypted).await?;
            parameters = CallbackParams::from_jwt_payload(&payload);
        }

        if parameters.state.is_some() && checks.state.is_none() {
            return Err(OidcClientError::new_type_error(
                "checks.state argument is missing",
                None,
            ));
        }

        if parameters.state.is_none() && checks.state.is_some() {
            let mut extra_data: HashMap<String, Value> = HashMap::new();

            if let Ok(p) = serde_json::to_value(parameters) {
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

        if parameters.state.as_deref() != checks.state {
            let checks_state = checks.state;
            let params_state = parameters.state.clone();

            let mut extra_data: HashMap<String, Value> = HashMap::new();

            if let Ok(p) = serde_json::to_value(parameters) {
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

        if parameters.iss.is_some() {
            if issuer.issuer.is_empty() {
                return Err(OidcClientError::new_type_error(
                    "issuer must be configured on the issuer",
                    None,
                ));
            }

            let params_iss = parameters.iss.clone().unwrap();
            if params_iss != issuer.issuer {
                let mut extra_data: HashMap<String, Value> = HashMap::new();

                if let Ok(p) = serde_json::to_value(parameters) {
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
            && parameters.id_token.is_none()
            && parameters.response.is_none()
        {
            let mut extra_data: HashMap<String, Value> = HashMap::new();

            if let Ok(p) = serde_json::to_value(parameters) {
                extra_data.insert("params".to_string(), p);
            };

            return Err(OidcClientError::new_rp_error(
                "iss missing from the response",
                None,
                Some(extra_data),
            ));
        }

        if parameters.error.is_some() {
            return Err(OidcClientError::new_op_error(
                parameters.error.unwrap(),
                parameters.error_description,
                parameters.error_uri,
                None,
                None,
                None,
            ));
        }

        if parameters.id_token.as_ref().is_some_and(|x| !x.is_empty()) {
            let mut extra_data: HashMap<String, Value> = HashMap::new();

            if let Ok(p) = serde_json::to_value(parameters) {
                extra_data.insert("params".to_string(), p);
            };

            return Err(OidcClientError::new_rp_error(
                "id_token detected in the response, you must use client.callback_async() instead of client.oauth_callback_async()",
                None,
                Some(extra_data),
            ));
        }

        parameters.id_token = None;

        if checks.response_type.is_some() {
            for res_type in checks.response_type.as_ref().unwrap().split(' ') {
                if res_type == "none"
                    && (parameters.code.is_some()
                        || parameters.id_token.is_some()
                        || parameters.access_token.is_some())
                {
                    let mut extra_data: HashMap<String, Value> = HashMap::new();

                    if let Ok(p) = serde_json::to_value(parameters) {
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

                    if res_type == "code" && parameters.code.is_none() {
                        message = "code missing from response";
                    }

                    if res_type == "token" && parameters.access_token.is_none() {
                        message = "access_token missing from response";
                    }

                    if res_type == "token" && parameters.token_type.is_none() {
                        message = "token_type missing from response";
                    }

                    if !message.is_empty() {
                        let mut extra_data: HashMap<String, Value> = HashMap::new();

                        if let Ok(p) = serde_json::to_value(parameters) {
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

        if parameters.code.is_some() {
            let mut exchange_body = match extras.as_ref() {
                Some(e) => e
                    .exchange_body
                    .clone()
                    .unwrap_or(HashMap::<String, String>::new()),
                None => HashMap::<String, String>::new(),
            };

            exchange_body.insert("grant_type".to_string(), "authorization_code".to_owned());
            exchange_body.insert(
                "code".to_string(),
                parameters.code.as_ref().unwrap().to_owned(),
            );
            if let Some(ru) = redirect_uri {
                exchange_body.insert("redirect_uri".to_string(), ru.to_owned());
            };

            if let Some(cv) = checks.code_verifier {
                exchange_body.insert("code_verifier".to_string(), cv.to_owned());
            };

            let mut grant_extras = GrantExtras::default();

            match &extras {
                Some(e) => {
                    grant_extras.client_assertion_payload = e.client_assertion_payload.clone();
                    grant_extras.dpop = e.dpop.as_ref();
                }
                None => {}
            };

            let mut token_set = self.grant_async(exchange_body, grant_extras, true).await?;

            if token_set.get_id_token().is_some_and(|x| !x.is_empty()) {
                let mut extra_data: HashMap<String, Value> = HashMap::new();

                if let Ok(p) = serde_json::to_value(parameters) {
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

        let mut other_fields = match parameters.other {
            Some(o) => o.clone(),
            None => HashMap::new(),
        };

        if let Some(state) = parameters.state {
            other_fields.insert("state".to_string(), state);
        }

        if let Some(code) = parameters.code {
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
        let expires_in = match parameters.expires_in {
            Some(exp_in) => exp_in.parse::<i64>().ok(),
            None => None,
        };

        let token_params = TokenSetParams {
            access_token: parameters.access_token,
            id_token: parameters.id_token,
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
        redirect_uri: Option<&str>,
        mut parameters: CallbackParams,
        checks: Option<OpenIDCallbackChecks<'_>>,
        extras: Option<CallbackExtras>,
    ) -> Result<TokenSet, OidcClientError> {
        let mut checks = checks.unwrap_or_default();

        let default_oauth_checks = OAuthCallbackChecks::default();

        let oauth_checks = checks
            .oauth_checks
            .as_ref()
            .unwrap_or(&default_oauth_checks);

        if oauth_checks.jarm.is_some_and(|x| x) && parameters.response.is_none() {
            let mut extra_data: HashMap<String, Value> = HashMap::new();

            if let Ok(p) = serde_json::to_value(parameters) {
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
        } else if let Some(response) = &parameters.response {
            let decrypted = self.decrypt_jarm(response)?;
            let payload = self.validate_jarm_async(&decrypted).await?;
            parameters = CallbackParams::from_jwt_payload(&payload);
        }

        if self.default_max_age.is_some() && checks.max_age.is_none() {
            checks.max_age = self.default_max_age;
        }

        if parameters.state.is_some() && oauth_checks.state.is_none() {
            return Err(OidcClientError::new_type_error(
                "checks.state argument is missing",
                None,
            ));
        }

        if parameters.state.is_none() && oauth_checks.state.is_some() {
            let mut extra_data: HashMap<String, Value> = HashMap::new();

            if let Ok(p) = serde_json::to_value(parameters) {
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

        if parameters.state.as_deref() != oauth_checks.state {
            let checks_state = oauth_checks.state;
            let params_state = parameters.state.clone();

            let mut extra_data: HashMap<String, Value> = HashMap::new();

            if let Ok(p) = serde_json::to_value(parameters) {
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

        if parameters.iss.is_some() {
            if issuer.issuer.is_empty() {
                return Err(OidcClientError::new_type_error(
                    "issuer must be configured on the issuer",
                    None,
                ));
            }

            let params_iss = parameters.iss.clone().unwrap();
            if params_iss != issuer.issuer {
                let mut extra_data: HashMap<String, Value> = HashMap::new();

                if let Ok(p) = serde_json::to_value(parameters) {
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
            && parameters.id_token.is_none()
            && parameters.response.is_none()
        {
            let mut extra_data: HashMap<String, Value> = HashMap::new();

            if let Ok(p) = serde_json::to_value(parameters) {
                extra_data.insert("params".to_string(), p);
            };

            return Err(OidcClientError::new_rp_error(
                "iss missing from the response",
                None,
                Some(extra_data),
            ));
        }

        if parameters.error.is_some() {
            return Err(OidcClientError::new_op_error(
                parameters.error.unwrap(),
                parameters.error_description,
                parameters.error_uri,
                None,
                None,
                None,
            ));
        }

        if oauth_checks.response_type.is_some() {
            for res_type in oauth_checks.response_type.as_ref().unwrap().split(' ') {
                if res_type == "none"
                    && (parameters.code.is_some()
                        || parameters.id_token.is_some()
                        || parameters.access_token.is_some())
                {
                    let mut extra_data: HashMap<String, Value> = HashMap::new();

                    if let Ok(p) = serde_json::to_value(parameters) {
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

                    if res_type == "code" && parameters.code.is_none() {
                        message = "code missing from response";
                    }

                    if res_type == "token" && parameters.access_token.is_none() {
                        message = "access_token missing from response";
                    }

                    if res_type == "token" && parameters.token_type.is_none() {
                        message = "token_type missing from response";
                    }

                    if res_type == "id_token" && parameters.id_token.is_none() {
                        message = "id_token missing from response";
                    }

                    if !message.is_empty() {
                        let mut extra_data: HashMap<String, Value> = HashMap::new();

                        if let Ok(p) = serde_json::to_value(parameters) {
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

        if parameters.id_token.as_ref().is_some_and(|x| !x.is_empty()) {
            let mut other_fields = match &parameters.other {
                Some(o) => o.clone(),
                None => HashMap::new(),
            };

            if let Some(state) = &parameters.state {
                other_fields.insert("state".to_owned(), state.to_owned());
            }

            if let Some(code) = &parameters.code {
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
            let expires_in = match &parameters.expires_in {
                Some(exp_in) => exp_in.parse::<i64>().ok(),
                None => None,
            };

            let token_params = TokenSetParams {
                access_token: parameters.access_token.clone(),
                id_token: parameters.id_token.clone(),
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
                    checks.nonce.map(|x| x.to_owned()),
                    "authorization",
                    checks.max_age,
                    oauth_checks.state.map(|x| x.to_owned()),
                )
                .await?;

            if parameters.code.is_none() {
                return Ok(token_set);
            }
        }

        if parameters.code.is_some() {
            let mut exchange_body = match extras.as_ref() {
                Some(e) => e
                    .exchange_body
                    .clone()
                    .unwrap_or(HashMap::<String, String>::new()),
                None => HashMap::<String, String>::new(),
            };

            exchange_body.insert("grant_type".to_string(), "authorization_code".to_owned());
            exchange_body.insert(
                "code".to_string(),
                parameters.code.as_ref().unwrap().to_owned(),
            );
            if let Some(ru) = redirect_uri {
                exchange_body.insert("redirect_uri".to_string(), ru.to_owned());
            };

            if let Some(cv) = oauth_checks.code_verifier {
                exchange_body.insert("code_verifier".to_string(), cv.to_owned());
            };

            let mut grant_extras = GrantExtras::default();

            match &extras {
                Some(e) => {
                    grant_extras.client_assertion_payload = e.client_assertion_payload.clone();
                    grant_extras.dpop = e.dpop.as_ref();
                }
                None => {}
            };

            let mut token_set = self.grant_async(exchange_body, grant_extras, true).await?;

            token_set = self.decrypt_id_token(token_set)?;
            token_set = self
                .validate_id_token_async(
                    token_set,
                    checks.nonce.map(|x| x.to_owned()),
                    "token",
                    checks.max_age,
                    oauth_checks.state.map(|x| x.to_owned()),
                )
                .await?;

            if parameters.session_state.is_some() {
                token_set.set_session_state(parameters.session_state);
            }

            return Ok(token_set);
        }

        let mut other_fields = match &parameters.other {
            Some(o) => o.clone(),
            None => HashMap::new(),
        };

        if let Some(state) = &parameters.state {
            other_fields.insert("state".to_string(), state.to_owned());
        }

        if let Some(code) = parameters.code {
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
        let expires_in = match parameters.expires_in {
            Some(exp_in) => exp_in.parse::<i64>().ok(),
            None => None,
        };

        let token_params = TokenSetParams {
            access_token: parameters.access_token,
            id_token: parameters.id_token,
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
    /// - `extras`: See [IntrospectionExtras]
    pub async fn introspect_async(
        &mut self,
        token: String,
        token_type_hint: Option<String>,
        extras: Option<IntrospectionExtras>,
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

        let req = Request {
            form: Some(form),
            ..Default::default()
        };

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
        )
        .await
    }

    /// # Request Resource
    /// Performs a request to fetch using the access token at `resource_url`.
    ///
    /// - `resource_url` : Url of the resource server
    /// - `access_token` : Token to authenticate the resource fetch request
    /// - `token_type` : Type of the `token`. Eg: `Bearer`, `DPoP`
    /// - `retry` : Whether to retry if the request failed or not
    /// - `options` : See [RequestResourceOptions]
    #[async_recursion::async_recursion(? Send)]
    pub async fn request_resource_async(
        &mut self,
        resource_url: &str,
        access_token: &str,
        token_type: Option<&'async_recursion str>,
        retry: bool,
        mut options: RequestResourceOptions<'async_recursion>,
    ) -> Result<Response, OidcClientError> {
        if self.dpop_bound_access_tokens.is_some_and(|x| x) && options.dpop.is_none() {
            return Err(OidcClientError::new_type_error("DPoP key not set", None));
        }

        let tt = if options.dpop.is_some() {
            "DPoP"
        } else {
            token_type.unwrap_or("Bearer")
        };

        if !options
            .headers
            .iter()
            .any(|(k, _)| k.as_str().to_lowercase() == "authorization")
        {
            if let Ok(header_val) = HeaderValue::from_str(&format!("{tt} {access_token}")) {
                options.headers.insert("Authorization", header_val);
            }
        }

        let req = Request {
            method: options.method.clone(),
            body: options.body.clone(),
            url: resource_url.to_string(),
            mtls: self
                .tls_client_certificate_bound_access_tokens
                .is_some_and(|x| x),
            headers: options.headers.clone(),
            bearer: options.bearer,
            expect_body_to_be_json: options.expect_body_to_be_json,
            ..Default::default()
        };

        match self
            .instance_request_async(req, options.dpop, Some(access_token))
            .await
        {
            Ok(r) => Ok(r),
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
                                        access_token,
                                        Some(tt),
                                        false,
                                        options.clone(),
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

        Err(OidcClientError::new_error(
            "could not parse the request",
            None,
        ))
    }

    /// # Refresh Request
    /// Performs a Token Refresh request at Issuer's `token_endpoint`
    ///
    /// - `token_set` : [TokenSet] with refresh token that will be used to perform the request
    /// - `params` : See [RefreshTokenExtras]
    pub async fn refresh_async(
        &mut self,
        token_set: TokenSet,
        extras: Option<RefreshTokenExtras<'_>>,
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

        let mut new_token_set = self.grant_async(body, grant_extras, true).await?;

        if let Some(id_token) = new_token_set.get_id_token() {
            new_token_set = self.decrypt_id_token(new_token_set)?;
            new_token_set = self
                .validate_id_token_async(new_token_set, None, "token", None, None)
                .await?;

            if let Some(Value::String(expected_sub)) =
                token_set.claims().as_ref().and_then(|x| x.get("sub"))
            {
                if let Some(Value::String(new_sub)) =
                    new_token_set.claims().as_ref().and_then(|x| x.get("sub"))
                {
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
    /// - `token_type_hint` : Hint to which type of token is being revoked
    /// - `extras` : See [RevokeExtras]
    pub async fn revoke_async(
        &mut self,
        token: &str,
        token_type_hint: Option<&str>,
        extras: Option<RevokeExtras>,
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

        let req = Request {
            form: Some(form),
            expect_body: false,
            ..Default::default()
        };

        self.authenticated_post_async(
            "revocation",
            req,
            AuthenticationPostParams {
                client_assertion_payload: client_assertion_payload.as_ref(),
                dpop: None,
                endpoint_auth_method: None,
            },
        )
        .await
    }

    /// # Userinfo
    /// Performs userinfo request at Issuer's `userinfo` endpoint.
    ///
    /// - `token_set` : [TokenSet] with `access_token` that will be used to perform the request
    /// - `options` : See [UserinfoOptions]
    pub async fn userinfo_async(
        &mut self,
        token_set: &TokenSet,
        options: UserinfoOptions<'_>,
    ) -> Result<Value, OidcClientError> {
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
            form_body.insert("access_token".to_string(), access_token.to_owned());
        }

        let mut req_res_params = RequestResourceOptions {
            bearer: true,
            expect_body_to_be_json: !jwt,
            dpop: options.dpop,
            ..Default::default()
        };

        if let Some(params) = options.params {
            if options.method == Method::GET {
                for (k, v) in params {
                    url.query_pairs_mut().append_pair(&k, &v);
                }
            } else if options.via == "body" && options.method == Method::POST {
                for (k, v) in params {
                    form_body.insert(k, v);
                }
            } else {
                req.headers.remove("Content-Type");
                req.headers.insert(
                    "Content-Type",
                    HeaderValue::from_static("application/x-www-form-urlencoded"),
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
        req_res_params.method = options.method;
        req_res_params.headers = req.headers;

        let res = self
            .request_resource_async(
                url.as_str(),
                &access_token,
                token_set.get_token_type().as_deref(),
                true,
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
                        let mut payload = json!({});
                        for (k, v) in json_res {
                            payload[k] = v;
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
                    let (jwt_payload, _, _) = self.validate_jwt_userinfo_async(&userinfo).await?;
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
                    .ok_or(OidcClientError::new_rp_error(
                        "body was emtpy",
                        Some(res.clone()),
                        None,
                    ))?
                    .to_owned();

                if let Ok(Value::Object(json_res)) = serde_json::from_str::<Value>(&body) {
                    let mut payload = json!({});
                    for (k, v) in json_res {
                        payload[k] = v;
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
    /// - `parameters` : See [AuthorizationParameters]
    /// - `extras` : See [PushedAuthorizationRequestExtras]
    pub async fn pushed_authorization_request_async(
        &mut self,
        parameters: Option<AuthorizationParameters>,
        extras: Option<PushedAuthorizationRequestExtras<'_>>,
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

        let auth_params = parameters.unwrap_or_default();

        let mut body = if auth_params.request.is_some() {
            auth_params
        } else {
            self.authorization_params(auth_params)
        };

        body.client_id = Some(self.client_id.clone());

        let form_body: HashMap<String, String> = body.into();

        let req = Request {
            form: Some(form_body),
            expect_body_to_be_json: true,
            expected: StatusCode::CREATED,
            ..Default::default()
        };

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

    /// # Device Authorization Grant
    /// Performs a Device Authorization Grant at `device_authorization_request_endpoint`.
    ///
    /// `params` : See [DeviceAuthorizationParams]
    /// `extras` : See [DeviceAuthorizationExtras]
    pub async fn device_authorization_async(
        &mut self,
        params: DeviceAuthorizationParams,
        extras: Option<DeviceAuthorizationExtras>,
    ) -> Result<DeviceFlowHandle, OidcClientError> {
        let issuer = match self.issuer.as_ref() {
            Some(iss) => iss,
            None => return Err(OidcClientError::new_type_error("Issuer is required", None)),
        };

        if issuer.token_endpoint.is_none() {
            return Err(OidcClientError::new_type_error(
                "token_endpoint must be configured on the issuer",
                None,
            ));
        }

        if issuer.device_authorization_endpoint.is_none() {
            return Err(OidcClientError::new_type_error(
                "device_authorization_endpoint must be configured on the issuer",
                None,
            ));
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
            } else if k == "client_id" {
                if let Some(client_id) = v.as_str() {
                    auth_params.client_id = Some(client_id.to_string());
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

        let req = Request {
            form: Some(form_body),
            expect_body: true,
            expect_body_to_be_json: true,
            ..Default::default()
        };

        let auth_post_params = AuthenticationPostParams {
            client_assertion_payload: extras
                .as_ref()
                .and_then(|x| x.client_assertion_payload.as_ref()),
            endpoint_auth_method: Some("token"),
            dpop: None,
        };

        let res = self
            .authenticated_post_async("device_authorization", req, auth_post_params)
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
