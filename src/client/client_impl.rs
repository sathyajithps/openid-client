use std::collections::HashMap;

use url::{form_urlencoded, Url};

use crate::types::{AuthorizationParameters, EndSessionParameters, OidcClientError, ResourceParam};

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
}

fn insert_query(qp: &mut HashMap<String, String>, key: &str, value: Option<String>) {
    if let Some(v) = value {
        qp.insert(key.to_string(), v);
    }
}
