use std::collections::HashMap;

use serde_json::Value;
use url::{form_urlencoded, Url};

use crate::types::Request;
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
}

fn insert_query(qp: &mut HashMap<String, String>, key: &str, value: Option<String>) {
    if let Some(v) = value {
        qp.insert(key.to_string(), v);
    }
}
