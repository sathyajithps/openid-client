use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    helpers::{generate_pkce, generate_random},
    types::Pkce,
};

/// # AuthorizationParameters
/// Represents the parameters used to construct an OIDC or OAuth 2.0 authorization request.
#[derive(Default)]
pub struct AuthorizationParameters {
    /// The unique identifier for the client application issued by the authorization server.
    pub client_id: Option<String>,
    /// Specifies the desired authorization flow, such as "code" for the authorization code flow.
    pub response_type: Option<String>,
    /// The URI where the authorization server redirects the user after the request is processed.
    pub redirect_uri: Option<String>,
    /// The challenge derived from the PKCE code verifier used to secure the code exchange.
    pub code_challenge: Option<String>,
    /// The hashing method used to generate the code challenge, typically "S256".
    pub code_challenge_method: Option<String>,
    /// Defines how the authorization response parameters are returned, such as "query" or "fragment".
    pub response_mode: Option<String>,
    /// A hint to the authorization server regarding the user's identity or login name.
    pub login_hint: Option<String>,
    /// A random string used to link a client session with an ID Token to prevent replay attacks.
    pub nonce: Option<String>,
    /// An opaque value used to maintain state between the request and callback for CSRF protection.
    pub state: Option<String>,
    /// Specifies the maximum allowable time in seconds since the user's last authentication.
    pub max_age: Option<String>,
    /// Provides a hint about how the authorization server should display the login and consent UI.
    pub display: Option<String>,
    /// An ID Token previously issued by the server, used to identify the user for whom the request is made.
    pub id_token_hint: Option<String>,
    /// Contains information for dynamic client registration during the authorization request.
    pub registration: Option<String>,
    /// A URL that points to a JWT containing the authorization request parameters.
    pub request_uri: Option<String>,
    /// A signed or encrypted JWT that bundles the authorization request parameters.
    pub request: Option<String>,
    /// A list of requested permissions or access levels for the tokens.
    pub scope: Option<Vec<String>>,
    /// Specifies whether the authorization server should prompt the user for re-authentication or consent.
    pub prompt: Option<Vec<String>>,
    /// The intended recipients for the issued tokens.
    pub audience: Option<Vec<String>>,
    /// Requested Authentication Context Class Reference values for the session.
    pub acr_values: Option<Vec<String>>,
    /// Preferred languages and scripts for the claims returned in the ID Token or UserInfo.
    pub claims_locales: Option<Vec<String>>,
    /// The target resource server or audience for which the access token is intended.
    pub resource: Option<Vec<String>>,
    /// Preferred languages for the authorization server's user interface.
    pub ui_locales: Option<Vec<String>>,
    /// Specific claims requested for the ID Token or UserInfo response.
    pub claims: Option<ClaimParam>,
    /// A collection of non-standard or custom parameters to be included in the request.
    pub additional_parameters: Option<HashMap<String, String>>,
}

// Builder methods
impl AuthorizationParameters {
    /// Sets the response_type to `code`
    pub fn authorization_code_flow(mut self) -> Self {
        self.response_type = Some("code".to_owned());
        self
    }

    /// Sets the response_type to `none`
    pub fn none_flow(mut self) -> Self {
        self.response_type = Some("none".to_owned());
        self
    }

    /// Sets the response_type to `token`
    pub fn token_implicit_flow(mut self) -> Self {
        self.response_type = Some("token".to_owned());
        self
    }

    /// Sets the response_type to `id_token`
    pub fn id_token_implicit_flow(mut self) -> Self {
        self.response_type = Some("id_token".to_owned());
        self
    }

    /// Sets the response_type to `id_token token`
    pub fn implicit_flow(mut self) -> Self {
        self.response_type = Some("id_token token".to_owned());
        self
    }

    /// Sets the response_type to `code token`
    pub fn token_hybrid_flow(mut self) -> Self {
        self.response_type = Some("code token".to_owned());
        self
    }

    /// Sets the response_type to `code id_token`
    pub fn id_token_hybrid_flow(mut self) -> Self {
        self.response_type = Some("code id_token".to_owned());
        self
    }

    /// Sets the response_type to `code id_token token`
    pub fn hybrid_flow(mut self) -> Self {
        self.response_type = Some("code id_token token".to_owned());
        self
    }

    /// Sets the `redirect_uri`
    pub fn redirect_uri(mut self, uri: impl Into<String>) -> Self {
        self.redirect_uri = Some(uri.into());
        self
    }

    /// Sets the `response_mode` parameter
    pub fn response_mode(mut self, mode: impl Into<String>) -> Self {
        self.response_mode = Some(mode.into());
        self
    }

    /// Sets the `login_hint` parameter
    pub fn login_hint(mut self, hint: impl Into<String>) -> Self {
        self.login_hint = Some(hint.into());
        self
    }

    /// Sets the `client_id` parameter. If not set, the client id is taken from the config.
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Sets the `max_age` parameter
    pub fn max_age(mut self, max_age: i64) -> Self {
        self.max_age = Some(max_age.to_string());
        self
    }

    /// Sets the`display` parameter
    pub fn display(mut self, display: impl Into<String>) -> Self {
        self.display = Some(display.into());
        self
    }

    /// Sets the`id_token_hint` parameter
    pub fn id_token_hint(mut self, id_token_hint: impl Into<String>) -> Self {
        self.id_token_hint = Some(id_token_hint.into());
        self
    }

    /// Sets the`registration` parameter
    pub fn registration(mut self, registration: impl Into<String>) -> Self {
        self.registration = Some(registration.into());
        self
    }

    /// Sets the`request_uri` parameter
    pub fn request_uri(mut self, request_uri: impl Into<String>) -> Self {
        self.request_uri = Some(request_uri.into());
        self
    }

    /// Sets the`request` parameter
    pub fn request(mut self, request: impl Into<String>) -> Self {
        self.request = Some(request.into());
        self
    }

    /// Add a scope to the `scope` parameter.
    pub fn add_scope(mut self, scope: impl Into<String>) -> Self {
        match &mut self.scope {
            Some(scopes) => scopes.push(scope.into()),
            None => self.scope = Some(vec![scope.into()]),
        }

        self
    }

    /// Add a prompt to the `prompt` parameter.
    pub fn add_prompt(mut self, prompt: impl Into<String>) -> Self {
        match &mut self.prompt {
            Some(prompts) => prompts.push(prompt.into()),
            None => self.prompt = Some(vec![prompt.into()]),
        }

        self
    }

    /// Add a audience to the `audience` parameter.
    pub fn add_audience(mut self, audience: impl Into<String>) -> Self {
        match &mut self.audience {
            Some(audiences) => audiences.push(audience.into()),
            None => self.audience = Some(vec![audience.into()]),
        }

        self
    }

    /// Add a acr_value to the `acr_values` parameter.
    pub fn add_acr_value(mut self, acr_value: impl Into<String>) -> Self {
        match &mut self.acr_values {
            Some(acr_values) => acr_values.push(acr_value.into()),
            None => self.acr_values = Some(vec![acr_value.into()]),
        }

        self
    }

    /// Add a claims_locale to the `claims_locales` parameter.
    pub fn add_claims_locale(mut self, claims_locale: impl Into<String>) -> Self {
        match &mut self.claims_locales {
            Some(claims_locales) => claims_locales.push(claims_locale.into()),
            None => self.claims_locales = Some(vec![claims_locale.into()]),
        }

        self
    }

    /// Add a resource to the `resource` parameter.
    pub fn add_resource(mut self, resource: impl Into<String>) -> Self {
        match &mut self.resource {
            Some(resources) => resources.push(resource.into()),
            None => self.resource = Some(vec![resource.into()]),
        }

        self
    }

    /// Add a ui_locale to the `ui_locales` parameter.
    pub fn add_ui_locale(mut self, ui_locale: impl Into<String>) -> Self {
        match &mut self.ui_locales {
            Some(ui_locales) => ui_locales.push(ui_locale.into()),
            None => self.ui_locales = Some(vec![ui_locale.into()]),
        }

        self
    }

    /// Sets the`claim` parameter
    pub fn claims(mut self, claim: ClaimParam) -> Self {
        self.claims = Some(claim);
        self
    }

    /// Add additional param to the authorization request
    pub fn add_additional_param(
        mut self,
        param: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        match &mut self.additional_parameters {
            Some(additional_params) => {
                additional_params.insert(param.into(), value.into());
            }
            None => {
                let mut map = HashMap::new();
                map.insert(param.into(), value.into());
                self.additional_parameters = Some(map)
            }
        }

        self
    }
}

// Helper methods
impl AuthorizationParameters {
    /// Generates PKCE and sets it to `code_challenge` parameter
    pub fn generate_pkce(&mut self) -> Pkce {
        let pkce = generate_pkce();

        self.code_challenge = Some(pkce.challenge.to_owned());
        self.code_challenge_method = Some("S256".to_owned());

        pkce
    }

    /// Sets the `nonce` parameter
    pub fn nonce(&mut self) -> String {
        let nonce = generate_random(None);
        self.nonce = Some(nonce.to_owned());
        nonce
    }

    /// Sets the `state` parameter
    pub fn state(&mut self) -> String {
        let state = generate_random(None);
        self.state = Some(state.to_owned());
        state
    }
}

impl From<AuthorizationParameters> for HashMap<String, String> {
    fn from(val: AuthorizationParameters) -> Self {
        let mut query = HashMap::new();

        if let Some(param) = val.additional_parameters {
            for (k, v) in param {
                query.entry(k).or_insert(v);
            }
        }

        insert_query(&mut query, "client_id", val.client_id);
        insert_query(&mut query, "acr_values", stringify_vec(val.acr_values));
        insert_query(&mut query, "audience", stringify_vec(val.audience));
        insert_query(
            &mut query,
            "claims_locales",
            stringify_vec(val.claims_locales),
        );
        insert_query(
            &mut query,
            "code_challenge_method",
            val.code_challenge_method,
        );
        insert_query(&mut query, "code_challenge", val.code_challenge);
        insert_query(&mut query, "display", val.display);
        insert_query(&mut query, "id_token_hint", val.id_token_hint);
        insert_query(&mut query, "login_hint", val.login_hint);
        insert_query(&mut query, "max_age", val.max_age);
        insert_query(&mut query, "nonce", val.nonce);
        insert_query(&mut query, "prompt", stringify_vec(val.prompt));
        insert_query(&mut query, "redirect_uri", val.redirect_uri);
        insert_query(&mut query, "registration", val.registration);
        insert_query(&mut query, "request_uri", val.request_uri);
        insert_query(&mut query, "request", val.request);
        insert_query(&mut query, "response_mode", val.response_mode);
        insert_query(&mut query, "response_type", val.response_type);
        insert_query(&mut query, "scope", stringify_vec(val.scope));
        insert_query(&mut query, "state", val.state);
        insert_query(&mut query, "resource", stringify_vec(val.resource));
        insert_query(&mut query, "ui_locales", stringify_vec(val.ui_locales));

        if let Some(c) = &val.claims {
            if let Ok(s) = serde_json::to_string(c) {
                query.insert("claims".to_owned(), s);
            }
        }

        query
    }
}

fn insert_query(qp: &mut HashMap<String, String>, key: &str, value: Option<String>) {
    if let Some(v) = value {
        qp.insert(key.to_owned(), v);
    }
}

fn stringify_vec(val: Option<Vec<String>>) -> Option<String> {
    if let Some(val) = val {
        let mut stringified = String::new();
        for v in val {
            stringified += &format!("{v} ");
        }

        return Some(stringified.trim_end().to_owned());
    }

    None
}

/// # ClaimParamValue
/// Value for each [ClaimParam]
#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum ClaimParamValue {
    /// Null (null) value
    Null,
    /// See [ClaimsParameterMember]
    ClaimParamMember(ClaimsParameterMember),
}

/// # ClaimParam
/// The value of `claims` of [AuthorizationParameters]
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ClaimParam {
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Claims structure of `id_token`
    pub id_token: Option<HashMap<String, ClaimParamValue>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    /// Claims structure of `userinfo` that will be returned
    pub userinfo: Option<HashMap<String, ClaimParamValue>>,
}

/// # ClaimsParameterMember
/// Customizing the claims from `claims` of [AuthorizationParameters]
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ClaimsParameterMember {
    /// Marks as essential or not
    #[serde(skip_serializing_if = "Option::is_none")]
    pub essential: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Claim that should be mapped to the specified key
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Claims that should be mapped to the specified key
    pub values: Option<Vec<String>>,
    #[serde(flatten)]
    /// Other fields that should be sent
    pub other: Option<HashMap<String, serde_json::Value>>,
}

#[cfg(test)]
mod claim_param_tests {
    use std::collections::HashMap;

    use assert_json_diff::assert_json_eq;
    use serde_json::{json, Value};

    use super::{ClaimParam, ClaimParamValue, ClaimsParameterMember};

    #[test]
    fn serialize_test_1() {
        let mut userinfo: HashMap<String, ClaimParamValue> = HashMap::new();
        userinfo.insert("null".to_string(), ClaimParamValue::Null);

        let cpm = ClaimsParameterMember {
            essential: Some(false),
            value: None,
            values: None,
            other: None,
        };

        let cv = ClaimParamValue::ClaimParamMember(cpm);

        userinfo.insert("cpm".to_string(), cv);

        let claim_param = ClaimParam {
            id_token: None,
            userinfo: Some(userinfo),
        };

        let serialized_result = serde_json::to_string(&claim_param);

        assert!(serialized_result.is_ok());

        let string = serialized_result.unwrap();

        assert_json_eq!(
            json!({"userinfo": {"null": null,"cpm":{"essential": false}}}),
            serde_json::from_str::<Value>(&string).unwrap()
        );
    }

    #[test]
    fn serialize_test_2() {
        let mut userinfo: HashMap<String, ClaimParamValue> = HashMap::new();

        let mut other: HashMap<String, Value> = HashMap::new();

        other.insert(
            "extra".to_string(),
            json!({"this_is_obj": {"str":"hi", "bool": true}}),
        );

        let cpm = ClaimsParameterMember {
            essential: None,
            value: None,
            values: Some(vec!["hello".to_string()]),
            other: Some(other),
        };

        let cv = ClaimParamValue::ClaimParamMember(cpm);

        userinfo.insert("cpm".to_string(), cv);

        let claim_param = ClaimParam {
            id_token: None,
            userinfo: Some(userinfo),
        };

        let serialized_result = serde_json::to_string(&claim_param);

        assert!(serialized_result.is_ok());

        let string = serialized_result.unwrap();

        assert_json_eq!(
            json!({"userinfo": {"cpm":{"values": ["hello"], "extra" : {"this_is_obj": {"str": "hi", "bool": true}}}}}),
            serde_json::from_str::<Value>(&string).unwrap()
        );
    }
}
