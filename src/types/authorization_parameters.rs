use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// # AuthorizationParameters
/// Values that will be sent with the [`crate::client::Client::authorization_url()`] or  authorize request
#[derive(Debug, Default)]
pub struct AuthorizationParameters {
    /// [Auth Context Class Reference Values](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
    pub acr_values: Option<Vec<String>>,
    /// Audience of the Access Token
    pub audience: Option<Vec<String>>,
    /// Claims customization for `id_token` and `userinfo`
    pub claims: Option<ClaimParam>,
    /// Preferred [language script](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) for claims
    pub claims_locales: Option<Vec<String>>,
    /// [Client Id](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
    pub client_id: Option<String>,
    /// [PKCE code challenge method](https://datatracker.ietf.org/doc/html/rfc7636)
    pub code_challenge_method: Option<String>,
    /// [PKCE code challenge](https://datatracker.ietf.org/doc/html/rfc7636)
    pub code_challenge: Option<String>,
    /// [Display](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
    pub display: Option<String>,
    /// [Id token hint](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest). Used for
    /// hinting the user the authorization request is meant for.
    pub id_token_hint: Option<String>,
    /// [Login hint](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) for
    /// the authorization server.
    pub login_hint: Option<String>,
    /// [Maximum Authentication Age](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
    pub max_age: Option<String>,
    /// [Nonce](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
    pub nonce: Option<String>,
    /// [Prompt Parameter](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
    pub prompt: Option<Vec<String>>,
    /// [Redirect Uri](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
    /// to which response will be sent
    pub redirect_uri: Option<String>,
    /// Boolean value that marks if the client requesting for authorization is to be dynamically
    /// registered
    pub registration: Option<String>,
    /// [Uri of the request object](https://www.rfc-editor.org/rfc/rfc9101#name-request-using-the-request_u)
    pub request_uri: Option<String>,
    /// [Request Object](https://www.rfc-editor.org/rfc/rfc9101#name-passing-a-request-object-by)
    pub request: Option<String>,
    /// [Resource Parameter](https://www.rfc-editor.org/rfc/rfc8693.html#section-2.1)
    pub resource: Option<Vec<String>>,
    /// [Response Mode](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
    pub response_mode: Option<String>,
    /// [Response Type](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
    pub response_type: Option<Vec<String>>,
    /// [Scope](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
    pub scope: Option<Vec<String>>,
    /// [State Parameter](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
    pub state: Option<String>,
    /// Preferred [language script](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) for UI
    pub ui_locales: Option<Vec<String>>,
    /// Other fields that will be sent with the authorization request
    pub other: Option<HashMap<String, String>>,
}

impl From<AuthorizationParameters> for HashMap<String, String> {
    fn from(val: AuthorizationParameters) -> Self {
        let mut query = HashMap::new();

        if let Some(other) = val.other {
            for (k, v) in other {
                query.entry(k).or_insert(v);
            }
        }

        insert_query(&mut query, "client_id", val.client_id);

        if let Some(acr_arr) = val.acr_values {
            let mut acr_str = String::new();
            for acr in acr_arr {
                acr_str += &format!("{} ", acr);
            }

            insert_query(
                &mut query,
                "acr_values",
                Some(acr_str.trim_end().to_owned()),
            );
        }

        if let Some(aud_arr) = val.audience {
            let mut aud_str = String::new();
            for aud in aud_arr {
                aud_str += &format!("{} ", aud);
            }

            insert_query(&mut query, "audience", Some(aud_str.trim_end().to_owned()));
        }

        if let Some(locale_arr) = val.claims_locales {
            let mut locale_str = String::new();
            for locale in locale_arr {
                locale_str += &format!("{} ", locale);
            }

            insert_query(
                &mut query,
                "claims_locales",
                Some(locale_str.trim_end().to_owned()),
            );
        }
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

        if let Some(prompt_arr) = val.prompt {
            let mut prompt_str = String::new();
            for prompt in prompt_arr {
                prompt_str += &format!("{} ", prompt);
            }

            insert_query(&mut query, "prompt", Some(prompt_str.trim_end().to_owned()));
        }

        insert_query(&mut query, "redirect_uri", val.redirect_uri);
        insert_query(&mut query, "registration", val.registration);
        insert_query(&mut query, "request_uri", val.request_uri);
        insert_query(&mut query, "request", val.request);
        insert_query(&mut query, "response_mode", val.response_mode);

        if let Some(res_arr) = val.response_type {
            let mut res_str = String::new();
            for res in res_arr {
                res_str += &format!("{} ", res);
            }

            insert_query(
                &mut query,
                "response_type",
                Some(res_str.trim_end().to_owned()),
            );
        }

        if let Some(scope_arr) = val.scope {
            let mut scope_str = String::new();
            for scope in scope_arr {
                scope_str += &format!("{} ", scope);
            }

            insert_query(&mut query, "scope", Some(scope_str.trim_end().to_owned()));
        }

        insert_query(&mut query, "state", val.state);

        if let Some(ui_locales_arr) = val.ui_locales {
            let mut ui_locales_str = String::new();
            for ui_locale in ui_locales_arr {
                ui_locales_str += &format!("{} ", ui_locale);
            }

            insert_query(
                &mut query,
                "ui_locales",
                Some(ui_locales_str.trim_end().to_owned()),
            );
        }

        if let Some(c) = &val.claims {
            if let Ok(s) = serde_json::to_string(c) {
                query.insert("claims".to_owned(), s);
            }
        }

        if let Some(resource) = &val.resource {
            let mut resource_str = String::new();
            for r in resource {
                resource_str += &format!("{} ", r);
            }

            insert_query(
                &mut query,
                "resource",
                Some(resource_str.trim_end().to_owned()),
            );
        }

        query
    }
}

fn insert_query(qp: &mut HashMap<String, String>, key: &str, value: Option<String>) {
    if let Some(v) = value {
        qp.insert(key.to_owned(), v);
    }
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
    pub other: Option<HashMap<String, Value>>,
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
