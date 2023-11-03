use std::collections::HashMap;

use serde::Serialize;
use serde_json::Value;

/// # AuthorizationParameters
/// Values that will be sent with the [`crate::client::Client::authorization_url()`] or  authorize request
#[derive(Debug, Default)]
pub struct AuthorizationParameters {
    /// [Auth Context Class Reference Values](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
    pub acr_values: Option<String>,
    /// Audience of the Access Token
    pub audience: Option<Vec<String>>,
    /// Claims customization for `id_token` and `userinfo`
    pub claims: Option<ClaimParam>,
    /// Preferred [language script](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) for claims
    pub claims_locales: Option<String>,
    /// [Client Id](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
    pub client_id: Option<String>,
    /// [PKCE code challenge method](https://datatracker.ietf.org/doc/html/rfc7636)
    pub code_challenge_method: Option<String>,
    /// [PKCE code challenge](https://datatracker.ietf.org/doc/html/rfc7636)
    pub code_challenge: Option<String>,
    /// [Display](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
    pub display: Option<String>,
    /// [Id token hint](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
    pub id_token_hint: Option<String>,
    /// [Login hint](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) for
    /// Op.
    pub login_hint: Option<String>,
    /// [Maximum Authentication Age](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
    pub max_age: Option<String>,
    /// [Nonce](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
    pub nonce: Option<String>,
    /// [Prompt Parameter](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
    pub prompt: Option<String>,
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
    /// [Resource Parameter](https://datatracker.ietf.org/doc/html/rfc8707#name-authorization-request)
    pub resource: Option<ResourceParam>,
    /// [Response Mode](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
    pub response_mode: Option<String>,
    /// [Response Type](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
    pub response_type: Option<Vec<String>>,
    /// [Scope](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
    pub scope: Option<String>,
    /// [State Parameter](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
    pub state: Option<String>,
    /// Preferred [language script](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) for UI
    pub ui_locales: Option<String>,
    /// Other fields
    pub other: Option<HashMap<String, String>>,
}

/// # ClaimParamValue
/// Value for each [ClaimParam]
#[derive(Serialize, Debug)]
#[serde(untagged)]
pub enum ClaimParamValue {
    /// Null (null) value
    Null,
    /// [ClaimsParameterMember]
    ClaimParamMember(ClaimsParameterMember),
}

/// # ClaimParam
/// The value of `claims` of [AuthorizationParameters]
#[derive(Serialize, Debug, Default)]
pub struct ClaimParam {
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Claims structure of `id_token`
    pub id_token: Option<HashMap<String, ClaimParamValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Claims structure of `userinfo` that will be returned
    pub userinfo: Option<HashMap<String, ClaimParamValue>>,
}

/// # ClaimsParameterMember
/// Customizing the claims from `claims` of [AuthorizationParameters]
#[derive(Serialize, Debug, Default)]
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

/// # ResourceParam
/// Value types for `resource` of [AuthorizationParameters]
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ResourceParam {
    /// Resource value as string
    String(String),
    /// Resource value as an array
    Array(Vec<String>),
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
