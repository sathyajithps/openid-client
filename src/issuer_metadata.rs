use crate::helpers::json_value_to_vec_string;
use json::object::Object;
use json::JsonValue;
use std::collections::HashMap;

#[derive(Debug)]
pub struct MtlsEndpoints {
    token_endpoint: Option<String>,
    userinfo_endpoint: Option<String>,
    revocation_endpoint: Option<String>,
    introspection_endpoint: Option<String>,
    device_authorization_endpoint: Option<String>,
}

impl MtlsEndpoints {
    pub fn is_empty(&self) -> bool {
        return self.userinfo_endpoint.is_none()
            && self.token_endpoint.is_none()
            && self.revocation_endpoint.is_none()
            && self.device_authorization_endpoint.is_none();
    }
}

#[derive(Debug)]
pub struct IssuerMetadata {
    pub issuer: String,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub revocation_endpoint: Option<String>,
    pub end_session_endpoint: Option<String>,
    pub registration_endpoint: Option<String>,
    pub introspection_endpoint: Option<String>,
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    pub introspection_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    pub revocation_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub revocation_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    pub request_object_signing_alg_values_supported: Option<Vec<String>>,
    pub mtls_endpoint_aliases: Option<MtlsEndpoints>,
    pub other_fields: Option<HashMap<String, JsonValue>>,
}

impl IssuerMetadata {
    pub fn default() -> Self {
        Self {
            issuer: String::new(),
            authorization_endpoint: None,
            token_endpoint: None,
            jwks_uri: None,
            userinfo_endpoint: None,
            revocation_endpoint: None,
            end_session_endpoint: None,
            registration_endpoint: None,
            introspection_endpoint: None,
            token_endpoint_auth_methods_supported: None,
            token_endpoint_auth_signing_alg_values_supported: None,
            introspection_endpoint_auth_methods_supported: None,
            introspection_endpoint_auth_signing_alg_values_supported: None,
            revocation_endpoint_auth_methods_supported: None,
            revocation_endpoint_auth_signing_alg_values_supported: None,
            request_object_signing_alg_values_supported: None,
            mtls_endpoint_aliases: None,
            other_fields: None,
        }
    }

    pub fn from(obj: &Object) -> Result<Self, String> {
        let mut metadata = Self::default();
        let mut other_fields: HashMap<String, JsonValue> = HashMap::new();
        for (k, v) in obj.iter() {
            match k {
                "issuer" => metadata.issuer = v.to_string(),
                "authorization_endpoint" => metadata.authorization_endpoint = Some(v.to_string()),
                "token_endpoint" => metadata.token_endpoint = Some(v.to_string()),
                "jwks_uri" => metadata.jwks_uri = Some(v.to_string()),
                "userinfo_endpoint" => metadata.userinfo_endpoint = Some(v.to_string()),
                "end_session_endpoint" => metadata.end_session_endpoint = Some(v.to_string()),
                "revocation_endpoint" => metadata.revocation_endpoint = Some(v.to_string()),
                "introspection_endpoint" => metadata.introspection_endpoint = Some(v.to_string()),
                "registration_endpoint" => metadata.registration_endpoint = Some(v.to_string()),
                "token_endpoint_auth_methods_supported" => {
                    metadata.token_endpoint_auth_methods_supported = json_value_to_vec_string(v)
                }
                "token_endpoint_auth_signing_alg_values_supported" => {
                    metadata.token_endpoint_auth_signing_alg_values_supported =
                        json_value_to_vec_string(v)
                }
                "introspection_endpoint_auth_methods_supported" => {
                    metadata.introspection_endpoint_auth_methods_supported =
                        json_value_to_vec_string(v)
                }
                "introspection_endpoint_auth_signing_alg_values_supported" => {
                    metadata.introspection_endpoint_auth_signing_alg_values_supported =
                        json_value_to_vec_string(v)
                }
                "revocation_endpoint_auth_methods_supported" => {
                    metadata.revocation_endpoint_auth_methods_supported =
                        json_value_to_vec_string(v)
                }
                "revocation_endpoint_auth_signing_alg_values_supported" => {
                    metadata.revocation_endpoint_auth_signing_alg_values_supported =
                        json_value_to_vec_string(v)
                }
                "request_object_signing_alg_values_supported" => {
                    metadata.request_object_signing_alg_values_supported =
                        json_value_to_vec_string(v)
                }
                "mtls_endpoint_aliases" => {
                    if let JsonValue::Object(mtls_obj) = v {
                        let mut mtls_endpoints = MtlsEndpoints {
                            token_endpoint: None,
                            userinfo_endpoint: None,
                            revocation_endpoint: None,
                            introspection_endpoint: None,
                            device_authorization_endpoint: None,
                        };
                        for (m_key, m_val) in mtls_obj.iter() {
                            match m_key {
                                "token_endpoint" => {
                                    mtls_endpoints.token_endpoint = Some(m_val.to_string())
                                }
                                "userinfo_endpoint" => {
                                    mtls_endpoints.userinfo_endpoint = Some(m_val.to_string())
                                }
                                "revocation_endpoint" => {
                                    mtls_endpoints.revocation_endpoint = Some(m_val.to_string())
                                }
                                "introspection_endpoint" => {
                                    mtls_endpoints.introspection_endpoint = Some(m_val.to_string())
                                }
                                "device_authorization_endpoint" => {
                                    mtls_endpoints.device_authorization_endpoint =
                                        Some(m_val.to_string())
                                }
                                _ => {}
                            }
                        }
                        if !mtls_endpoints.is_empty() {
                            metadata.mtls_endpoint_aliases = Some(mtls_endpoints)
                        } else {
                            metadata.mtls_endpoint_aliases = None
                        }
                    }
                }
                _ => {
                    other_fields.insert(k.to_string(), v.to_owned());
                }
            }
        }

        if !other_fields.is_empty() {
            metadata.other_fields = Some(other_fields);
        }

        Ok(metadata)
    }
}
