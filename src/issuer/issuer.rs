use core::fmt::Debug;
use std::collections::HashMap;

use crate::client::Client;
use crate::helpers::{convert_json_to, now, validate_url, webfinger_normalize};
use crate::http::request_async;
use crate::jwks::Jwks;
use crate::types::http_client::HttpMethod;
use crate::types::{
    ClientMetadata, ClientOptions, Fapi, HttpRequest, HttpResponse, IssuerMetadata, MtlsEndpoints,
    OidcClientError, OidcHttpClient, OidcReturnType, WebFingerResponse,
};

use serde_json::Value;
use url::Url;

use super::keystore::KeyStore;

/// Holds all the discovered values from the OIDC Issuer
#[derive(Debug)]
pub struct Issuer {
    pub(crate) issuer: String,
    pub(crate) authorization_endpoint: Option<String>,
    pub(crate) device_authorization_endpoint: Option<String>,
    pub(crate) token_endpoint: Option<String>,
    pub(crate) jwks_uri: Option<String>,
    pub(crate) userinfo_endpoint: Option<String>,
    pub(crate) revocation_endpoint: Option<String>,
    pub(crate) claims_parameter_supported: Option<bool>,
    pub(crate) grant_types_supported: Option<Vec<String>>,
    pub(crate) request_parameter_supported: Option<bool>,
    pub(crate) request_uri_parameter_supported: Option<bool>,
    pub(crate) require_request_uri_registration: Option<bool>,
    pub(crate) response_modes_supported: Option<Vec<String>>,
    pub(crate) claim_types_supported: Vec<String>,
    pub(crate) token_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub(crate) token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    pub(crate) introspection_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub(crate) introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    pub(crate) revocation_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub(crate) revocation_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    pub(crate) end_session_endpoint: Option<String>,
    pub(crate) other_fields: HashMap<String, Value>,
    pub(crate) keystore: Option<KeyStore>,
    pub(crate) mtls_endpoint_aliases: Option<MtlsEndpoints>,
    pub(crate) introspection_endpoint: Option<String>,
    pub(crate) registration_endpoint: Option<String>,
    pub(crate) authorization_response_iss_parameter_supported: Option<bool>,
    pub(crate) dpop_signing_alg_values_supported: Option<Vec<String>>,
    pub(crate) pushed_authorization_request_endpoint: Option<String>,
    pub(crate) require_pushed_authorization_requests: bool,
    pub(crate) backchannel_token_delivery_modes_supported: Option<Vec<String>>,
    pub(crate) backchannel_authentication_endpoint: Option<String>,
    pub(crate) backchannel_authentication_request_signing_alg_values_supported: Option<Vec<String>>,
    pub(crate) backchannel_user_code_parameter_supported: bool,
    pub(crate) now: fn() -> u64,
}

impl Default for Issuer {
    fn default() -> Self {
        Self {
            claims_parameter_supported: Some(false),
            grant_types_supported: Some(vec![
                String::from("authorization_code"),
                String::from("implicit"),
            ]),
            request_parameter_supported: Some(false),
            request_uri_parameter_supported: Some(true),
            require_request_uri_registration: Some(false),
            response_modes_supported: Some(vec![String::from("query"), String::from("fragment")]),
            claim_types_supported: vec![String::from("normal")],
            token_endpoint_auth_methods_supported: Some(vec!["client_secret_basic".to_string()]),
            introspection_endpoint_auth_methods_supported: None,
            issuer: "".to_string(),
            authorization_endpoint: None,
            token_endpoint: None,
            jwks_uri: None,
            userinfo_endpoint: None,
            revocation_endpoint: None,
            revocation_endpoint_auth_methods_supported: None,
            token_endpoint_auth_signing_alg_values_supported: None,
            introspection_endpoint_auth_signing_alg_values_supported: None,
            revocation_endpoint_auth_signing_alg_values_supported: None,
            end_session_endpoint: None,
            other_fields: Default::default(),
            keystore: None,
            mtls_endpoint_aliases: None,
            introspection_endpoint: None,
            authorization_response_iss_parameter_supported: None,
            registration_endpoint: None,
            dpop_signing_alg_values_supported: None,
            pushed_authorization_request_endpoint: None,
            require_pushed_authorization_requests: false,
            device_authorization_endpoint: None,
            backchannel_token_delivery_modes_supported: None,
            backchannel_authentication_endpoint: None,
            backchannel_authentication_request_signing_alg_values_supported: None,
            backchannel_user_code_parameter_supported: false,
            now,
        }
    }
}

/// Issuer Instance Creation
impl Issuer {
    fn from(metadata: IssuerMetadata) -> Self {
        let token_endpoint_auth_methods_supported =
            match metadata.token_endpoint_auth_methods_supported {
                None => Some(vec!["client_secret_basic".to_string()]),
                Some(v) => Some(v),
            };

        let introspection_endpoint_auth_methods_supported =
            match metadata.introspection_endpoint_auth_methods_supported {
                None => token_endpoint_auth_methods_supported.clone(),
                Some(v) => Some(v),
            };

        let introspection_endpoint_auth_signing_alg_values_supported =
            match metadata.introspection_endpoint_auth_signing_alg_values_supported {
                None => metadata
                    .token_endpoint_auth_signing_alg_values_supported
                    .clone(),
                Some(v) => Some(v),
            };

        let revocation_endpoint_auth_methods_supported =
            match metadata.revocation_endpoint_auth_methods_supported {
                None => token_endpoint_auth_methods_supported.clone(),
                Some(v) => Some(v),
            };

        let revocation_endpoint_auth_signing_alg_values_supported =
            match metadata.revocation_endpoint_auth_signing_alg_values_supported {
                None => metadata
                    .token_endpoint_auth_signing_alg_values_supported
                    .clone(),
                Some(v) => Some(v),
            };

        let jwks_uri = metadata.jwks_uri.clone();

        Self {
            issuer: metadata.issuer,
            authorization_endpoint: metadata.authorization_endpoint,
            device_authorization_endpoint: metadata.device_authorization_endpoint,
            token_endpoint: metadata.token_endpoint,
            jwks_uri: metadata.jwks_uri,
            userinfo_endpoint: metadata.userinfo_endpoint,
            revocation_endpoint: metadata.revocation_endpoint,
            token_endpoint_auth_methods_supported,
            introspection_endpoint_auth_methods_supported,
            introspection_endpoint_auth_signing_alg_values_supported,
            revocation_endpoint_auth_methods_supported,
            revocation_endpoint_auth_signing_alg_values_supported,
            end_session_endpoint: metadata.end_session_endpoint,
            registration_endpoint: metadata.registration_endpoint,
            introspection_endpoint: metadata.introspection_endpoint,
            token_endpoint_auth_signing_alg_values_supported: metadata
                .token_endpoint_auth_signing_alg_values_supported,
            mtls_endpoint_aliases: metadata.mtls_endpoint_aliases,
            authorization_response_iss_parameter_supported: metadata
                .authorization_response_iss_parameter_supported,
            dpop_signing_alg_values_supported: metadata.dpop_signing_alg_values_supported,
            pushed_authorization_request_endpoint: metadata.pushed_authorization_request_endpoint,
            require_pushed_authorization_requests: metadata.require_pushed_authorization_requests,
            other_fields: metadata.other_fields,
            keystore: Some(KeyStore::new(jwks_uri)),
            backchannel_token_delivery_modes_supported: metadata
                .backchannel_token_delivery_modes_supported,
            backchannel_authentication_endpoint: metadata.backchannel_authentication_endpoint,
            backchannel_authentication_request_signing_alg_values_supported: metadata
                .backchannel_authentication_request_signing_alg_values_supported,
            backchannel_user_code_parameter_supported: metadata
                .backchannel_user_code_parameter_supported
                .unwrap_or(false),
            ..Issuer::default()
        }
    }

    /// ## Issuer
    ///
    /// Create an [Issuer] instance using [IssuerMetadata].
    ///
    /// - `metadata` - [IssuerMetadata]
    ///
    /// No OIDC Discovery defaults are set if Issuer is created using this method.
    ///
    /// If no introspection/revocation endpoint auth methods or algorithms are specified,
    /// value of token endpoint auth methods and algorithms are used as the the value for the said
    /// properties.
    pub fn new(metadata: IssuerMetadata) -> Self {
        let introspection_endpoint_auth_methods_supported =
            match metadata.introspection_endpoint_auth_methods_supported {
                None => metadata.token_endpoint_auth_methods_supported.clone(),
                Some(v) => Some(v),
            };

        let introspection_endpoint_auth_signing_alg_values_supported =
            match metadata.introspection_endpoint_auth_signing_alg_values_supported {
                None => metadata
                    .token_endpoint_auth_signing_alg_values_supported
                    .clone(),
                Some(v) => Some(v),
            };

        let revocation_endpoint_auth_methods_supported =
            match metadata.revocation_endpoint_auth_methods_supported {
                None => metadata.token_endpoint_auth_methods_supported.clone(),
                Some(v) => Some(v),
            };

        let revocation_endpoint_auth_signing_alg_values_supported =
            match metadata.revocation_endpoint_auth_signing_alg_values_supported {
                None => metadata
                    .token_endpoint_auth_signing_alg_values_supported
                    .clone(),
                Some(v) => Some(v),
            };

        let jwks_uri = metadata.jwks_uri.clone();

        Self {
            issuer: metadata.issuer,
            authorization_endpoint: metadata.authorization_endpoint,
            token_endpoint: metadata.token_endpoint,
            jwks_uri: metadata.jwks_uri,
            userinfo_endpoint: metadata.userinfo_endpoint,
            revocation_endpoint: metadata.revocation_endpoint,
            claims_parameter_supported: None,
            grant_types_supported: None,
            request_parameter_supported: None,
            request_uri_parameter_supported: None,
            require_request_uri_registration: None,
            response_modes_supported: None,
            claim_types_supported: vec![],
            token_endpoint_auth_methods_supported: metadata.token_endpoint_auth_methods_supported,
            introspection_endpoint_auth_methods_supported,
            token_endpoint_auth_signing_alg_values_supported: metadata
                .token_endpoint_auth_signing_alg_values_supported,
            introspection_endpoint_auth_signing_alg_values_supported,
            revocation_endpoint_auth_methods_supported,
            revocation_endpoint_auth_signing_alg_values_supported,
            other_fields: metadata.other_fields,
            keystore: Some(KeyStore::new(jwks_uri)),
            mtls_endpoint_aliases: metadata.mtls_endpoint_aliases,
            introspection_endpoint: metadata.introspection_endpoint,
            registration_endpoint: metadata.registration_endpoint,
            end_session_endpoint: metadata.end_session_endpoint,
            authorization_response_iss_parameter_supported: metadata
                .authorization_response_iss_parameter_supported,
            dpop_signing_alg_values_supported: metadata.dpop_signing_alg_values_supported,
            pushed_authorization_request_endpoint: metadata.pushed_authorization_request_endpoint,
            require_pushed_authorization_requests: metadata.require_pushed_authorization_requests,
            device_authorization_endpoint: metadata.device_authorization_endpoint,
            backchannel_token_delivery_modes_supported: metadata
                .backchannel_token_delivery_modes_supported,
            backchannel_authentication_endpoint: metadata.backchannel_authentication_endpoint,
            backchannel_authentication_request_signing_alg_values_supported: metadata
                .backchannel_authentication_request_signing_alg_values_supported,
            backchannel_user_code_parameter_supported: metadata
                .backchannel_user_code_parameter_supported
                .unwrap_or(false),
            now,
        }
    }
}

/// OIDC [Issuer Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery)
impl Issuer {
    /// # Discover OIDC Issuer
    ///
    /// Discover an OIDC Issuer using the issuer url.
    ///
    /// - `http_client` - The http client used to make the request.
    /// - `issuer` - The issuer url (absolute).
    ///
    /// *Only an absolute urls are accepted, passing in `auth.example.com` will result in an error.*
    pub async fn discover_async<T>(http_client: &T, issuer: &str) -> OidcReturnType<Issuer>
    where
        T: OidcHttpClient,
    {
        let mut url = match validate_url(issuer) {
            Ok(parsed) => parsed,
            Err(err) => return Err(err),
        };

        let mut path: String = url.path().to_string();
        if path.ends_with('/') {
            path.pop();
        }

        if path.ends_with(".well-known") {
            path.push_str("/openid-configuration");
        } else if !path.contains(".well-known") {
            path.push_str("/.well-known/openid-configuration");
        }

        url.set_path(&path);

        let mut headers = HashMap::new();
        headers.insert("accept".to_string(), vec!["application/json".to_string()]);

        let req = HttpRequest::new().url(url).headers(headers);

        let res = request_async(req, http_client).await?;

        let issuer_metadata = match convert_json_to::<IssuerMetadata>(res.body.as_ref().unwrap()) {
            Ok(metadata) => metadata,
            Err(_) => {
                return Err(Box::new(OidcClientError::new_op_error(
                    "invalid_issuer_metadata".to_string(),
                    None,
                    None,
                    Some(res),
                )));
            }
        };

        Ok(Issuer::from(issuer_metadata))
    }
}

/// OIDC [Issuer Webfinger Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery)
impl Issuer {
    /// # Webfinger OIDC Issuer Discovery
    ///
    /// Discover an OIDC Issuer using the user email, url, url with port syntax or acct syntax.
    ///
    /// - `http_client` - The http client to make the request
    /// - `input` - The resource.
    ///
    pub async fn webfinger_async<T>(http_client: &T, input: &str) -> OidcReturnType<Issuer>
    where
        T: OidcHttpClient,
    {
        let req = Self::build_webfinger_request(input)?;

        let res = request_async(req, http_client).await?;

        let expected_issuer = Self::process_webfinger_response(res)?;

        let issuer_result = Issuer::discover_async(http_client, &expected_issuer).await;

        Self::process_webfinger_issuer_result(issuer_result, expected_issuer)
    }

    fn build_webfinger_request(input: &str) -> OidcReturnType<HttpRequest> {
        let resource = webfinger_normalize(input);

        let mut host: Option<String> = None;

        if resource.starts_with("acct:") {
            let split: Vec<&str> = resource.split('@').collect();
            host = split.last().map(|s| s.to_string());
        } else if resource.starts_with("https://") {
            let url = validate_url(&resource)?;

            if let Some(host_str) = url.host_str() {
                host = match url.port() {
                    Some(port) => Some(host_str.to_string() + &format!(":{port}")),
                    None => Some(host_str.to_string()),
                }
            }
        }

        if host.is_none() {
            return Err(Box::new(OidcClientError::new_type_error(
                "given input was invalid",
                None,
            )));
        }

        let mut web_finger_url =
            Url::parse(&format!("https://{}/.well-known/webfinger", host.unwrap())).unwrap();

        let mut headers = HashMap::new();
        headers.insert("accept".to_string(), vec!["application/json".to_string()]);

        web_finger_url.set_query(Some(&format!(
            "resource={}&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer",
            urlencoding::encode(&resource)
        )));

        Ok(HttpRequest::new()
            .url(web_finger_url)
            .method(HttpMethod::GET)
            .headers(headers)
            .expect_bearer(false)
            .expect_status_code(200)
            .expect_body(true))
    }

    fn process_webfinger_response(response: HttpResponse) -> OidcReturnType<String> {
        let webfinger_response =
            match convert_json_to::<WebFingerResponse>(response.body.as_ref().unwrap()) {
                Ok(res) => res,
                Err(_) => {
                    return Err(Box::new(OidcClientError::new_op_error(
                        "invalid  webfinger response".to_string(),
                        None,
                        None,
                        Some(response),
                    )));
                }
            };

        let location_link_result = webfinger_response
            .links
            .iter()
            .find(|x| x.rel == "http://openid.net/specs/connect/1.0/issuer" && x.href.is_some());

        let expected_issuer = match location_link_result {
            Some(link) => link.href.as_ref().unwrap(),
            None => {
                return Err(Box::new(OidcClientError::new_rp_error(
                    "no issuer found in webfinger response",
                    Some(response),
                )));
            }
        };

        if !expected_issuer.starts_with("https://") {
            return Err(Box::new(OidcClientError::new_op_error(
                "invalid_location".to_string(),
                Some(format!("invalid issuer location {expected_issuer}")),
                None,
                Some(response),
            )));
        }

        Ok(expected_issuer.to_string())
    }

    fn process_webfinger_issuer_result(
        issuer_result: OidcReturnType<Issuer>,
        expected_issuer: String,
    ) -> OidcReturnType<Issuer> {
        let mut response = None;

        let issuer = match issuer_result {
            Ok(i) => i,
            Err(err) => {
                response = match err.as_ref() {
                    OidcClientError::Error(_, response) => response.as_ref(),
                    OidcClientError::TypeError(_, response) => response.as_ref(),
                    OidcClientError::RPError(_, response) => response.as_ref(),
                    OidcClientError::OPError(_, response) => response.as_ref(),
                };

                if let Some(error_res) = response {
                    if error_res.status_code == 404 {
                        return Err(Box::new(OidcClientError::new_op_error(
                            "no_issuer".to_string(),
                            Some(format!("invalid issuer location {expected_issuer}")),
                            None,
                            Some(error_res.clone()),
                        )));
                    }
                }

                return Err(err);
            }
        };

        if issuer.issuer != expected_issuer {
            return Err(Box::new(OidcClientError::new_op_error(
                "issuer_mismatch".to_string(),
                Some(format!(
                    "discovered issuer mismatch, expected {expected_issuer}, got: {}",
                    issuer.issuer
                )),
                None,
                response.map(|r| r.to_owned()),
            )));
        }

        Ok(issuer)
    }
}

/// New [Client] implementation for Issuer
impl Issuer {
    /// # Creates a client from the issuer
    /// This method creates a new [Client] from the issuer.
    /// A client metadata with a required `client_id` field is also required
    ///
    /// - `metadata` - [ClientMetadata]
    /// - `jwks` - The client jwks with private keys.
    /// - `client_options` - Client options.
    /// - `fapi` - Version of FAPI
    ///
    /// Note: If the [Issuer] already have a request interceptor and none was passed in through `interceptor`,
    ///       the interceptor from the [Issuer] is used.
    pub fn client(
        &self,
        metadata: ClientMetadata,
        jwks: Option<Jwks>,
        client_options: Option<ClientOptions>,
        fapi: Option<Fapi>,
    ) -> OidcReturnType<Client> {
        Client::jwks_only_private_keys_validation(jwks.as_ref())?;

        Client::from_internal(metadata, Some(self), jwks, client_options, fapi)
    }
}

impl Clone for Issuer {
    fn clone(&self) -> Self {
        Self {
            issuer: self.issuer.clone(),
            authorization_endpoint: self.authorization_endpoint.clone(),
            token_endpoint: self.token_endpoint.clone(),
            jwks_uri: self.jwks_uri.clone(),
            userinfo_endpoint: self.userinfo_endpoint.clone(),
            revocation_endpoint: self.revocation_endpoint.clone(),
            claims_parameter_supported: self.claims_parameter_supported,
            grant_types_supported: self.grant_types_supported.clone(),
            request_parameter_supported: self.request_parameter_supported,
            request_uri_parameter_supported: self.request_uri_parameter_supported,
            require_request_uri_registration: self.require_request_uri_registration,
            response_modes_supported: self.response_modes_supported.clone(),
            claim_types_supported: self.claim_types_supported.clone(),
            token_endpoint_auth_methods_supported: self
                .token_endpoint_auth_methods_supported
                .clone(),
            token_endpoint_auth_signing_alg_values_supported: self
                .token_endpoint_auth_signing_alg_values_supported
                .clone(),
            introspection_endpoint_auth_methods_supported: self
                .introspection_endpoint_auth_methods_supported
                .clone(),
            introspection_endpoint_auth_signing_alg_values_supported: self
                .introspection_endpoint_auth_signing_alg_values_supported
                .clone(),
            revocation_endpoint_auth_methods_supported: self
                .revocation_endpoint_auth_methods_supported
                .clone(),
            revocation_endpoint_auth_signing_alg_values_supported: self
                .revocation_endpoint_auth_signing_alg_values_supported
                .clone(),
            other_fields: self.other_fields.clone(),
            keystore: self.keystore.clone(),
            mtls_endpoint_aliases: self.mtls_endpoint_aliases.clone(),
            introspection_endpoint: self.introspection_endpoint.clone(),
            registration_endpoint: self.registration_endpoint.clone(),
            end_session_endpoint: self.end_session_endpoint.clone(),
            authorization_response_iss_parameter_supported: self
                .authorization_response_iss_parameter_supported,
            dpop_signing_alg_values_supported: self.dpop_signing_alg_values_supported.clone(),
            pushed_authorization_request_endpoint: self
                .pushed_authorization_request_endpoint
                .clone(),
            require_pushed_authorization_requests: self.require_pushed_authorization_requests,
            device_authorization_endpoint: self.device_authorization_endpoint.clone(),
            backchannel_token_delivery_modes_supported: self
                .backchannel_token_delivery_modes_supported
                .clone(),
            backchannel_authentication_endpoint: self.backchannel_authentication_endpoint.clone(),
            backchannel_authentication_request_signing_alg_values_supported: self
                .backchannel_authentication_request_signing_alg_values_supported
                .clone(),
            backchannel_user_code_parameter_supported: self
                .backchannel_user_code_parameter_supported,
            now,
        }
    }
}

impl Issuer {
    /// Gets the [IssuerMetadata] of the [Issuer]
    pub fn get_metadata(&self) -> IssuerMetadata {
        IssuerMetadata {
            issuer: self.issuer.clone(),
            authorization_endpoint: self.authorization_endpoint.clone(),
            device_authorization_endpoint: self.device_authorization_endpoint.clone(),
            token_endpoint: self.token_endpoint.clone(),
            jwks_uri: self.jwks_uri.clone(),
            userinfo_endpoint: self.userinfo_endpoint.clone(),
            revocation_endpoint: self.revocation_endpoint.clone(),
            end_session_endpoint: self.end_session_endpoint.clone(),
            registration_endpoint: self.registration_endpoint.clone(),
            introspection_endpoint: self.introspection_endpoint.clone(),
            token_endpoint_auth_methods_supported: self
                .token_endpoint_auth_methods_supported
                .clone(),
            token_endpoint_auth_signing_alg_values_supported: self
                .token_endpoint_auth_signing_alg_values_supported
                .clone(),
            introspection_endpoint_auth_methods_supported: self
                .introspection_endpoint_auth_methods_supported
                .clone(),
            introspection_endpoint_auth_signing_alg_values_supported: self
                .introspection_endpoint_auth_signing_alg_values_supported
                .clone(),
            revocation_endpoint_auth_methods_supported: self
                .revocation_endpoint_auth_methods_supported
                .clone(),
            revocation_endpoint_auth_signing_alg_values_supported: self
                .revocation_endpoint_auth_signing_alg_values_supported
                .clone(),
            mtls_endpoint_aliases: self.mtls_endpoint_aliases.clone(),
            authorization_response_iss_parameter_supported: self
                .authorization_response_iss_parameter_supported,
            dpop_signing_alg_values_supported: self.dpop_signing_alg_values_supported.clone(),
            pushed_authorization_request_endpoint: self
                .pushed_authorization_request_endpoint
                .clone(),
            require_pushed_authorization_requests: self.require_pushed_authorization_requests,
            backchannel_token_delivery_modes_supported: self
                .backchannel_token_delivery_modes_supported
                .clone(),
            backchannel_authentication_endpoint: self.backchannel_authentication_endpoint.clone(),
            backchannel_authentication_request_signing_alg_values_supported: self
                .backchannel_authentication_request_signing_alg_values_supported
                .clone(),
            backchannel_user_code_parameter_supported: Some(
                self.backchannel_user_code_parameter_supported,
            ),
            other_fields: self.other_fields.clone(),
        }
    }

    /// Get Jwks
    pub async fn get_jwks<T>(&mut self, http_client: &T) -> Option<Jwks>
    where
        T: OidcHttpClient,
    {
        if let Some(ks) = &mut self.keystore {
            return ks.get_keystore_async(false, http_client).await.ok();
        }

        None
    }
}

#[cfg(test)]
#[path = "../tests/issuer/mod.rs"]
mod issuer_tests;
