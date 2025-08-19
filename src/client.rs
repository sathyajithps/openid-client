use std::{collections::HashMap, str::FromStr};

use serde_json::Value;
use url::Url;

use crate::{
    client_utils::{
        authorization_code::{
            self, validate_access_token_response, validate_auth_code_oauth_response,
            validate_auth_code_openid_response, validate_auth_response, validate_hybrid_response,
            validate_implicit_response,
        },
        jwt::{validate_jwt, JwtValidationParameters},
    },
    config::{ClientAuth, DPoPOptions, OpenIdClientConfiguration},
    defaults::Crypto,
    errors::{OidcReturn, OpenIdError},
    helpers::{
        base64_url_encode, deserialize, generate_random, unix_timestamp, url_decode,
        webfinger_normalize,
    },
    http::Http,
    jwk::{Jwk, JwksResponse},
    token_set::TokenSet,
    types::{
        http_client::{HttpMethod, HttpRequest, HttpResponse, OidcHttpClient, RequestBody},
        AuthMethods, AuthenticatedEndpoints, AuthorizationCodeGrantParameters,
        AuthorizationParameters, CibaAuthRequest, CibaAuthResponse, ClientRegistrationRequest,
        ClientRegistrationResponse, DeviceAuthorizationRequest, DeviceAuthorizationResponse,
        EndSessionParameters, Header, ImplicitGrantParameters, IssuerMetadata, JwtSigningAlg,
        OpenIdCrypto, OpenIdResponseType, Payload, PushedAuthorizationResponse,
        UserinfoTokenLocation, WebFingerResponse,
    },
};

/// # Client
/// Represents the Client
pub struct Client;

impl Client {
    /// # Discover OIDC Issuer
    ///
    /// Discover an OIDC Issuer using the issuer url.
    ///
    /// - `issuer` - The issuer url (absolute).
    /// - `http_client` - The http client used to make the request.
    pub async fn discover_oidc_async<T: OidcHttpClient>(
        issuer: &str,
        http_client: &T,
    ) -> OidcReturn<IssuerMetadata> {
        let mut request = HttpRequest::new();

        let base_url =
            Url::parse(issuer).map_err(|_| OpenIdError::new_error("Invalid Issuer Url"))?;

        let well_known_path = format!(
            "{}/.well-known/openid-configuration",
            base_url.path().trim_end_matches('/')
        );
        request.url = base_url;
        request.url.set_path(&well_known_path);

        let res = Http::default().request_async(request, http_client).await?;

        if let Some(body) = res.body {
            return match deserialize::<IssuerMetadata>(&body) {
                Ok(metadata) => {
                    let expected = issuer.trim_end_matches('/');
                    let actual = metadata.issuer.trim_end_matches('/');
                    if actual != expected {
                        return Err(OpenIdError::new_error(format!(
                            "discovered issuer mismatch, expected {}, got: {}",
                            issuer, metadata.issuer
                        )));
                    }
                    Ok(metadata)
                }
                Err(_) => Err(OpenIdError::new_error(
                    "invalid_issuer_metadata".to_string(),
                )),
            };
        }

        Err(OpenIdError::new_error("Response does not have a body."))
    }

    /// # Discover OAuth Issuer
    ///
    /// Discover an OAuth Issuer using the issuer url.
    ///
    /// - `issuer` - The issuer url (absolute).
    /// - `http_client` - The http client used to make the request.
    pub async fn discover_oauth_async<T: OidcHttpClient>(
        issuer: &str,
        http_client: &T,
    ) -> OidcReturn<IssuerMetadata> {
        let mut request = HttpRequest::new();

        let base_url =
            Url::parse(issuer).map_err(|_| OpenIdError::new_error("Invalid Issuer Url"))?;

        let well_known_path = format!(
            "{}/.well-known/oauth-authorization-server",
            base_url.path().trim_end_matches('/')
        );
        request.url = base_url;
        request.url.set_path(&well_known_path);

        let res = Http::default().request_async(request, http_client).await?;

        if let Some(body) = res.body {
            return match deserialize::<IssuerMetadata>(&body) {
                Ok(metadata) => {
                    let expected = issuer.trim_end_matches('/');
                    let actual = metadata.issuer.trim_end_matches('/');
                    if actual != expected {
                        return Err(OpenIdError::new_error(format!(
                            "discovered issuer mismatch, expected {}, got: {}",
                            issuer, metadata.issuer
                        )));
                    }
                    Ok(metadata)
                }
                Err(_) => Err(OpenIdError::new_error(
                    "invalid_authorization_server_metadata".to_string(),
                )),
            };
        }

        Err(OpenIdError::new_error("Response does not have a body."))
    }

    /// # Fetch Issuer Jwks
    ///
    /// Fetches Issuer Json Web Key Set from `jwks_uri`.
    ///
    /// - `issuer` - The issuer metadata.
    /// - `http_client` - The http client to make the request.
    pub async fn fetch_issuer_jwks<H: OidcHttpClient>(
        issuer: &IssuerMetadata,
        http_client: &H,
    ) -> OidcReturn<Vec<Jwk>> {
        match &issuer.jwks_uri {
            Some(jwks_uri) => {
                let request = HttpRequest::new()
                    .url(Url::parse(jwks_uri).map_err(|e| OpenIdError::new_error(e.to_string()))?)
                    .expect_json(true)
                    .method(HttpMethod::GET)
                    .expect_status_code(200);

                let response = Http::default().request_async(request, http_client).await?;

                match response.body {
                    Some(raw_body) => {
                        let jwks_response = deserialize::<JwksResponse>(&raw_body)
                            .map_err(OpenIdError::new_error)?;
                        Ok(jwks_response.keys)
                    }
                    None => Err(OpenIdError::new_error("JWKS response empty")),
                }
            }
            None => Err(OpenIdError::new_error(
                "jwks_uri not found in the issuer metadata",
            )),
        }
    }

    /// # WebFinger OIDC Issuer Discovery
    ///
    /// Discover an OIDC Issuer using the user email, url, url with port syntax or acct syntax.
    ///
    /// - `resource` - The resource.
    /// - `http_client` - The http client to make the request.
    pub async fn webfinger_async<T: OidcHttpClient>(
        resource: &str,
        http_client: &T,
    ) -> OidcReturn<IssuerMetadata> {
        let resource = webfinger_normalize(resource);

        let mut host: Option<String> = None;

        if resource.starts_with("acct:") {
            let split: Vec<&str> = resource.split('@').collect();
            host = split.last().map(|s| s.to_string());
        } else if resource.starts_with("https://") {
            let url =
                Url::from_str(&resource).map_err(|e| OpenIdError::new_error(e.to_string()))?;

            if let Some(host_str) = url.host_str() {
                host = match url.port() {
                    Some(port) => Some(host_str.to_string() + &format!(":{port}")),
                    None => Some(host_str.to_string()),
                }
            }
        }

        if host.is_none() {
            return Err(OpenIdError::new_error("given input was invalid"));
        }

        let mut web_finger_url =
            Url::parse(&format!("https://{}/.well-known/webfinger", host.unwrap())).unwrap();

        let mut headers = HashMap::new();
        headers.insert("accept".to_string(), vec!["application/json".to_string()]);

        web_finger_url.set_query(Some(&format!(
            "resource={}&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer",
            urlencoding::encode(&resource)
        )));

        let request = HttpRequest::new()
            .url(web_finger_url)
            .method(HttpMethod::GET)
            .headers(headers);

        let response = Http::default().request_async(request, http_client).await?;

        let body = response
            .body
            .as_ref()
            .ok_or_else(|| OpenIdError::new_error("webfinger response body is empty"))?;

        let webfinger_response = match deserialize::<WebFingerResponse>(body) {
            Ok(res) => res,
            Err(_) => {
                return Err(OpenIdError::new_error(
                    "invalid_webfinger_response".to_string(),
                ));
            }
        };

        let location_link_result = webfinger_response
            .links
            .iter()
            .find(|x| x.rel == "http://openid.net/specs/connect/1.0/issuer" && x.href.is_some());

        let expected_issuer = match location_link_result.and_then(|l| l.href.as_ref()) {
            Some(iss) => iss,
            _ => {
                return Err(OpenIdError::new_error(
                    "No issuer found in webfinger response",
                ));
            }
        };

        if !expected_issuer.starts_with("https://") {
            return Err(OpenIdError::new_error(format!(
                "invalid issuer location {expected_issuer}"
            )));
        }

        let issuer_metadata = Client::discover_oidc_async(expected_issuer, http_client).await?;

        if &issuer_metadata.issuer != expected_issuer {
            return Err(OpenIdError::new_error(format!(
                "discovered issuer mismatch, expected {expected_issuer}, got: {}",
                issuer_metadata.issuer
            )));
        }

        Ok(issuer_metadata)
    }

    /// # Authorization Url
    /// Builds an authorization url with respect to the `authorization_parameters`.
    ///
    /// - `config` - Openid client configuration.
    /// - `authorization_parameters` - [AuthorizationParameters]: Customize the authorization request.
    pub fn authorization_url(
        config: &OpenIdClientConfiguration,
        mut authorization_parameters: AuthorizationParameters,
    ) -> OidcReturn<String> {
        let mut authorization_endpoint = config.authorization_endpoint()?;

        if authorization_parameters.client_id.is_none() {
            authorization_parameters.client_id = Some(config.client.client_id.to_owned());
        }

        let authorization_parameters_map: HashMap<String, String> = authorization_parameters.into();

        authorization_endpoint
            .query_pairs_mut()
            .extend_pairs(authorization_parameters_map);

        Ok(authorization_endpoint.to_string())
    }

    /// # End Session Url
    /// Builds an endsession url with respect to the `end_session_parameters`.
    ///
    /// - `config` - Openid client configuration.
    /// - `end_session_parameters` - [EndSessionParameters]: Customize the endsession url.
    pub fn endsession_url(
        config: &OpenIdClientConfiguration,
        mut end_session_parameters: EndSessionParameters,
    ) -> OidcReturn<String> {
        let mut end_session_endpoint = config.end_session_endpoint()?;

        if end_session_parameters.client_id.is_none() {
            end_session_parameters.client_id = Some(config.client.client_id.to_owned());
        }

        {
            let mut query_params = end_session_endpoint.query_pairs_mut();

            if let Some(client_id) = end_session_parameters.client_id {
                query_params.append_pair("client_id", &client_id);
            }

            if let Some(post_logout_redirect_uri) = end_session_parameters
                .post_logout_redirect_uri
                .or_else(|| config.client.post_logout_redirect_uri.clone())
            {
                query_params.append_pair("post_logout_redirect_uri", &post_logout_redirect_uri);
            }

            if let Some(state) = end_session_parameters.state {
                query_params.append_pair("state", &state);
            }

            if let Some(id_token_hint) = end_session_parameters.id_token_hint {
                query_params.append_pair("id_token_hint", &id_token_hint);
            }

            if let Some(logout_hint) = end_session_parameters.logout_hint {
                query_params.append_pair("logout_hint", &logout_hint);
            }
        }

        Ok(end_session_endpoint.to_string())
    }

    /// # Authorization Post
    /// Builds an authorization post page with respect to the `authorization_parameters`.
    ///
    /// - `config` - Openid client configuration.
    /// - `authorization_parameters` - [AuthorizationParameters]: Customize the authorization request.
    pub fn authorization_post(
        config: &OpenIdClientConfiguration,
        mut authorization_parameters: AuthorizationParameters,
    ) -> OidcReturn<String> {
        let authorization_endpoint = config.authorization_endpoint()?;

        if authorization_parameters.client_id.is_none() {
            authorization_parameters.client_id = Some(config.client.client_id.to_owned());
        }

        let authorization_parameters_map: HashMap<String, String> = authorization_parameters.into();

        let mut html = r#"<!DOCTYPE html>
        <head>
        <title>Requesting Authorization</title>
        </head>
        <body onload="javascript:document.forms[0].submit()">
        <form method="post" action=""#
            .to_string()
            + authorization_endpoint.as_ref()
            + r#"">"#
            + "\n";

        for (param, value) in authorization_parameters_map {
            let escaped_param = html_escape(&param);
            let escaped_value = html_escape(&value);
            html = html
                + r#"<input type="hidden" name=""#
                + &escaped_param
                + r#"" value=""#
                + &escaped_value
                + r#""/>"#
                + "\n";
        }

        html += r#"</form>
        </body>
        </html>"#;

        Ok(html)
    }

    /// # Token Grant
    /// Performs a grant at the token endpoint.
    ///
    /// - `config` - Openid client configuration.
    /// - `body` - Grant request body.
    /// - `http_client` - The http client to make the request.
    /// - `dpop_options` - Optional DPoP options for the request.
    pub async fn grant_async<H: OidcHttpClient>(
        config: &OpenIdClientConfiguration,
        body: RequestBody,
        http_client: &H,
        dpop_options: Option<&DPoPOptions>,
    ) -> OidcReturn<TokenSet> {
        if !matches!(body, RequestBody::Form(_)) {
            return Err(OpenIdError::new_error(
                "grant_async() only supports form url encoded body.",
            ));
        }

        let response = authenticated_post_async(
            config,
            AuthenticatedEndpoints::Token,
            body,
            http_client,
            dpop_options,
        )
        .await?;

        let body = response
            .body
            .ok_or(OpenIdError::new_error("body expected in grant response"))?;

        deserialize::<TokenSet>(&body).or(Err(OpenIdError::new_error(
            "could not convert body to TokenSet",
        )))
    }

    /// # Authorization Code Grant
    ///
    /// Performs authorization code grant on the token endpoint.
    ///
    /// - `config` - Openid client configuration.
    /// - `http_client` - The http client to make the request.
    /// - `callback_request` - The callback request received from the provider.
    /// - `parameters` - [AuthorizationCodeGrantParameters]: Parameters for the authorization code grant.
    /// - `dpop_options` - Optional DPoP options for the request.
    pub async fn authorization_code_grant<H: OidcHttpClient>(
        config: &OpenIdClientConfiguration,
        http_client: &H,
        callback_request: HttpRequest,
        parameters: AuthorizationCodeGrantParameters,
        dpop_options: Option<&DPoPOptions>,
    ) -> OidcReturn<TokenSet> {
        let callback_params = match callback_request.method {
            HttpMethod::GET => match config.response_type {
                OpenIdResponseType::Hybrid => {
                    let fragment = callback_request
                        .url
                        .fragment()
                        .ok_or(OpenIdError::new_error("fragment not found"))?;
                    url_decode(fragment)
                }
                OpenIdResponseType::Implicit => {
                    return Err(OpenIdError::new_error("unsupported response type"))
                }
                // Support fragment.jwt?
                OpenIdResponseType::Jarm | OpenIdResponseType::Code => callback_request
                    .url
                    .query_pairs()
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .collect(),
            },
            HttpMethod::POST => match callback_request.body {
                Some(RequestBody::Form(body)) => body,
                _ => return Err(OpenIdError::new_error("Body not found/incorrect format")),
            },
            _ => return Err(OpenIdError::new_error("unexpected Request HTTP method")),
        };

        let callback_params = match config.response_type {
            OpenIdResponseType::Jarm => {
                authorization_code::validate_jarm(config, callback_params, parameters.state_check)?
            }
            OpenIdResponseType::Hybrid => validate_hybrid_response(
                config,
                callback_params,
                parameters.state_check,
                parameters.nonce_check.clone(),
                parameters.max_age_check.clone(),
            )?,
            OpenIdResponseType::Implicit => {
                return Err(OpenIdError::new_error("unsupported response type"))
            }
            OpenIdResponseType::Code => authorization_code::validate_auth_response(
                &config.issuer.issuer,
                config
                    .issuer
                    .authorization_response_iss_parameter_supported
                    .is_some_and(|s| s),
                callback_params,
                parameters.state_check,
            )?,
        };

        let code = callback_params.get("code").ok_or(OpenIdError::new_error(
            "no authorization code in \"callback_params\"",
        ))?;

        if code.is_empty() {
            return Err(OpenIdError::new_error(
                "authorization code in \"callback_params\" is empty",
            ));
        }

        let mut token_request_params = HashMap::new();
        token_request_params.extend(parameters.additional_parameters);
        token_request_params.insert("grant_type".to_owned(), "authorization_code".to_owned());
        token_request_params.insert("code".to_owned(), code.to_owned());
        token_request_params.insert("redirect_uri".to_owned(), parameters.redirect_uri);
        if let Some(code_verifier) = parameters.pkce_code_verifier {
            token_request_params.insert("code_verifier".to_owned(), code_verifier);
        }

        let tokenset = Client::grant_async(
            config,
            RequestBody::Form(token_request_params),
            http_client,
            dpop_options,
        )
        .await?;

        match (
            &parameters.nonce_check,
            &parameters.max_age_check,
            parameters.expect_id_token,
        ) {
            (Some(_), Some(_), _)
            | (Some(_), None, _)
            | (None, Some(_), _)
            | (None, None, true) => validate_auth_code_openid_response(
                config,
                tokenset,
                parameters.nonce_check.ok_or(OpenIdError::new_error(
                    "nonce_check is required for openid auth code validation",
                ))?,
                parameters.max_age_check,
            ),
            (None, None, false) => validate_auth_code_oauth_response(config, tokenset),
        }
    }

    /// # Implicit Code Grant
    ///
    /// Validates the returned access token and/or id token.
    ///
    /// - `config` - Openid client configuration.
    /// - `callback_request` - The callback request received from the provider.
    /// - `parameters` - [ImplicitGrantParameters]: Parameters for the implicit grant.
    pub async fn implicit_authentication<H: OidcHttpClient>(
        config: &OpenIdClientConfiguration,
        callback_request: HttpRequest,
        parameters: ImplicitGrantParameters,
    ) -> OidcReturn<TokenSet> {
        let mut callback_params = match callback_request.method {
            HttpMethod::GET => match config.response_type {
                OpenIdResponseType::Hybrid => {
                    return Err(OpenIdError::new_error("unsupported response type"))
                }
                OpenIdResponseType::Implicit => {
                    let fragment = callback_request
                        .url
                        .fragment()
                        .ok_or(OpenIdError::new_error("fragment not found"))?;
                    url_decode(fragment)
                }
                OpenIdResponseType::Jarm | OpenIdResponseType::Code => {
                    return Err(OpenIdError::new_error("unsupported response type"))
                }
            },
            HttpMethod::POST => match callback_request.body {
                Some(RequestBody::Form(body)) => body,
                _ => return Err(OpenIdError::new_error("Body not found/incorrect format")),
            },
            _ => return Err(OpenIdError::new_error("unexpected Request HTTP method")),
        };

        let id_token = callback_params.get("id_token").cloned();
        callback_params.remove("id_token");

        let access_token = callback_params.get("access_token").cloned();
        callback_params.remove("access_token");

        let callback_params = match config.response_type {
            OpenIdResponseType::Code | OpenIdResponseType::Jarm | OpenIdResponseType::Hybrid => {
                return Err(OpenIdError::new_error("unsupported response type"))
            }
            OpenIdResponseType::Implicit => validate_auth_response(
                &config.issuer.issuer,
                false,
                callback_params,
                parameters.state_check,
            )?,
        };

        let tokenset = TokenSet {
            access_token,
            id_token,
            expires_in: callback_params
                .get("expires_in")
                .and_then(|ei| ei.parse::<u64>().ok()),
            scope: callback_params.get("scope").cloned(),
            token_type: callback_params.get("token_type").cloned(),
            ..Default::default()
        };

        if parameters.expect_id_token && tokenset.id_token.is_none() {
            return Err(OpenIdError::new_error(
                "expected id_token in implicit response but none was returned",
            ));
        }

        let has_id_token = tokenset.id_token.is_some();

        validate_implicit_response(
            config,
            tokenset,
            has_id_token,
            parameters.nonce_check,
            parameters.max_age_check,
        )
    }

    /// # Refresh Token Grant
    ///
    /// Performs a refresh token grant.
    ///
    /// - `config` - Openid client configuration.
    /// - `http_client` - The http client to make the request.
    /// - `refresh_token` - The refresh token.
    /// - `additional_parameters` - Optional additional parameters for the grant.
    /// - `dpop_options` - Optional DPoP options for the request.
    pub async fn refresh_grant<H: OidcHttpClient>(
        config: &OpenIdClientConfiguration,
        http_client: &H,
        refresh_token: &str,
        additional_parameters: Option<HashMap<String, String>>,
        dpop_options: Option<&DPoPOptions>,
    ) -> OidcReturn<TokenSet> {
        let mut refresh_grant_params = HashMap::new();
        if let Some(additional_parameters) = additional_parameters {
            refresh_grant_params.extend(additional_parameters);
        }
        refresh_grant_params.insert("grant_type".to_owned(), "refresh_token".to_owned());
        refresh_grant_params.insert("refresh_token".to_owned(), refresh_token.to_owned());

        let tokenset = Client::grant_async(
            config,
            RequestBody::Form(refresh_grant_params),
            http_client,
            dpop_options,
        )
        .await?;

        validate_access_token_response(config, tokenset, &[], true)
    }

    /// # Pushed Authorization Request
    ///
    /// Performs a pushed authorization request.
    ///
    /// - `config` - Openid client configuration.
    /// - `http_client` - The http client to make the request.
    /// - `authorization_parameters` - [AuthorizationParameters]: Customize the authorization request.
    /// - `dpop_options` - Optional DPoP options for the request.
    pub async fn pushed_authorization_request<H: OidcHttpClient>(
        config: &OpenIdClientConfiguration,
        http_client: &H,
        mut authorization_parameters: AuthorizationParameters,
        dpop_options: Option<&DPoPOptions>,
    ) -> OidcReturn<PushedAuthorizationResponse> {
        if authorization_parameters.client_id.is_none() {
            authorization_parameters.client_id = Some(config.client.client_id.to_owned());
        }

        let authorization_parameters_map: HashMap<String, String> = authorization_parameters.into();

        let response = authenticated_post_async(
            config,
            AuthenticatedEndpoints::PushedAuthorization,
            RequestBody::Form(authorization_parameters_map),
            http_client,
            dpop_options,
        )
        .await?;

        let body = response
            .body
            .ok_or(OpenIdError::new_error("body expected in PAR response"))?;

        deserialize::<PushedAuthorizationResponse>(&body).or(Err(OpenIdError::new_error(
            "could not convert body to PushedAuthorizationResponse",
        )))
    }

    /// # Device Authorization Request
    ///
    /// Performs a device authorization request as defined in RFC 8628.
    /// Returns the device authorization response containing the `device_code` and `user_code`.
    ///
    /// - `config` - OpenID client configuration.
    /// - `http_client` - The HTTP client to make the request.
    /// - `request` - [DeviceAuthorizationRequest]: Device authorization request parameters.
    /// - `additional_parameters` - Optional additional parameters for the request.
    /// - `dpop_options` - Optional DPoP options for the request.
    pub async fn device_authorization_request<H: OidcHttpClient>(
        config: &OpenIdClientConfiguration,
        http_client: &H,
        request: DeviceAuthorizationRequest,
        additional_parameters: Option<HashMap<String, String>>,
        dpop_options: Option<&DPoPOptions>,
    ) -> OidcReturn<DeviceAuthorizationResponse> {
        let mut device_auth_parameters: HashMap<String, String> = HashMap::new();

        if let Some(additional_parameters) = additional_parameters {
            device_auth_parameters.extend(additional_parameters);
        }

        if request.client_id.is_none() {
            device_auth_parameters
                .insert("client_id".to_owned(), config.client.client_id.to_owned());
        }

        device_auth_parameters.extend::<HashMap<String, String>>(request.into());

        let response = authenticated_post_async(
            config,
            AuthenticatedEndpoints::DeviceAuthorization,
            RequestBody::Form(device_auth_parameters),
            http_client,
            dpop_options,
        )
        .await?;

        let body = response.body.ok_or(OpenIdError::new_error(
            "body expected in device authorization response",
        ))?;

        deserialize::<DeviceAuthorizationResponse>(&body).or(Err(OpenIdError::new_error(
            "could not convert body to DeviceAuthorizationResponse",
        )))
    }

    /// # Device Code Grant
    ///
    /// Performs a device code grant.
    ///
    /// - `config` - OpenID client configuration.
    /// - `http_client` - The HTTP client to make the request.
    /// - `device_code` - The device code.
    /// - `additional_parameters` - Optional additional parameters for the grant.
    /// - `dpop_options` - Optional DPoP options for the request.
    pub async fn device_code_grant<H: OidcHttpClient>(
        config: &OpenIdClientConfiguration,
        http_client: &H,
        device_code: &str,
        additional_parameters: Option<HashMap<String, String>>,
        dpop_options: Option<&DPoPOptions>,
    ) -> OidcReturn<TokenSet> {
        let mut device_code_grant_params = HashMap::new();
        if let Some(additional_parameters) = additional_parameters {
            device_code_grant_params.extend(additional_parameters);
        }
        device_code_grant_params.insert(
            "grant_type".to_owned(),
            "urn:ietf:params:oauth:grant-type:device_code".to_owned(),
        );
        device_code_grant_params.insert("device_code".to_owned(), device_code.to_owned());

        let tokenset = Client::grant_async(
            config,
            RequestBody::Form(device_code_grant_params),
            http_client,
            dpop_options,
        )
        .await?;

        validate_access_token_response(config, tokenset, &[], true)
    }

    /// # Client Credentials Grant
    ///
    /// Performs client credentials grant.
    ///
    /// - `config` - OpenID client configuration.
    /// - `http_client` - The HTTP client to make the request.
    /// - `additional_parameters` - Optional additional parameters for the grant.
    /// - `dpop_options` - Optional DPoP options for the request.
    pub async fn client_credentials_grant<H: OidcHttpClient>(
        config: &OpenIdClientConfiguration,
        http_client: &H,
        additional_parameters: Option<HashMap<String, String>>,
        dpop_options: Option<&DPoPOptions>,
    ) -> OidcReturn<TokenSet> {
        let mut client_credentials_parameters = HashMap::new();
        if let Some(additional_parameters) = additional_parameters {
            client_credentials_parameters.extend(additional_parameters);
        }
        client_credentials_parameters
            .insert("grant_type".to_owned(), "client_credentials".to_owned());

        let tokenset = Client::grant_async(
            config,
            RequestBody::Form(client_credentials_parameters),
            http_client,
            dpop_options,
        )
        .await?;

        validate_access_token_response(config, tokenset, &[], true)
    }

    /// # CIBA Authentication
    ///
    /// Performs a Client Initiated Backchannel Authentication (CIBA) request.
    /// Returns the CIBA authentication response containing the `auth_req_id`.
    ///
    /// - `config` - OpenID client configuration.
    /// - `http_client` - The HTTP client to make the request.
    /// - `request` - [CibaAuthRequest]: CIBA authentication request parameters.
    /// - `additional_parameters` - Optional additional parameters for the request.
    /// - `dpop_options` - Optional DPoP options for the request.
    pub async fn ciba_authentication<H: OidcHttpClient>(
        config: &OpenIdClientConfiguration,
        http_client: &H,
        request: CibaAuthRequest,
        additional_parameters: Option<HashMap<String, String>>,
        dpop_options: Option<&DPoPOptions>,
    ) -> OidcReturn<CibaAuthResponse> {
        let hint_count = [
            request.login_hint.is_some(),
            request.login_hint_token.is_some(),
            request.id_token_hint.is_some(),
        ]
        .iter()
        .filter(|&&h| h)
        .count();

        if hint_count != 1 {
            return Err(OpenIdError::new_error(
                "exactly one of login_hint, login_hint_token, or id_token_hint must be provided",
            ));
        }

        let mut ciba_parameters: HashMap<String, String> = HashMap::new();

        if let Some(additional_parameters) = additional_parameters {
            ciba_parameters.extend(additional_parameters);
        }

        if request.scope.is_empty() {
            return Err(OpenIdError::new_error("scope is required for CIBA request"));
        }

        ciba_parameters.extend::<HashMap<String, String>>(request.into());

        ciba_parameters.insert("client_id".to_owned(), config.client.client_id.to_owned());

        let response = authenticated_post_async(
            config,
            AuthenticatedEndpoints::BackChannelAuthentication,
            RequestBody::Form(ciba_parameters),
            http_client,
            dpop_options,
        )
        .await?;

        let body = response.body.ok_or(OpenIdError::new_error(
            "body expected in CIBA authentication response",
        ))?;

        let ciba_response = deserialize::<CibaAuthResponse>(&body)
            .map_err(|_| OpenIdError::new_error("could not convert body to CibaAuthResponse"))?;

        if ciba_response.auth_req_id.is_empty() {
            return Err(OpenIdError::new_client_error(
                "expected auth_req_id in CIBA Successful Response",
            ));
        }

        Ok(ciba_response)
    }

    /// # CIBA Grant
    ///
    /// Performs a CIBA token grant using the `auth_req_id` from a previous CIBA authentication.
    /// This method is used to poll for the token after the user has authenticated.
    ///
    /// - `config` - OpenID client configuration.
    /// - `http_client` - The HTTP client to make the request.
    /// - `auth_req_id` - The authentication request ID from CIBA authentication response.
    /// - `additional_parameters` - Optional additional parameters for the grant.
    /// - `dpop_options` - Optional DPoP options for the request.
    pub async fn ciba_grant<H: OidcHttpClient>(
        config: &OpenIdClientConfiguration,
        http_client: &H,
        auth_req_id: &str,
        additional_parameters: Option<HashMap<String, String>>,
        dpop_options: Option<&DPoPOptions>,
    ) -> OidcReturn<TokenSet> {
        let mut ciba_grant_params = HashMap::new();

        if let Some(additional_parameters) = additional_parameters {
            ciba_grant_params.extend(additional_parameters);
        }

        ciba_grant_params.insert(
            "grant_type".to_owned(),
            "urn:openid:params:grant-type:ciba".to_owned(),
        );

        ciba_grant_params.insert("auth_req_id".to_owned(), auth_req_id.to_owned());

        let tokenset = Client::grant_async(
            config,
            RequestBody::Form(ciba_grant_params),
            http_client,
            dpop_options,
        )
        .await?;

        validate_access_token_response(config, tokenset, &[], true)
    }

    /// # Introspection
    ///
    /// Performs an introspection request at Issuer's `introspection_endpoint`.
    ///
    /// - `config` - OpenID client configuration.
    /// - `http_client` - The HTTP client to make the request.
    /// - `token` - The token to introspect.
    /// - `token_type_hint` - Hint to which type of token is being introspected.
    /// - `additional_parameters` - Optional additional parameters for the introspection request.
    /// - `dpop_options` - Optional DPoP options for the request.
    pub async fn introspect_async<H: OidcHttpClient>(
        config: &OpenIdClientConfiguration,
        http_client: &H,
        token: &str,
        token_type_hint: Option<&str>,
        additional_parameters: Option<HashMap<String, String>>,
        dpop_options: Option<&DPoPOptions>,
    ) -> OidcReturn<HttpResponse> {
        let mut introspect_params = HashMap::new();

        if let Some(additional_parameters) = additional_parameters {
            introspect_params.extend(additional_parameters);
        }

        introspect_params.insert("token".to_owned(), token.to_owned());

        if let Some(hint) = token_type_hint {
            introspect_params.insert("token_type_hint".to_owned(), hint.to_owned());
        }

        authenticated_post_async(
            config,
            AuthenticatedEndpoints::Introspection,
            RequestBody::Form(introspect_params),
            http_client,
            dpop_options,
        )
        .await
    }

    /// # Revoke Token
    ///
    /// Performs token revocation at the revocation endpoint (RFC 7009).
    ///
    /// - `config` - OpenID client configuration.
    /// - `http_client` - The HTTP client to make the request.
    /// - `token` - The token to be revoked (access_token or refresh_token).
    /// - `token_type_hint` - Optional hint about the token type ("access_token" or "refresh_token").
    /// - `additional_parameters` - Optional additional parameters for the revocation request.
    /// - `dpop_options` - Optional DPoP options for the request.
    pub async fn revoke_async<H: OidcHttpClient>(
        config: &OpenIdClientConfiguration,
        http_client: &H,
        token: &str,
        token_type_hint: Option<&str>,
        additional_parameters: Option<HashMap<String, String>>,
        dpop_options: Option<&DPoPOptions>,
    ) -> OidcReturn<()> {
        let mut revoke_params = HashMap::new();

        if let Some(additional_parameters) = additional_parameters {
            revoke_params.extend(additional_parameters);
        }

        revoke_params.insert("token".to_owned(), token.to_owned());

        if let Some(hint) = token_type_hint {
            revoke_params.insert("token_type_hint".to_owned(), hint.to_owned());
        }

        let _response = authenticated_post_async(
            config,
            AuthenticatedEndpoints::Revocation,
            RequestBody::Form(revoke_params),
            http_client,
            dpop_options,
        )
        .await?;

        Ok(())
    }

    /// # Request Resource
    ///
    /// Makes a resource request using an access token.
    ///
    /// - `config` - OpenID client configuration.
    /// - `http_client` - The HTTP client to make the request.
    /// - `resource_url` - The URL of the resource to request.
    /// - `access_token` - The access token to use for authorization.
    /// - `is_mtls` - Boolean to indicate if the request should use mTLS.
    /// - `method` - HTTP method (default: GET).
    /// - `headers` - Optional additional headers for the request.
    /// - `body` - Optional request body.
    /// - `dpop_options` - Optional DPoP options for the request.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_resource_async<H: OidcHttpClient>(
        config: &OpenIdClientConfiguration,
        http_client: &H,
        resource_url: Url,
        access_token: &str,
        is_mtls: bool,
        method: Option<HttpMethod>,
        headers: Option<HashMap<String, Vec<String>>>,
        body: Option<RequestBody>,
        dpop_options: Option<&DPoPOptions>,
    ) -> OidcReturn<HttpResponse> {
        if resource_url.scheme() != "https" && resource_url.scheme() != "https" {
            return Err(OpenIdError::new_error("Only http and https"));
        }

        let mut request_headers = headers.unwrap_or_default();

        if request_headers
            .iter()
            .any(|(k, _)| k.to_lowercase() == "authorization")
        {
            return Err(OpenIdError::new_error(
                "Authorization header must not be present",
            ));
        }

        // Note: We are setting the scheme to DPoP since a key is passed in.
        // If the request fails when DPoP options is passed in
        // check if the dpop header is being set properly
        let token_type = if dpop_options.is_some() {
            "DPoP"
        } else {
            "Bearer"
        };

        request_headers.insert(
            "authorization".to_string(),
            vec![format!("{} {}", token_type, access_token)],
        );

        let mut request = HttpRequest::new()
            .url(resource_url)
            .mtls(is_mtls)
            .method(method.unwrap_or(HttpMethod::GET))
            .headers(request_headers);

        if let Some(body) = body {
            request.body = Some(body);
        }

        let mut http_builder = Http::default()
            .set_config(config)
            .set_check_expectations(false)
            .set_access_token(access_token);

        if let Some(dpop_options) = dpop_options {
            http_builder = http_builder.set_dpop(
                dpop_options,
                config.issuer.dpop_signing_alg_values_supported.as_ref(),
                config.options.clock_skew,
            );
        }

        http_builder.request_async(request, http_client).await
    }

    /// # Userinfo
    ///
    /// Fetches user information from the userinfo endpoint.
    ///
    /// - `config` - OpenID client configuration
    /// - `http_client` - The HTTP client to make the request
    /// - `token_set` - TokenSet containing the access_token
    /// - `at_location` - Access token location
    /// - `method` - HTTP method (GET or POST, default: GET)
    /// - `additional_params` - Optional additional parameters
    /// - `dpop_options` - Optional DPoP options for the request.
    pub async fn userinfo_async<H: OidcHttpClient>(
        config: &OpenIdClientConfiguration,
        http_client: &H,
        token_set: &TokenSet,
        at_location: UserinfoTokenLocation,
        method: Option<HttpMethod>,
        additional_params: Option<HashMap<String, String>>,
        dpop_options: Option<&DPoPOptions>,
    ) -> OidcReturn<Value> {
        let access_token = token_set
            .access_token
            .as_ref()
            .ok_or_else(|| OpenIdError::new_error("access_token is required in token_set"))?;

        let method = method.unwrap_or(HttpMethod::GET);

        if !matches!(method, HttpMethod::GET | HttpMethod::POST) {
            return Err(OpenIdError::new_error(
                "userinfo method can only be GET or POST",
            ));
        }

        if matches!(at_location, UserinfoTokenLocation::Body) && !matches!(method, HttpMethod::POST)
        {
            return Err(OpenIdError::new_error(
                "can only send token via body on POST",
            ));
        }

        // Determine if JWT response is expected
        let expect_jwt = config.client.userinfo_signed_response_alg.is_some()
            || config.client.userinfo_encrypted_response_alg.is_some();

        // Determine endpoint URL (use mTLS if certificate-bound tokens)
        let mtls = config
            .client
            .tls_client_certificate_bound_access_tokens
            .is_some_and(|x| x);

        let mut url = if mtls {
            config
                .mtls_userinfo_endpoint()
                .or_else(|_| config.userinfo_endpoint())?
        } else {
            config.userinfo_endpoint()?
        };

        // Determine token type
        let token_type = if dpop_options.is_some() {
            "DPoP"
        } else {
            token_set.token_type.as_deref().unwrap_or("Bearer")
        };

        // Build headers
        let mut headers = HashMap::new();

        if expect_jwt {
            headers.insert("accept".to_string(), vec!["application/jwt".to_string()]);
        } else {
            headers.insert("accept".to_string(), vec!["application/json".to_string()]);
        }

        // Build request body and handle token delivery
        let mut form_body: HashMap<String, String> = HashMap::new();

        if at_location == UserinfoTokenLocation::Header {
            headers.insert(
                "authorization".to_string(),
                vec![format!("{} {}", token_type, access_token)],
            );
        } else {
            // Body
            headers.insert(
                "content-type".to_string(),
                vec!["application/x-www-form-urlencoded".to_string()],
            );
            form_body.insert("access_token".to_string(), access_token.to_owned());
        }

        // Handle additional params
        if let Some(params) = additional_params {
            match method {
                HttpMethod::GET => {
                    for (k, v) in params {
                        url.query_pairs_mut().append_pair(&k, &v);
                    }
                }
                HttpMethod::POST => {
                    for (k, v) in params {
                        form_body.insert(k, v);
                    }
                }
                _ => {}
            }
        }

        // Build request
        let mut request = HttpRequest::new()
            .url(url)
            .method(method)
            .headers(headers)
            .expect_json(!expect_jwt);

        // Enable bearer token error handling
        request.expectations.bearer = true;
        request.mtls = mtls;

        if !form_body.is_empty() {
            request.body = Some(RequestBody::Form(form_body));
        }

        let mut http_builder = Http::default()
            .set_config(config)
            .set_access_token(access_token);

        if let Some(dpop_options) = dpop_options {
            http_builder = http_builder.set_dpop(
                dpop_options,
                config.issuer.dpop_signing_alg_values_supported.as_ref(),
                config.options.clock_skew,
            );
        }

        let response = http_builder.request_async(request, http_client).await?;

        // Parse response
        let body = response
            .body
            .ok_or_else(|| OpenIdError::new_error("userinfo response body was empty"))?;

        let payload: Value = if expect_jwt {
            let jwt_params = JwtValidationParameters {
                signing_keys: &config.issuer_jwks,
                check_header_alg: true,
                issuer_algs: &config.issuer.userinfo_signing_alg_values_supported,
                client_algs: config
                    .client
                    .userinfo_signed_response_alg
                    .clone()
                    .map(|alg| vec![alg]),
                fallback_algs: Some(vec![JwtSigningAlg::RS256]),
                skew: config.options.clock_skew,
                tolerance: config.options.clock_tolerance,
            };

            let validated_jwt = validate_jwt(body, jwt_params, &config.jwe_keys)?;
            Value::Object(validated_jwt.payload.params)
        } else {
            deserialize::<Value>(&body)
                .map_err(|_| OpenIdError::new_error("failed to parse userinfo response as JSON"))?
        };

        // Per OpenID Connect Core Section 5.3.4: sub claim MUST always be present
        if payload.get("sub").is_none() {
            return Err(OpenIdError::new_error(
                "userinfo response is missing the required \"sub\" claim",
            ));
        }

        // Validate sub claim consistency with ID token
        if token_set.id_token.is_some() {
            if let Some(expected_sub) = token_set.claims().and_then(|c| c.get("sub").cloned()) {
                if let Some(actual_sub) = payload.get("sub") {
                    if expected_sub != *actual_sub {
                        return Err(OpenIdError::new_error(format!(
                            "userinfo sub mismatch, expected {}, got: {}",
                            expected_sub, actual_sub
                        )));
                    }
                }
            }
        }

        Ok(payload)
    }

    /// # Request Object
    ///
    /// Creates a JWT-secured Authorization Request (JAR - RFC 9101).
    /// The returned JWT can be used as the `request` parameter in authorization requests.
    ///
    /// - `config` - OpenID client configuration
    /// - `request_object` - The request object claims as a JSON Value (must be an object)
    ///
    /// Note: Encryption is not yet supported. Only signing is implemented.
    pub fn request_object(
        config: &OpenIdClientConfiguration,
        mut request_object: Value,
    ) -> OidcReturn<String> {
        if !request_object.is_object() {
            return Err(OpenIdError::new_error(
                "request_object must be a plain object",
            ));
        }

        // Get signing algorithm
        let alg = config
            .client
            .request_object_signing_alg
            .as_ref()
            .map(jwt_signing_alg_to_string)
            .unwrap_or_else(|| "none".to_string());

        let typ = "oauth-authz-req+jwt";

        let now = unix_timestamp();

        // Add standard claims
        request_object["iss"] = Value::String(config.client.client_id.clone());
        request_object["aud"] = Value::String(config.issuer.issuer.clone());
        request_object["client_id"] = Value::String(config.client.client_id.clone());
        request_object["jti"] = Value::String(generate_random(None));
        request_object["iat"] = Value::Number(now.into());
        request_object["exp"] = Value::Number((now + 300).into());

        // Add nbf for FAPI clients
        if config.fapi {
            request_object["nbf"] = Value::Number(now.into());
        }

        let payload_str = request_object.to_string();

        // Handle unsigned JWT (alg = none)
        if alg == "none" {
            let header = format!("{{\"alg\":\"none\",\"typ\":\"{}\"}}", typ);
            let encoded_header = base64_url_encode(&header);
            let encoded_payload = base64_url_encode(&payload_str);
            return Ok(format!("{}.{}.", encoded_header, encoded_payload));
        }

        // Get signing key based on algorithm
        let (jwk, include_kid) = if alg.starts_with("HS") {
            // Symmetric algorithm - need client secret
            let secret = get_client_secret(config)?;
            (Jwk::from_symmetric_key(secret.as_bytes()), false)
        } else {
            // Asymmetric algorithm - need private key from config.auth
            match &config.auth {
                ClientAuth::PrivateKeyJwt { jwk, .. } => (jwk.clone(), true),
                _ => {
                    return Err(OpenIdError::new_error(format!(
                        "no private key available for signing with algorithm {}",
                        alg
                    )));
                }
            }
        };

        // Build header
        let mut header_params = serde_json::Map::new();
        header_params.insert("alg".to_string(), Value::String(alg.clone()));
        header_params.insert("typ".to_string(), Value::String(typ.to_string()));

        if include_kid {
            if let Some(kid) = jwk.get_param("kid").and_then(|v| v.as_str()) {
                header_params.insert("kid".to_string(), Value::String(kid.to_string()));
            }
        }

        let header = Header {
            params: header_params,
        };

        let payload = Payload {
            params: request_object.as_object().cloned().unwrap_or_default(),
        };

        // Sign the JWT
        let signed = Crypto
            .jws_serialize(payload, header, &jwk)
            .map_err(|e| OpenIdError::new_error(format!("failed to sign request object: {}", e)))?;

        // Check if encryption is configured
        if config.client.request_object_encryption_alg.is_some() {
            return Err(OpenIdError::new_error(
                "request object encryption is not yet supported in the new client",
            ));
        }

        Ok(signed)
    }

    /// # From URI
    ///
    /// Fetches client metadata from a registration_client_uri.
    /// This is used to retrieve client configuration after dynamic registration.
    ///
    /// - `http_client` - The HTTP client to make the request.
    /// - `registration_client_uri` - The URL to fetch client metadata from.
    /// - `registration_access_token` - Optional access token for authentication.
    pub async fn from_uri<H: OidcHttpClient>(
        http_client: &H,
        registration_client_uri: &str,
        registration_access_token: Option<&str>,
    ) -> OidcReturn<ClientRegistrationResponse> {
        let url = Url::parse(registration_client_uri)
            .map_err(|e| OpenIdError::new_error(format!("Invalid registration_client_uri: {e}")))?;

        let mut headers = HashMap::new();
        headers.insert("accept".to_string(), vec!["application/json".to_string()]);

        if let Some(rat) = registration_access_token {
            headers.insert("authorization".to_string(), vec![format!("Bearer {}", rat)]);
        }

        let request = HttpRequest::new()
            .url(url)
            .method(HttpMethod::GET)
            .headers(headers)
            .expect_json(true)
            .expect_status_code(200);

        let response = Http::default().request_async(request, http_client).await?;

        let body = response
            .body
            .ok_or_else(|| OpenIdError::new_error("empty response from registration_client_uri"))?;

        deserialize::<ClientRegistrationResponse>(&body)
            .map_err(|e| OpenIdError::new_error(format!("failed to parse client metadata: {}", e)))
    }

    /// # Register
    ///
    /// Performs dynamic client registration (RFC 7591) at the issuer's registration_endpoint.
    ///
    /// - `http_client` - The HTTP client to make the request.
    /// - `issuer` - The issuer metadata (must have registration_endpoint).
    /// - `registration_request` - The client registration request parameters.
    /// - `initial_access_token` - Optional initial access token for protected registration.
    pub async fn register<H: OidcHttpClient>(
        http_client: &H,
        issuer: &IssuerMetadata,
        registration_request: ClientRegistrationRequest,
        initial_access_token: Option<&str>,
    ) -> OidcReturn<ClientRegistrationResponse> {
        let registration_endpoint = issuer.registration_endpoint.as_ref().ok_or_else(|| {
            OpenIdError::new_error("registration_endpoint must be configured on the issuer")
        })?;

        let url = Url::parse(registration_endpoint)
            .map_err(|e| OpenIdError::new_error(format!("Invalid registration_endpoint: {e}")))?;

        let body = serde_json::to_string(&registration_request).map_err(|e| {
            OpenIdError::new_error(format!("failed to serialize registration request: {}", e))
        })?;

        let mut headers = HashMap::new();
        headers.insert("accept".to_string(), vec!["application/json".to_string()]);
        headers.insert(
            "content-type".to_string(),
            vec!["application/json".to_string()],
        );

        if let Some(iat) = initial_access_token {
            headers.insert("authorization".to_string(), vec![format!("Bearer {}", iat)]);
        }

        let request = HttpRequest::new()
            .url(url)
            .method(HttpMethod::POST)
            .headers(headers)
            .expect_json(true)
            .expect_status_code(201);

        let mut request = request;
        request.body = Some(RequestBody::Json(body));

        let response = Http::default().request_async(request, http_client).await?;

        let body = response
            .body
            .ok_or_else(|| OpenIdError::new_error("empty response from registration_endpoint"))?;

        deserialize::<ClientRegistrationResponse>(&body).map_err(|e| {
            OpenIdError::new_error(format!("failed to parse registration response: {}", e))
        })
    }

    /// # Token Exchange
    ///
    /// Performs a Token Exchange Grant (RFC 8693).
    /// *This method is currently a stub outlining how to extend this client.*
    pub async fn token_exchange_async<H: OidcHttpClient>(
        config: &OpenIdClientConfiguration,
        http_client: &H,
        subject_token: &str,
        subject_token_type: &str,
        additional_parameters: Option<HashMap<String, String>>,
        dpop_options: Option<&DPoPOptions>,
    ) -> OidcReturn<TokenSet> {
        let mut params = HashMap::new();
        if let Some(additional_parameters) = additional_parameters {
            params.extend(additional_parameters);
        }
        params.insert(
            "grant_type".to_owned(),
            "urn:ietf:params:oauth:grant-type:token-exchange".to_owned(),
        );
        params.insert("subject_token".to_owned(), subject_token.to_owned());
        params.insert(
            "subject_token_type".to_owned(),
            subject_token_type.to_owned(),
        );

        let tokenset =
            Client::grant_async(config, RequestBody::Form(params), http_client, dpop_options)
                .await?;

        // RFC 8693 Section 2.2.1 specifies `issued_token_type` is REQUIRED in the response
        if tokenset
            .other
            .as_ref()
            .and_then(|other| other.get("issued_token_type"))
            .and_then(|val| val.as_str())
            .is_none()
        {
            return Err(OpenIdError::new_error(
                "token exchange response is missing the required 'issued_token_type' parameter",
            ));
        }

        // `token_type` is also REQUIRED in RFC 8693, with 'N/A' allowed if no type applies
        if tokenset.token_type.is_none() {
            return Err(OpenIdError::new_error(
                "token exchange response is missing the required 'token_type' parameter",
            ));
        }

        Ok(tokenset)
    }
}

fn get_client_secret(config: &OpenIdClientConfiguration) -> OidcReturn<String> {
    match &config.auth {
        ClientAuth::ClientSecretBasic { client_secret }
        | ClientAuth::ClientSecretPost { client_secret }
        | ClientAuth::ClientSecretJwt { client_secret, .. } => Ok(client_secret.to_string()),
        _ => Err(OpenIdError::new_error(
            "client secret not available for symmetric signing",
        )),
    }
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn jwt_signing_alg_to_string(alg: &JwtSigningAlg) -> String {
    match alg {
        JwtSigningAlg::HS256 => "HS256",
        JwtSigningAlg::HS384 => "HS384",
        JwtSigningAlg::HS512 => "HS512",
        JwtSigningAlg::RS256 => "RS256",
        JwtSigningAlg::RS384 => "RS384",
        JwtSigningAlg::RS512 => "RS512",
        JwtSigningAlg::ES256 => "ES256",
        JwtSigningAlg::ES384 => "ES384",
        JwtSigningAlg::ES512 => "ES512",
        JwtSigningAlg::PS256 => "PS256",
        JwtSigningAlg::PS384 => "PS384",
        JwtSigningAlg::PS512 => "PS512",
        JwtSigningAlg::EdDSA => "EdDSA",
        JwtSigningAlg::ES256K => "ES256K",
    }
    .to_string()
}

async fn authenticated_post_async<H: OidcHttpClient>(
    config: &OpenIdClientConfiguration,
    endpoint: AuthenticatedEndpoints,
    body: RequestBody,
    http_client: &H,
    dpop_options: Option<&DPoPOptions>,
) -> OidcReturn<HttpResponse> {
    config.check_authentication_support(&endpoint)?;

    let mut request = HttpRequest::new();

    request.body = Some(body);

    config.auth.authenticate(
        &config.client.client_id,
        &config.options,
        &config.issuer,
        &mut request,
    )?;

    request = request.header("content-type", "application/x-www-form-urlencoded");

    let is_mtls_auth = config.auth.get_auth_method() == AuthMethods::TlsClientAuth
        || config.auth.get_auth_method() == AuthMethods::SelfSignedTlsClientAuth;

    request.mtls = is_mtls_auth
        || config
            .client
            .tls_client_certificate_bound_access_tokens
            .is_some_and(|tccbat| tccbat);

    request.url = match (&endpoint, request.mtls) {
        // Regular Requests
        (AuthenticatedEndpoints::Token, false) => config.token_endpoint()?,
        (AuthenticatedEndpoints::Introspection, false) => config.introspection_endpoint()?,
        (AuthenticatedEndpoints::Revocation, false) => config.revocation_endpoint()?,
        (AuthenticatedEndpoints::PushedAuthorization, false) => config.par_endpoint()?,
        (AuthenticatedEndpoints::DeviceAuthorization, false) => {
            config.device_authorization_endpoint()?
        }
        (AuthenticatedEndpoints::BackChannelAuthentication, false) => {
            config.backchannel_authentication_endpoint()?
        }
        // MTLS Requests
        (AuthenticatedEndpoints::Token, true) => config.mtls_token_endpoint()?,
        (AuthenticatedEndpoints::Introspection, true) => config.mtls_introspection_endpoint()?,
        (AuthenticatedEndpoints::Revocation, true) => config.mtls_revocation_endpoint()?,
        (AuthenticatedEndpoints::PushedAuthorization, true) => config.mtls_par_endpoint()?,
        (AuthenticatedEndpoints::DeviceAuthorization, true) => {
            config.mtls_device_authorization_endpoint()?
        }
        (AuthenticatedEndpoints::BackChannelAuthentication, true) => {
            config.mtls_backchannel_authentication_endpoint()?
        }
    };

    match endpoint {
        AuthenticatedEndpoints::Revocation => {
            // No body response is expected for revocation
        }
        _ => {
            request = request.header("accept", "application/json");
        }
    };

    request.method = HttpMethod::POST;

    let mut binding = Http::default().set_config(config);

    if let Some(dpop_options) = dpop_options {
        binding = binding.set_dpop(
            dpop_options,
            config.issuer.dpop_signing_alg_values_supported.as_ref(),
            config.options.clock_skew,
        );
    }

    binding.request_async(request, http_client).await
}
