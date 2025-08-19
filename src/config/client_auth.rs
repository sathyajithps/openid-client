use serde_json::{Map, Number, Value};
use std::{borrow::Cow, collections::HashMap, time::Duration};

use crate::{
    config::configuration_options::ConfigurationOptions,
    defaults::Crypto,
    errors::{OidcReturn, OpenIdError},
    helpers::{base64_encode, generate_random, unix_timestamp, url_encoded},
    jwk::{Jwk, JwkType},
    types::{
        http_client::{ClientCertificate, HttpRequest, RequestBody},
        AuthMethods, Header, IssuerMetadata, OpenIdCrypto, Payload,
    },
};

/// HS256 algorithm value
pub const DEFAULT_HS256_ALGORITHM: &str = "HS256";
/// RS256 algorithm value
pub const DEFAULT_RS256_ALGORITHM: &str = "RS256";
/// Default JWT assertion type
pub const DEFAULT_JWT_ASSERTION_TYPE: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Options to configure the JWT assertion.
#[derive(Default, Debug, Clone)]
pub struct JwtAssertionOptions {
    /// Optional duration (in seconds) for which the assertion is valid. (exp) claim is derived from this value.
    assertion_duration: Option<Duration>,
    /// Optional additional claims to include in the JWT payload.
    custom_claims: Option<HashMap<String, Value>>,
    /// Optional additional claims to include in the JWT header.
    custom_header_claims: Option<HashMap<String, Value>>,
    /// Optional signing algorithm to use for the JWT. Default is HS256 for client_secret_jwt and RS256 for private_key_jwt.
    signing_algorithm: Option<Cow<'static, str>>,
    /// Optional assertion type. The default is urn:ietf:params:oauth:client-assertion-type:jwt-bearer.
    assertion_type: Option<Cow<'static, str>>,
}

/// Represents the different client authentication methods in OpenID Connect.
#[derive(Debug, Clone)]
pub enum ClientAuth {
    /// Auth using client ID and optional secret in HTTP Basic Authorization header.
    ClientSecretBasic {
        /// Client secret
        client_secret: Cow<'static, str>,
    },
    /// Auth by sending client ID and optional secret in POST form body.
    ClientSecretPost {
        /// Client secret
        client_secret: Cow<'static, str>,
    },
    /// Auth using a client secret JWT with optional custom claims.
    ClientSecretJwt {
        /// The client secret used to sign the JWT.
        client_secret: Cow<'static, str>,
        /// Options to configure the JWT assertion.
        options: JwtAssertionOptions,
    },
    /// Auth with a private key JWT and optional custom claims.
    PrivateKeyJwt {
        /// The client secret used to sign the JWT.
        jwk: Jwk,
        /// Options to configure the JWT assertion.
        options: JwtAssertionOptions,
    },
    /// Auth using a self-signed TLS client certificate.
    SelfSignedTls(ClientCertificate),
    /// Auth using a TLS client certificate.
    Tls(ClientCertificate),
    /// No client authentication.
    None,
}

impl ClientAuth {
    /// Creates a client authentication method representing no authentication.
    pub fn none() -> Self {
        ClientAuth::None
    }

    /// Creates a `ClientSecretBasic` authentication method.
    pub fn client_secret_basic(client_secret: impl Into<Cow<'static, str>>) -> Self {
        ClientAuth::ClientSecretBasic {
            client_secret: client_secret.into(),
        }
    }

    /// Creates a `ClientSecretPost` authentication method.
    pub fn client_secret_post(client_secret: impl Into<Cow<'static, str>>) -> Self {
        ClientAuth::ClientSecretPost {
            client_secret: client_secret.into(),
        }
    }

    /// Creates a `ClientSecretJwt` authentication method.
    pub fn client_secret_jwt(client_secret: impl Into<Cow<'static, str>>) -> Self {
        ClientAuth::ClientSecretJwt {
            client_secret: client_secret.into(),
            options: JwtAssertionOptions::default(),
        }
    }

    /// Creates a `PrivateKeyJwt` authentication method.
    pub fn private_key_jwt(jwk: Jwk) -> Self {
        ClientAuth::PrivateKeyJwt {
            jwk,
            options: JwtAssertionOptions::default(),
        }
    }

    /// Creates a `SelfSignedTls` authentication method.
    pub fn self_signed_tls(certificate: ClientCertificate) -> Self {
        ClientAuth::SelfSignedTls(certificate)
    }

    /// Creates a `Tls` authentication method.
    pub fn tls(certificate: ClientCertificate) -> Self {
        ClientAuth::Tls(certificate)
    }
}

impl ClientAuth {
    /// Adds client authentication data to the HTTP request according to the auth method.
    ///
    /// - For `ClientSecretBasic`, sets the `Authorization` header with Basic auth.
    /// - For `ClientSecretPost`, adds client credentials to the form body.
    /// - For `ClientSecretJwt` and `PrivateKeyJwt`, creates an assertion and adds to the body.
    /// - For `Tls` and `SelfSignedTls`, attaches the client certificate.
    /// - For `None`, does nothing.
    pub fn authenticate(
        &self,
        client_id: impl AsRef<str>,
        options: &ConfigurationOptions,
        issuer: &IssuerMetadata,
        request: &mut HttpRequest,
    ) -> OidcReturn<()> {
        match &self {
            ClientAuth::ClientSecretBasic { client_secret } => {
                let client_id_ref = client_id.as_ref();
                let client_secret_ref = client_secret.as_ref();
                let encoded = format!(
                    "{}:{}",
                    url_encoded(client_id_ref.as_bytes()),
                    url_encoded(client_secret_ref.as_bytes())
                );

                let header = format!("Basic {}", base64_encode(encoded));

                request
                    .headers
                    .insert("Authorization".to_owned(), vec![header]);
            }
            ClientAuth::ClientSecretPost { client_secret } => match &mut request.body {
                Some(RequestBody::Form(form)) => {
                    form.insert("client_id".to_owned(), client_id.as_ref().to_owned());
                    form.insert("client_secret".to_owned(), client_secret.to_string());
                }
                _ => {
                    return Err(OpenIdError::new_error(
                        "ClientSecretPost requires a form body but received another type",
                    ))
                }
            },
            ClientAuth::ClientSecretJwt {
                client_secret,
                options:
                    JwtAssertionOptions {
                        custom_header_claims,
                        signing_algorithm,
                        assertion_type,
                        ..
                    },
            } => {
                self.create_assertion(
                    issuer,
                    client_id.as_ref(),
                    request,
                    &Jwk::from_symmetric_key(client_secret.as_bytes()),
                    signing_algorithm
                        .as_deref()
                        .unwrap_or(DEFAULT_HS256_ALGORITHM),
                    assertion_type.as_deref(),
                    custom_header_claims,
                )?;
            }
            ClientAuth::PrivateKeyJwt {
                jwk,
                options:
                    JwtAssertionOptions {
                        custom_header_claims,
                        signing_algorithm,
                        assertion_type,
                        ..
                    },
                ..
            } => {
                if jwk.key_type() == JwkType::Oct {
                    return Err(OpenIdError::new_error(
                        "Cannot use oct key to sign using private_key_jwt",
                    ));
                }

                self.create_assertion(
                    issuer,
                    client_id.as_ref(),
                    request,
                    jwk,
                    signing_algorithm
                        .as_deref()
                        .unwrap_or(DEFAULT_RS256_ALGORITHM),
                    assertion_type.as_deref(),
                    custom_header_claims,
                )?;
            }
            ClientAuth::Tls(certificate) | ClientAuth::SelfSignedTls(certificate) => {
                match &mut request.body {
                    Some(RequestBody::Form(form)) => {
                        form.insert("client_id".to_owned(), client_id.as_ref().to_owned());
                    }
                    _ => {
                        return Err(OpenIdError::new_error(
                            "mTLS auth requires a form body but received another type",
                        ))
                    }
                }
                request.client_certificate = Some(certificate.clone());
            }
            ClientAuth::None => {
                if options.add_client_id_to_request {
                    let client_id = client_id.as_ref().to_owned();
                    match &mut request.body {
                        Some(RequestBody::Form(form)) => {
                            form.insert("client_id".to_owned(), client_id);
                        }
                        _ => {
                            if request
                                .url
                                .query_pairs()
                                .find(|q| q.0 == "client_id")
                                .is_none()
                            {
                                request
                                    .url
                                    .query_pairs_mut()
                                    .append_pair("client_id", &client_id);
                            }
                        }
                    }
                }
            }
        };

        Ok(())
    }

    /// Sets custom JWT assertion claims for JWT-based client authentication.
    ///
    /// Has an effect only on `ClientSecretJwt` and `PrivateKeyJwt` variants.
    pub fn set_custom_assertion_claims(
        &mut self,
        custom_claims: impl IntoIterator<Item = (String, Value)>,
    ) {
        if let Some(options) = self.get_jwt_options_mut() {
            options.custom_claims = Some(custom_claims.into_iter().collect());
        }
    }

    /// Sets custom JWT assertion header claims for JWT-based client authentication.
    ///
    /// Has an effect only on `ClientSecretJwt` and `PrivateKeyJwt` variants.
    pub fn set_custom_header_claims(
        &mut self,
        custom_claims: impl IntoIterator<Item = (String, Value)>,
    ) {
        if let Some(options) = self.get_jwt_options_mut() {
            options.custom_header_claims = Some(custom_claims.into_iter().collect());
        }
    }

    /// Sets assertion type for JWT-based client authentication.
    ///
    /// Has effect only on `ClientSecretJwt` and `PrivateKeyJwt` variants.
    pub fn set_assertion_type(&mut self, assertion_type: impl Into<Cow<'static, str>>) {
        if let Some(options) = self.get_jwt_options_mut() {
            options.assertion_type = Some(assertion_type.into());
        }
    }

    /// Creates the payload of the assertion
    pub fn create_assertion_payload(
        &self,
        issuer: &IssuerMetadata,
        client_id: &str,
    ) -> OidcReturn<Payload> {
        let mut payload = Payload {
            params: serde_json::Map::new(),
        };

        // The 'aud' (audience) claim of the JWT assertion is set to include both the issuer
        // and the token_endpoint as per the OpenID Connect specification, to ensure
        // the assertion is only accepted by the intended audience.
        let mut audience = vec![Value::String(issuer.issuer.to_owned())];

        if let Some(token_endpoint) = &issuer.token_endpoint {
            audience.push(Value::String(token_endpoint.to_owned()));
        }

        payload.params.insert("aud".into(), Value::Array(audience));

        let client_id_string = client_id.to_owned();

        payload
            .params
            .insert("iss".into(), Value::String(client_id_string.clone()));

        payload
            .params
            .insert("sub".into(), Value::String(client_id_string));

        payload
            .params
            .insert("jti".into(), Value::String(generate_random(None)));

        let now = unix_timestamp();

        payload
            .params
            .insert("iat".into(), Value::Number(Number::from(now)));

        payload
            .params
            .insert("nbf".into(), Value::Number(Number::from(now)));

        let (assertion_duration, custom_claims) = match self {
            ClientAuth::PrivateKeyJwt {
                options:
                    JwtAssertionOptions {
                        assertion_duration,
                        custom_claims,
                        ..
                    },
                ..
            }
            | ClientAuth::ClientSecretJwt {
                options:
                    JwtAssertionOptions {
                        assertion_duration,
                        custom_claims,
                        ..
                    },
                ..
            } => (*assertion_duration, custom_claims.as_ref()),
            _ => (None, None),
        };

        let exp_duration = assertion_duration.map(|d| d.as_secs()).unwrap_or(300);
        let exp = now + exp_duration;
        payload
            .params
            .insert("exp".into(), Value::Number(Number::from(exp)));

        if let Some(claims) = custom_claims {
            for (k, v) in claims {
                payload.params.insert(k.to_owned(), v.to_owned());
            }
        }

        Ok(payload)
    }

    /// Retruns the configured client authentication method
    pub fn get_auth_method(&self) -> AuthMethods {
        match self {
            ClientAuth::ClientSecretBasic { .. } => AuthMethods::ClientSecretBasic,
            ClientAuth::ClientSecretPost { .. } => AuthMethods::ClientSecretPost,
            ClientAuth::ClientSecretJwt { .. } => AuthMethods::ClientSecretJwt,
            ClientAuth::PrivateKeyJwt { .. } => AuthMethods::PrivateKeyJwt,
            ClientAuth::SelfSignedTls(_) => AuthMethods::SelfSignedTlsClientAuth,
            ClientAuth::Tls(_) => AuthMethods::TlsClientAuth,
            ClientAuth::None => AuthMethods::None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn create_assertion(
        &self,
        issuer: &IssuerMetadata,
        client_id: &str,
        request: &mut HttpRequest,
        jwk: &Jwk,
        alg: &str,
        assertion_type: Option<&str>,
        custom_header_claims: &Option<HashMap<String, Value>>,
    ) -> OidcReturn<()> {
        let payload = self.create_assertion_payload(issuer, client_id)?;

        let mut params = Map::new();

        params.insert("alg".to_string(), Value::String(alg.to_owned()));

        if let Some(kid) = jwk
            .get_param("kid")
            .and_then(|v| v.as_str().map(|k| Value::String(k.to_owned())))
        {
            params.insert("kid".to_string(), kid);
        }

        params.insert("typ".to_string(), Value::String("JWT".to_owned()));

        let mut header = Header { params };

        if let Some(custom_header_claims) = custom_header_claims {
            for (k, v) in custom_header_claims {
                header.params.insert(k.to_owned(), v.to_owned());
            }
        }

        let assertion = Crypto
            .jws_serialize(payload, header, jwk)
            .map_err(OpenIdError::new_error)?;

        let assertion_type = assertion_type.unwrap_or(DEFAULT_JWT_ASSERTION_TYPE);

        match request.body {
            Some(RequestBody::Form(ref mut form)) => {
                form.insert("client_id".to_owned(), client_id.to_owned());
                form.insert("client_assertion_type".to_owned(), assertion_type.to_owned());
                form.insert("client_assertion".to_owned(), assertion);
                Ok(())
            }
            _ => Err(OpenIdError::new_error("Body is not form; JWT client authentication requires application/x-www-form-urlencoded on token endpoint")),
        }
    }

    fn get_jwt_options_mut(&mut self) -> Option<&mut JwtAssertionOptions> {
        match self {
            ClientAuth::ClientSecretJwt { options, .. }
            | ClientAuth::PrivateKeyJwt { options, .. } => Some(options),
            _ => None,
        }
    }
}
