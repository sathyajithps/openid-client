use url::Url;

use crate::{
    config::{client_auth::ClientAuth, configuration_options::ConfigurationOptions},
    errors::{OidcReturn, OpenIdError},
    jwk::Jwk,
    types::{
        AuthMethods, AuthenticatedEndpoints, ClientMetadata, IssuerMetadata, OpenIdResponseType,
    },
};

/// Represents the complete OpenID Connect client configuration.
///
/// This struct bundles together all the key metadata and client authentication
/// details required to perform OpenID Connect flows.
#[derive(Debug, Clone)]
pub struct OpenIdClientConfiguration {
    /// Metadata describing the OpenID Connect issuer.
    pub issuer: IssuerMetadata,
    /// Issuer Jwks fetched from the `jwks_uri`
    pub issuer_jwks: Vec<Jwk>,
    /// Metadata describing the client application.
    pub client: ClientMetadata,
    /// Client authentication method used to authenticate the client.
    pub auth: ClientAuth,
    /// Extra options to customize client behavior and configuration.
    pub options: ConfigurationOptions,
    /// Jwks used for json web encryption
    pub jwe_keys: Vec<Jwk>,
    /// Specifies the response type that is used for the authorization callback.
    /// See [OpenIdResponseType].
    pub response_type: OpenIdResponseType,
    /// Specifies if the client is a FAPI Client
    pub fapi: bool,
}

impl OpenIdClientConfiguration {
    /// Creates new [OpenIdClientConfiguration]. All the other options are set to default.
    pub fn new(
        issuer: IssuerMetadata,
        issuer_jwks: Vec<Jwk>,
        client: ClientMetadata,
        auth: ClientAuth,
    ) -> Self {
        Self {
            issuer,
            issuer_jwks,
            client,
            auth,
            options: ConfigurationOptions::default(),
            jwe_keys: vec![],
            response_type: OpenIdResponseType::Code,
            fapi: false,
        }
    }

    /// Creates new [OpenIdClientConfiguration] with all the provided options.
    #[allow(clippy::too_many_arguments)]
    pub fn new_all(
        issuer: IssuerMetadata,
        issuer_jwks: Vec<Jwk>,
        client: ClientMetadata,
        auth: ClientAuth,
        options: ConfigurationOptions,
        jwe_keys: Vec<Jwk>,
        response_type: OpenIdResponseType,
        fapi: bool,
    ) -> Self {
        Self {
            issuer,
            issuer_jwks,
            client,
            auth,
            options,
            jwe_keys,
            response_type,
            fapi,
        }
    }

    /// Returns the parsed URL for the issuer's authorization endpoint.
    pub fn authorization_endpoint(&self) -> OidcReturn<Url> {
        match self
            .issuer
            .authorization_endpoint
            .as_ref()
            .map(|authorization_endpoint| Url::parse(authorization_endpoint))
        {
            Some(Ok(url)) => Ok(url),
            _ => Err(OpenIdError::new_error(
                "authorization_endpoint not found or incorrect format",
            )),
        }
    }

    /// Returns the parsed URL for the issuer's end session or logout endpoint.
    pub fn end_session_endpoint(&self) -> OidcReturn<Url> {
        match self
            .issuer
            .end_session_endpoint
            .as_ref()
            .map(|end_session_endpoint| Url::parse(end_session_endpoint))
        {
            Some(Ok(url)) => Ok(url),
            _ => Err(OpenIdError::new_error(
                "end_session_endpoint not found or incorrect format",
            )),
        }
    }

    /// Returns the parsed URL for the issuer's token endpoint.
    pub fn token_endpoint(&self) -> OidcReturn<Url> {
        match self
            .issuer
            .token_endpoint
            .as_ref()
            .map(|token_endpoint| Url::parse(token_endpoint))
        {
            Some(Ok(url)) => Ok(url),
            _ => Err(OpenIdError::new_error(
                "token_endpoint not found or incorrect format",
            )),
        }
    }

    /// Returns the MTLS-specific alias URL for the token endpoint.
    pub fn mtls_token_endpoint(&self) -> OidcReturn<Url> {
        match self
            .issuer
            .mtls_endpoint_aliases
            .as_ref()
            .and_then(|aliases| {
                aliases
                    .token_endpoint
                    .as_ref()
                    .map(|token_endpoint| Url::parse(token_endpoint))
            }) {
            Some(Ok(url)) => Ok(url),
            _ => Err(OpenIdError::new_error(
                "mtls_token_endpoint not found or incorrect format",
            )),
        }
    }

    /// Returns the parsed URL for the Pushed Authorization Request (PAR) endpoint.
    pub fn par_endpoint(&self) -> OidcReturn<Url> {
        match self
            .issuer
            .pushed_authorization_request_endpoint
            .as_ref()
            .map(|par_endpoint| Url::parse(par_endpoint))
        {
            Some(Ok(url)) => Ok(url),
            _ => Err(OpenIdError::new_error(
                "pushed_authorization_request_endpoint not found or incorrect format",
            )),
        }
    }

    /// Returns the MTLS-specific alias URL for the PAR endpoint.
    pub fn mtls_par_endpoint(&self) -> OidcReturn<Url> {
        match self
            .issuer
            .mtls_endpoint_aliases
            .as_ref()
            .and_then(|aliases| {
                aliases
                    .pushed_authorization_request_endpoint
                    .as_ref()
                    .map(|par_endpoint| Url::parse(par_endpoint))
            }) {
            Some(Ok(url)) => Ok(url),
            _ => Err(OpenIdError::new_error(
                "mtls_pushed_authorization_request_endpoint not found or incorrect format",
            )),
        }
    }

    /// Returns the parsed URL for the device authorization endpoint.
    pub fn device_authorization_endpoint(&self) -> OidcReturn<Url> {
        match self
            .issuer
            .device_authorization_endpoint
            .as_ref()
            .map(|device_authorization_endpoint| Url::parse(device_authorization_endpoint))
        {
            Some(Ok(url)) => Ok(url),
            _ => Err(OpenIdError::new_error(
                "device_authorization_endpoint not found or incorrect format",
            )),
        }
    }

    /// Returns the MTLS-specific alias URL for the device authorization endpoint.
    pub fn mtls_device_authorization_endpoint(&self) -> OidcReturn<Url> {
        match self
            .issuer
            .mtls_endpoint_aliases
            .as_ref()
            .and_then(|aliases| {
                aliases
                    .device_authorization_endpoint
                    .as_ref()
                    .map(|device_authorization_endpoint| Url::parse(device_authorization_endpoint))
            }) {
            Some(Ok(url)) => Ok(url),
            _ => Err(OpenIdError::new_error(
                "mtls_device_authorization_endpoint not found or incorrect format",
            )),
        }
    }

    /// Returns the parsed URL for the backchannel (CIBA) authentication endpoint.
    pub fn backchannel_authentication_endpoint(&self) -> OidcReturn<Url> {
        match self
            .issuer
            .backchannel_authentication_endpoint
            .as_ref()
            .map(|backchannel_authentication_endpoint| {
                Url::parse(backchannel_authentication_endpoint)
            }) {
            Some(Ok(url)) => Ok(url),
            _ => Err(OpenIdError::new_error(
                "backchannel_authentication_endpoint not found or incorrect format",
            )),
        }
    }

    /// Returns the MTLS-specific alias URL for the backchannel authentication endpoint.
    pub fn mtls_backchannel_authentication_endpoint(&self) -> OidcReturn<Url> {
        match self
            .issuer
            .mtls_endpoint_aliases
            .as_ref()
            .and_then(|aliases| {
                aliases.backchannel_authentication_endpoint.as_ref().map(
                    |backchannel_authentication_endpoint| {
                        Url::parse(backchannel_authentication_endpoint)
                    },
                )
            }) {
            Some(Ok(url)) => Ok(url),
            _ => Err(OpenIdError::new_error(
                "mtls_backchannel_authentication_endpoint not found or incorrect format",
            )),
        }
    }

    /// Returns the parsed URL for the issuer's userinfo endpoint.
    pub fn userinfo_endpoint(&self) -> OidcReturn<Url> {
        match self
            .issuer
            .userinfo_endpoint
            .as_ref()
            .map(|userinfo_endpoint| Url::parse(userinfo_endpoint))
        {
            Some(Ok(url)) => Ok(url),
            _ => Err(OpenIdError::new_error(
                "userinfo_endpoint not found or incorrect format",
            )),
        }
    }

    /// Returns the MTLS-specific alias URL for the userinfo endpoint.
    pub fn mtls_userinfo_endpoint(&self) -> OidcReturn<Url> {
        match self
            .issuer
            .mtls_endpoint_aliases
            .as_ref()
            .and_then(|aliases| {
                aliases
                    .userinfo_endpoint
                    .as_ref()
                    .map(|userinfo_endpoint| Url::parse(userinfo_endpoint))
            }) {
            Some(Ok(url)) => Ok(url),
            _ => Err(OpenIdError::new_error(
                "mtls_userinfo_endpoint not found or incorrect format",
            )),
        }
    }

    /// Returns the parsed URL for the token revocation endpoint.
    pub fn revocation_endpoint(&self) -> OidcReturn<Url> {
        match self
            .issuer
            .revocation_endpoint
            .as_ref()
            .map(|revocation_endpoint| Url::parse(revocation_endpoint))
        {
            Some(Ok(url)) => Ok(url),
            _ => Err(OpenIdError::new_error(
                "revocation_endpoint not found or incorrect format",
            )),
        }
    }

    /// Returns the MTLS-specific alias URL for the token revocation endpoint.
    pub fn mtls_revocation_endpoint(&self) -> OidcReturn<Url> {
        match self
            .issuer
            .mtls_endpoint_aliases
            .as_ref()
            .and_then(|aliases| {
                aliases
                    .revocation_endpoint
                    .as_ref()
                    .map(|revocation_endpoint| Url::parse(revocation_endpoint))
            }) {
            Some(Ok(url)) => Ok(url),
            _ => Err(OpenIdError::new_error(
                "mtls_revocation_endpoint not found or incorrect format",
            )),
        }
    }

    /// Returns the parsed URL for the token introspection endpoint.
    pub fn introspection_endpoint(&self) -> OidcReturn<Url> {
        match self
            .issuer
            .introspection_endpoint
            .as_ref()
            .map(|introspection_endpoint| Url::parse(introspection_endpoint))
        {
            Some(Ok(url)) => Ok(url),
            _ => Err(OpenIdError::new_error(
                "introspection_endpoint not found or incorrect format",
            )),
        }
    }

    /// Returns the MTLS-specific alias URL for the token introspection endpoint.
    pub fn mtls_introspection_endpoint(&self) -> OidcReturn<Url> {
        match self
            .issuer
            .mtls_endpoint_aliases
            .as_ref()
            .and_then(|aliases| {
                aliases
                    .introspection_endpoint
                    .as_ref()
                    .map(|introspection_endpoint| Url::parse(introspection_endpoint))
            }) {
            Some(Ok(url)) => Ok(url),
            _ => Err(OpenIdError::new_error(
                "mtls_introspection_endpoint not found or incorrect format",
            )),
        }
    }

    /// Returns the parsed URL for the dynamic client registration endpoint.
    pub fn registration_endpoint(&self) -> OidcReturn<Url> {
        match self
            .issuer
            .registration_endpoint
            .as_ref()
            .map(|registration_endpoint| Url::parse(registration_endpoint))
        {
            Some(Ok(url)) => Ok(url),
            _ => Err(OpenIdError::new_error(
                "registration_endpoint not found or incorrect format",
            )),
        }
    }

    /// Verifies if the configured client authentication method is supported by the target endpoint.
    pub fn check_authentication_support(
        &self,
        endpoint: &AuthenticatedEndpoints,
    ) -> OidcReturn<()> {
        if self.options.skip_auth_checks {
            return Ok(());
        }

        let configured_authentication_method = self.auth.get_auth_method();

        let supported_authentication_methods = match endpoint {
            AuthenticatedEndpoints::Token
            | AuthenticatedEndpoints::PushedAuthorization
            | AuthenticatedEndpoints::DeviceAuthorization
            | AuthenticatedEndpoints::BackChannelAuthentication => {
                self.issuer.token_endpoint_auth_methods_supported.clone()
            }
            AuthenticatedEndpoints::Introspection => self
                .issuer
                .introspection_endpoint_auth_methods_supported
                .clone(),
            AuthenticatedEndpoints::Revocation => self
                .issuer
                .revocation_endpoint_auth_methods_supported
                .clone()
                .or(Some(vec![AuthMethods::ClientSecretBasic])),
        };

        match supported_authentication_methods {
            Some(supported_authentication_methods) => {
                let result =
                    supported_authentication_methods.contains(&configured_authentication_method);

                if !result {
                    return Err(OpenIdError::new_error(format!(
                        "{:?} does not support {:?}",
                        endpoint, configured_authentication_method
                    )));
                }

                Ok(())
            }
            None => Err(OpenIdError::new_error("Unsupported authentication method")),
        }
    }
}
