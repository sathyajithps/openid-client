use serde::Deserialize;

use super::http::Response;

/// # ErrorWithResponse
/// Returned error type from
/// - [`OidcClientError::error()`] : T is [Error]
/// - [`OidcClientError::type_error()`] : T is [TypeError]
/// - [`OidcClientError::rp_error()`] : T is [RPError]
/// - [`OidcClientError::op_error()`] : T is [StandardBodyError]
pub struct ErrorWithResponse<T> {
    /// The error
    pub error: T,
    /// Response
    pub response: Option<Response>,
}

/// # StandardBodyError
/// Error that is returned from the OIDC Server
/// - [Error Response](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1)
#[derive(Debug, Deserialize)]
pub struct StandardBodyError {
    /// Short title of the error
    pub error: String,
    /// Description of the error
    pub error_description: Option<String>,
    /// Error uri
    pub error_uri: Option<String>,
    /// State from Auth Serverr
    pub state: Option<String>,
    /// Scope from Auth Server
    pub scope: Option<String>,
}

/// # Error
/// General Error returned when anything unexpected happens
#[derive(Debug)]
pub struct Error {
    /// Error Message
    pub message: String,
}

/// # TypeError
/// Error returned when an arg is of Uuexpected value or type
#[derive(Debug)]
pub struct TypeError {
    /// Error Message
    pub message: String,
}

// TODO: add more context related fields

/// # RPError
/// Error related to the Client response expectations
#[derive(Debug)]
pub struct RPError {
    /// Error Message
    pub message: String,
}

/// # OidcClientError
/// Error returned for all things related to `openid_client`
#[derive(Debug)]
pub enum OidcClientError {
    /// [Error]
    Error(Error, Option<Response>),
    /// [TypeError]
    TypeError(TypeError, Option<Response>),
    /// [RPError]
    RPError(RPError, Option<Response>),
    /// [StandardBodyError]
    OPError(StandardBodyError, Option<Response>),
}

impl OidcClientError {
    /// Checks if the Error is [`OidcClientError::Error`]
    pub fn is_error(&self) -> bool {
        matches!(self, OidcClientError::Error(..))
    }

    /// Checks if the Error is [`OidcClientError::TypeError`]
    pub fn is_type_error(&self) -> bool {
        matches!(self, OidcClientError::TypeError(..))
    }

    /// Checks if the Error is [`OidcClientError::RPError`]
    pub fn is_rp_error(&self) -> bool {
        matches!(self, OidcClientError::RPError(..))
    }

    /// Checks if the Error is [`OidcClientError::OPError`]
    pub fn is_op_error(&self) -> bool {
        matches!(self, OidcClientError::OPError(..))
    }

    /// Returns the [`ErrorWithResponse<Error>`]
    /// *Note: panics if called on the wrong enum*
    pub fn error(self) -> ErrorWithResponse<Error> {
        if let OidcClientError::Error(error, response) = self {
            return ErrorWithResponse { error, response };
        }
        panic!("Not an Error");
    }

    /// Returns the [`ErrorWithResponse<TypeError>`]
    /// *Note: panics if called on the wrong enum*
    pub fn type_error(self) -> ErrorWithResponse<TypeError> {
        if let OidcClientError::TypeError(error, response) = self {
            return ErrorWithResponse { error, response };
        }
        panic!("Not a TypeError");
    }

    /// Returns the [`ErrorWithResponse<RPError>`]
    /// *Note: panics if called on the wrong enum*
    pub fn rp_error(self) -> ErrorWithResponse<RPError> {
        if let OidcClientError::RPError(error, response) = self {
            return ErrorWithResponse { error, response };
        }
        panic!("Not an RPError");
    }

    /// Returns the [`ErrorWithResponse<StandardBodyError>`]
    /// *Note: panics if called on the wrong enum*
    pub fn op_error(self) -> ErrorWithResponse<StandardBodyError> {
        if let OidcClientError::OPError(error, response) = self {
            return ErrorWithResponse { error, response };
        }
        panic!("Not an OPError");
    }
}

impl OidcClientError {
    pub(crate) fn new_error(message: &str, response: Option<Response>) -> Self {
        OidcClientError::Error(
            Error {
                message: message.to_string(),
            },
            response,
        )
    }

    pub(crate) fn new_type_error(message: &str, response: Option<Response>) -> Self {
        OidcClientError::TypeError(
            TypeError {
                message: message.to_string(),
            },
            response,
        )
    }

    // TODO: remove
    #[allow(dead_code)]
    pub(crate) fn new_rp_error(message: &str, response: Option<Response>) -> Self {
        OidcClientError::RPError(
            RPError {
                message: message.to_string(),
            },
            response,
        )
    }

    pub(crate) fn new_op_error(
        error: String,
        error_description: Option<String>,
        error_uri: Option<String>,
        state: Option<String>,
        scope: Option<String>,
        response: Option<Response>,
    ) -> Self {
        OidcClientError::OPError(
            StandardBodyError {
                error,
                error_description,
                error_uri,
                state,
                scope,
            },
            response,
        )
    }
}
