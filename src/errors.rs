use std::error::Error as StdError;
use std::fmt::{Display, Formatter, Result as FmtResult};

use serde::Deserialize;

/// The return type of the methods used in this library
pub type OidcReturn<T> = Result<T, OpenIdError>;

/// # StandardBodyError
/// Error that is returned from the OpenID Server
/// - [Error Response](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1)
#[derive(Debug, Deserialize)]
pub struct StandardBodyError {
    /// Short title of the error
    pub error: String,
    /// Description of the error
    pub error_description: Option<String>,
    /// Error uri
    pub error_uri: Option<String>,
}

/// # Error
/// General Error returned when anything unexpected happens
#[derive(Debug)]
pub struct Error {
    /// Error Message
    pub message: String,
}

/// # ClientError
/// Error related to the Client response expectations
#[derive(Debug)]
pub struct ClientError {
    /// Error Message
    pub message: String,
}

/// # OpenIdError
/// Error returned for all things related to `openid_client`
#[derive(Debug)]
pub enum OpenIdError {
    /// [Error]
    Error(Error),
    /// [ClientError]
    ClientError(ClientError),
    /// [StandardBodyError]
    OPError(StandardBodyError),
}

impl Display for OpenIdError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            OpenIdError::Error(err) => write!(f, "Error: {}", err.message),
            OpenIdError::ClientError(err) => write!(f, "Client error: {}", err.message),
            OpenIdError::OPError(err) => write!(
                f,
                "OpenId server error: {}, description {:?}",
                err.error, err.error_description
            ),
        }
    }
}

impl StdError for OpenIdError {}

impl OpenIdError {
    pub(crate) fn new_error(message: impl Into<String>) -> OpenIdError {
        OpenIdError::Error(Error {
            message: message.into(),
        })
    }

    pub(crate) fn new_client_error(message: impl Into<String>) -> OpenIdError {
        OpenIdError::ClientError(ClientError {
            message: message.into(),
        })
    }

    pub(crate) fn new_op_error(
        error: impl Into<String>,
        error_description: Option<String>,
        error_uri: Option<String>,
    ) -> OpenIdError {
        OpenIdError::OPError(StandardBodyError {
            error: error.into(),
            error_description,
            error_uri,
        })
    }
}
