use std::{cmp::max, collections::HashMap, num::Wrapping};

use crate::types::{
    grant_params::GrantParams, DeviceAuthorizationExtras, DeviceAuthorizationResponse,
    DeviceFlowGrantResponse, GrantExtras, OidcClientError, OidcHttpClient, OidcReturnType,
};

use super::Client;

/// # DeviceFlowHandle
/// Handle used for Device Grant
#[derive(Debug)]
pub struct DeviceFlowHandle {
    client: Client,
    extras: Option<DeviceAuthorizationExtras>,
    expires_at: i64,
    interval: f64,
    max_age: Option<u64>,
    response: DeviceAuthorizationResponse,
    last_requested: i64,
    pub(crate) now: fn() -> i64,
}

impl DeviceFlowHandle {
    /// Creates a new Device Flow Handle
    ///
    /// `client` - See [Client]
    /// `response` - [DeviceAuthorizationResponse] from the Device Authorization Endpoint
    /// `extras` - See [DeviceAuthorizationExtras]
    /// `max_age` - Maximum allowed age of the token
    pub fn new(
        client: Client,
        response: DeviceAuthorizationResponse,
        extras: Option<DeviceAuthorizationExtras>,
        max_age: Option<u64>,
    ) -> Self {
        let now = client.now;
        Self {
            client,
            extras,
            expires_at: now() + response.expires_in,
            interval: response.interval.unwrap_or(5.0),
            max_age,
            response,
            last_requested: 0,
            now,
        }
    }

    /// Gets the timestamp in seconds of when the device code expires
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// Gets the seconds in which the device code expires
    pub fn expires_in(&self) -> i64 {
        max((Wrapping(self.expires_at) - Wrapping((self.now)())).0, 0)
    }

    /// Gets wether the device code is expired or not
    pub fn expired(&self) -> bool {
        self.expires_in() == 0
    }

    /// Gets the polling interval
    pub fn interval(&self) -> f64 {
        self.interval
    }

    /// Increase the interval by `by` seconds
    pub fn increase_interval(&mut self, by: f64) {
        self.interval += by;
    }

    /// Gets the inner client
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Gets the Device Code
    pub fn device_code(&self) -> &str {
        &self.response.device_code
    }

    /// Gets the User Code
    pub fn user_code(&self) -> &str {
        &self.response.user_code
    }

    /// Gets verification uri
    pub fn verification_uri(&self) -> &str {
        &self.response.verification_uri
    }

    /// Gets the complete verification uri
    pub fn verification_uri_complete(&self) -> Option<&String> {
        self.response.verification_uri_complete.as_ref()
    }

    /// ## Device Flow Grant
    ///
    /// Performs grant request at the token endpoint. This method will
    /// not poll itself. It is left to the implementor to create that logic.
    ///
    /// See [DeviceFlowGrantResponse] for the possible responses that will be obtained from the grant.
    pub async fn grant_async<T>(
        &mut self,
        http_client: &T,
    ) -> OidcReturnType<DeviceFlowGrantResponse>
    where
        T: OidcHttpClient,
    {
        if self.expired() {
            return Err(Box::new(OidcClientError::new_rp_error(&format!("the device code {} has expired and the device authorization session has concluded", self.device_code()), None)));
        }

        if (((self.now)() - self.last_requested) as f64) < self.interval {
            return Ok(DeviceFlowGrantResponse::Debounced);
        }

        let extras = GrantExtras {
            client_assertion_payload: self
                .extras
                .as_ref()
                .and_then(|x| x.client_assertion_payload.to_owned()),
            dpop: self.extras.as_ref().and_then(|x| x.dpop.as_ref()),
            ..Default::default()
        };

        let mut body = HashMap::new();

        if let Some(eb) = &self.extras.as_ref().and_then(|x| x.exchange_body.clone()) {
            for (k, v) in eb {
                body.insert(k.to_owned(), v.to_owned());
            }
        }

        body.insert(
            "grant_type".to_string(),
            "urn:ietf:params:oauth:grant-type:device_code".to_owned(),
        );

        body.insert("device_code".to_string(), self.device_code().to_owned());

        self.last_requested = (self.now)();

        let mut token_set = match self
            .client
            .grant_async(
                http_client,
                GrantParams {
                    body,
                    extras,
                    retry: true,
                },
            )
            .await
        {
            Ok(t) => t,
            Err(e) => {
                match e.as_ref() {
                    OidcClientError::OPError(sbe, _) => {
                        if sbe.error == "slow_down" {
                            self.increase_interval(5.0);
                            return Ok(DeviceFlowGrantResponse::SlowDown);
                        }
                        if sbe.error == "authorization_pending" {
                            return Ok(DeviceFlowGrantResponse::AuthorizationPending);
                        }

                        return Err(e);
                    }
                    OidcClientError::Error(_, _)
                    | OidcClientError::TypeError(_, _)
                    | OidcClientError::RPError(_, _) => return Err(e),
                };
            }
        };

        if token_set.get_id_token().is_some() {
            token_set = self.client.decrypt_id_token(token_set)?;
            token_set = self
                .client
                .validate_id_token_async(token_set, None, "token", self.max_age, None, http_client)
                .await?;
        }

        Ok(DeviceFlowGrantResponse::Successful(Box::new(token_set)))
    }
}
