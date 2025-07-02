use std::collections::HashMap;

use crate::types::{
    CibaAuthResponse, CibaAuthenticationExtras, CibaGrantResponse, GrantExtras, GrantParams,
    OidcClientError, OidcHttpClient, OidcReturnType,
};

use super::{validate_id_token_params::ValidateIdTokenParams, Client};

/// # CibaHandle
/// Handle used for CIBA grant
pub struct CibaHandle {
    client: Client,
    extras: Option<CibaAuthenticationExtras>,
    expires_at: u64,
    interval: u64,
    response: CibaAuthResponse,
    last_requested: u64,
    pub(crate) now: fn() -> u64,
}

impl CibaHandle {
    /// Creates new CIBA Handle
    pub fn new(
        client: Client,
        res: CibaAuthResponse,
        extras: Option<CibaAuthenticationExtras>,
    ) -> Self {
        let now = client.now;

        Self {
            client,
            extras,
            expires_at: now() + res.get_expires_in(),
            interval: res.get_interval().unwrap_or(5),
            response: res,
            last_requested: 0,
            now,
        }
    }

    /// Gets wether the auth request id is expired or not
    pub fn expired(&self) -> bool {
        self.expires_in() == 0
    }

    /// Gets the interval
    pub fn interval(&self) -> u64 {
        self.interval
    }

    /// Gets the seconds in which the auth request id expires
    pub fn expires_in(&self) -> u64 {
        let now = (self.now)();
        if now >= self.expires_at {
            return 0;
        }

        self.expires_at - now
    }

    /// Increase the interval by `by` seconds
    pub fn increase_interval(&mut self, by: u64) {
        self.interval += by;
    }

    /// Ciba response attached to this handle
    pub fn response(&self) -> &CibaAuthResponse {
        &self.response
    }

    /// Performs token request using the ciba grant type
    pub async fn grant_async<T: OidcHttpClient>(
        &mut self,
        http_client: &T,
    ) -> OidcReturnType<CibaGrantResponse> {
        if self.expired() {
            return Err(Box::new(OidcClientError::new_rp_error(
                "auth_req_id has expired",
                None,
            )));
        }

        if ((self.now)() - self.last_requested) < self.interval {
            return Ok(CibaGrantResponse::Debounced);
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
            "urn:openid:params:grant-type:ciba".to_owned(),
        );

        body.insert(
            "auth_req_id".to_string(),
            self.response.auth_req_id.to_owned(),
        );

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
                            self.increase_interval(5);
                            return Ok(CibaGrantResponse::SlowDown);
                        }
                        if sbe.error == "authorization_pending" {
                            return Ok(CibaGrantResponse::AuthorizationPending);
                        }
                        if sbe.error == "expired_token" {
                            return Ok(CibaGrantResponse::ExpiredToken);
                        }
                        if sbe.error == "access_denied" {
                            return Ok(CibaGrantResponse::AccessDenied);
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
                .validate_id_token_async(
                    ValidateIdTokenParams::new(token_set, "ciba", http_client)
                        .auth_req_id(self.response.auth_req_id.clone()),
                )
                .await?;
        }

        Ok(CibaGrantResponse::Successful(Box::new(token_set)))
    }
}
