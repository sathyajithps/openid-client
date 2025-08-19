use crate::{errors::OpenIdError, types::JwtSigningAlg};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// # JwkType
/// Represents the JwkType
#[derive(PartialEq, Copy, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JwkType {
    /// OCT - Shared Key
    Oct,
    /// RSA
    Rsa,
    /// Elliptic curve
    Ec,
    /// OKP
    Okp,
}

impl From<JwtSigningAlg> for JwkType {
    fn from(alg: JwtSigningAlg) -> Self {
        match alg {
            JwtSigningAlg::HS256 | JwtSigningAlg::HS384 | JwtSigningAlg::HS512 => Self::Oct,
            JwtSigningAlg::RS256
            | JwtSigningAlg::RS384
            | JwtSigningAlg::RS512
            | JwtSigningAlg::PS256
            | JwtSigningAlg::PS384
            | JwtSigningAlg::PS512 => Self::Rsa,
            JwtSigningAlg::ES256
            | JwtSigningAlg::ES384
            | JwtSigningAlg::ES512
            | JwtSigningAlg::ES256K => Self::Ec,
            JwtSigningAlg::EdDSA => Self::Okp,
        }
    }
}

impl JwkType {
    /// Gets the key type as string
    pub fn get_kty(&self) -> &'static str {
        match self {
            JwkType::Oct => "oct",
            JwkType::Rsa => "RSA",
            JwkType::Ec => "EC",
            JwkType::Okp => "OKP",
        }
    }
}

// TODO: Check if serialization fails if a kty is present in the params
/// Represents a JSON Web Key (JWK).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    kty: JwkType,
    /// The key fields as a JSON map (key-value pairs).
    #[serde(flatten)]
    pub(crate) params: Map<String, Value>,
}

/// Represents a JSON Web Key Set (JWKS) as returned by the jwks_uri endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksResponse {
    /// The array of JSON Web Keys
    pub keys: Vec<Jwk>,
}

impl TryFrom<&str> for Jwk {
    type Error = OpenIdError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let map: Map<String, Value> =
            serde_json::from_str(value).map_err(|e| OpenIdError::new_error(e.to_string()))?;

        let kty_str = map
            .get("kty")
            .and_then(|v| v.as_str())
            .ok_or_else(|| OpenIdError::new_error("Missing 'kty' field"))?;

        let kty = match kty_str {
            "oct" => JwkType::Oct,
            "RSA" => JwkType::Rsa,
            "EC" => JwkType::Ec,
            "OKP" => JwkType::Okp,
            _ => {
                return Err(OpenIdError::new_error(format!(
                    "Unsupported kty: {}",
                    kty_str
                )))
            }
        };

        Ok(Jwk { kty, params: map })
    }
}

impl Jwk {
    /// Construct new [Jwk]
    pub fn new(key_type: JwkType, params: Option<Map<String, Value>>) -> Self {
        let mut params = params.unwrap_or_default();

        params.insert(
            "kty".to_owned(),
            Value::String(key_type.get_kty().to_owned()),
        );

        Self {
            kty: key_type,
            params,
        }
    }

    /// Returns the [JwkType] of the key
    pub fn key_type(&self) -> JwkType {
        self.kty
    }

    /// Clones the innner map
    pub fn as_map(&self) -> Map<String, Value> {
        self.params.clone()
    }

    /// Get a parameter of [Jwk]
    pub fn get_param(&self, key: &str) -> Option<&Value> {
        self.params.get(key)
    }

    /// Create a [Jwk] from a symmetric key
    pub fn from_symmetric_key(key: &[u8]) -> Self {
        let mut params = Map::new();

        params.insert("k".to_string(), Value::String(base64_url::encode(key)));
        params.insert("kty".to_string(), Value::String("oct".to_owned()));

        Self {
            kty: JwkType::Oct,
            params,
        }
    }

    /// Get the publick key of jwk. Discards unknown parameters.
    ///
    /// This method extracts the parameters but does not check the validity of the values.
    pub fn extract_public_key_jwk(&self) -> Option<Jwk> {
        match self.kty {
            JwkType::Rsa => {
                let n = self.params.get("n")?;
                let e = self.params.get("e")?;

                let mut public_key = Map::new();
                public_key.insert("kty".to_string(), Value::String("RSA".to_string()));
                public_key.insert("n".to_string(), n.clone());
                public_key.insert("e".to_string(), e.clone());

                if let Some(use_param) = self.params.get("use") {
                    public_key.insert("use".to_string(), use_param.clone());
                }
                if let Some(alg) = self.params.get("alg") {
                    public_key.insert("alg".to_string(), alg.clone());
                }
                if let Some(kid) = self.params.get("kid") {
                    public_key.insert("kid".to_string(), kid.clone());
                }

                Some(Jwk::new(JwkType::Rsa, Some(public_key)))
            }
            JwkType::Ec => {
                let crv = self.params.get("crv")?;
                let x = self.params.get("x")?;
                let y = self.params.get("y")?;

                let mut public_key = Map::new();
                public_key.insert("kty".to_string(), Value::String("EC".to_string()));
                public_key.insert("crv".to_string(), crv.clone());
                public_key.insert("x".to_string(), x.clone());
                public_key.insert("y".to_string(), y.clone());

                if let Some(use_param) = self.params.get("use") {
                    public_key.insert("use".to_string(), use_param.clone());
                }
                if let Some(alg) = self.params.get("alg") {
                    public_key.insert("alg".to_string(), alg.clone());
                }
                if let Some(kid) = self.params.get("kid") {
                    public_key.insert("kid".to_string(), kid.clone());
                }

                Some(Jwk::new(JwkType::Ec, Some(public_key)))
            }
            JwkType::Okp => {
                let crv = self.params.get("crv")?;
                let x = self.params.get("x")?;

                let mut public_key = Map::new();
                public_key.insert("kty".to_string(), Value::String("OKP".to_string()));
                public_key.insert("crv".to_string(), crv.clone());
                public_key.insert("x".to_string(), x.clone());

                if let Some(use_param) = self.params.get("use") {
                    public_key.insert("use".to_string(), use_param.clone());
                }
                if let Some(alg) = self.params.get("alg") {
                    public_key.insert("alg".to_string(), alg.clone());
                }
                if let Some(kid) = self.params.get("kid") {
                    public_key.insert("kid".to_string(), kid.clone());
                }

                Some(Jwk::new(JwkType::Okp, Some(public_key)))
            }
            JwkType::Oct => None,
        }
    }

    /// Get the private key of jwk. Discards unknown parameters.
    ///
    /// This method extracts the parameters but does not check the validity of the values.
    pub fn extract_private_key_jwk(&self) -> Option<Jwk> {
        match self.kty {
            JwkType::Rsa => {
                let n = self.params.get("n")?;
                let e = self.params.get("e")?;
                let d = self.params.get("d")?;

                let mut private_key = Map::new();
                private_key.insert("kty".to_string(), Value::String("RSA".to_string()));
                private_key.insert("n".to_string(), n.clone());
                private_key.insert("e".to_string(), e.clone());
                private_key.insert("d".to_string(), d.clone());

                if let Some(p) = self.params.get("p") {
                    private_key.insert("p".to_string(), p.clone());
                }
                if let Some(q) = self.params.get("q") {
                    private_key.insert("q".to_string(), q.clone());
                }
                if let Some(dp) = self.params.get("dp") {
                    private_key.insert("dp".to_string(), dp.clone());
                }
                if let Some(dq) = self.params.get("dq") {
                    private_key.insert("dq".to_string(), dq.clone());
                }
                if let Some(qi) = self.params.get("qi") {
                    private_key.insert("qi".to_string(), qi.clone());
                }
                if let Some(oth) = self.params.get("oth") {
                    private_key.insert("oth".to_string(), oth.clone());
                }
                if let Some(r) = self.params.get("r") {
                    private_key.insert("r".to_string(), r.clone());
                }
                if let Some(t) = self.params.get("t") {
                    private_key.insert("t".to_string(), t.clone());
                }

                if let Some(use_param) = self.params.get("use") {
                    private_key.insert("use".to_string(), use_param.clone());
                }
                if let Some(alg) = self.params.get("alg") {
                    private_key.insert("alg".to_string(), alg.clone());
                }
                if let Some(kid) = self.params.get("kid") {
                    private_key.insert("kid".to_string(), kid.clone());
                }

                Some(Jwk::new(JwkType::Rsa, Some(private_key)))
            }
            JwkType::Ec => {
                let crv = self.params.get("crv")?;
                let x = self.params.get("x")?;
                let y = self.params.get("y")?;
                let d = self.params.get("d")?;

                let mut private_key = Map::new();
                private_key.insert("kty".to_string(), Value::String("EC".to_string()));
                private_key.insert("crv".to_string(), crv.clone());
                private_key.insert("x".to_string(), x.clone());
                private_key.insert("y".to_string(), y.clone());
                private_key.insert("d".to_string(), d.clone());

                if let Some(use_param) = self.params.get("use") {
                    private_key.insert("use".to_string(), use_param.clone());
                }
                if let Some(alg) = self.params.get("alg") {
                    private_key.insert("alg".to_string(), alg.clone());
                }
                if let Some(kid) = self.params.get("kid") {
                    private_key.insert("kid".to_string(), kid.clone());
                }

                Some(Jwk::new(JwkType::Ec, Some(private_key)))
            }
            JwkType::Okp => {
                let crv = self.params.get("crv")?;
                let x = self.params.get("x")?;
                let d = self.params.get("d")?;

                let mut private_key = Map::new();
                private_key.insert("kty".to_string(), Value::String("OKP".to_string()));
                private_key.insert("crv".to_string(), crv.clone());
                private_key.insert("x".to_string(), x.clone());
                private_key.insert("d".to_string(), d.clone());

                if let Some(use_param) = self.params.get("use") {
                    private_key.insert("use".to_string(), use_param.clone());
                }
                if let Some(alg) = self.params.get("alg") {
                    private_key.insert("alg".to_string(), alg.clone());
                }
                if let Some(kid) = self.params.get("kid") {
                    private_key.insert("kid".to_string(), kid.clone());
                }

                Some(Jwk::new(JwkType::Okp, Some(private_key)))
            }
            JwkType::Oct => None,
        }
    }

    /// Checks if a [Jwk] is a valid public key structurally
    pub fn is_valid_public_key(&self) -> bool {
        match self.kty {
            JwkType::Rsa => {
                self.params
                    .get("n")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.is_empty())
                    && self
                        .params
                        .get("e")
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| !s.is_empty())
            }
            JwkType::Ec => {
                self.params
                    .get("crv")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.is_empty())
                    && self
                        .params
                        .get("x")
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| !s.is_empty())
                    && self
                        .params
                        .get("y")
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| !s.is_empty())
            }
            JwkType::Okp => {
                self.params
                    .get("crv")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.is_empty())
                    && self
                        .params
                        .get("x")
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| !s.is_empty())
            }
            JwkType::Oct => false,
        }
    }

    /// Checks if a [Jwk] is a valid private key structurally
    pub fn is_valid_private_key(&self) -> bool {
        match self.kty {
            // Add validation for multiprime check?
            JwkType::Rsa => {
                let has_basic_params = self
                    .params
                    .get("n")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.is_empty())
                    && self
                        .params
                        .get("e")
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| !s.is_empty())
                    && self
                        .params
                        .get("d")
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| !s.is_empty());

                if !has_basic_params {
                    return false;
                }

                let has_p = self
                    .params
                    .get("p")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.is_empty());
                let has_q = self
                    .params
                    .get("q")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.is_empty());
                let has_dp = self
                    .params
                    .get("dp")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.is_empty());
                let has_dq = self
                    .params
                    .get("dq")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.is_empty());
                let has_qi = self
                    .params
                    .get("qi")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.is_empty());

                let crt_count = [has_p, has_q, has_dp, has_dq, has_qi]
                    .iter()
                    .filter(|&&x| x)
                    .count();
                crt_count == 0 || crt_count == 5
            }
            JwkType::Ec => {
                self.params
                    .get("crv")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.is_empty())
                    && self
                        .params
                        .get("x")
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| !s.is_empty())
                    && self
                        .params
                        .get("y")
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| !s.is_empty())
                    && self
                        .params
                        .get("d")
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| !s.is_empty())
            }
            JwkType::Okp => {
                self.params
                    .get("crv")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.is_empty())
                    && self
                        .params
                        .get("x")
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| !s.is_empty())
                    && self
                        .params
                        .get("d")
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| !s.is_empty())
            }
            JwkType::Oct => self
                .params
                .get("k")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty()),
        }
    }
}
