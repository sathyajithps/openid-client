use crate::errors::OpenIdError;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// # JwkType
/// Represents the JwkType
#[derive(PartialEq, Copy, Clone, Debug, Serialize, Deserialize)]
pub enum JwkType {
    /// OCT - Shared Key
    #[serde(rename = "oct")]
    OCT,
    /// RSA
    #[serde(rename = "RSA")]
    RSA,
    /// Elliptic curve
    #[serde(rename = "EC")]
    EC,
    /// OKP
    #[serde(rename = "OKP")]
    OKP,
}

impl JwkType {
    /// Creates [JwkType] from algorithm
    pub fn from_alg_str(alg: &str) -> Option<JwkType> {
        match alg {
            "HS256" | "HS384" | "HS512" => Some(Self::OCT),
            "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => Some(Self::RSA),
            "ES256" | "ES384" | "ES512" | "ES256K" => Some(Self::EC),
            "EdDSA" => Some(Self::OKP),
            _ => None,
        }
    }

    /// Creates [JwkType] from key type
    pub fn from_kty_str(alg: &str) -> Option<JwkType> {
        match alg {
            "oct" => Some(Self::OCT),
            "RSA" => Some(Self::RSA),
            "EC" => Some(Self::EC),
            "OKP" => Some(Self::OKP),
            _ => None,
        }
    }
}

impl JwkType {
    /// Gets the key type as string
    pub fn get_kty(&self) -> &'static str {
        match self {
            JwkType::OCT => "oct",
            JwkType::RSA => "RSA",
            JwkType::EC => "EC",
            JwkType::OKP => "OKP",
        }
    }
}

/// Represents a JSON Web Key (JWK).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
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

        Ok(Jwk { params: map })
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

        Self { params }
    }

    /// Returns the [JwkType] of the key
    pub fn key_type(&self) -> Option<JwkType> {
        self.params
            .get("kty")
            .and_then(|kty| kty.as_str().map(JwkType::from_kty_str))
            .flatten()
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

        Self { params }
    }

    /// Get the publick key of jwk. Discards unknown parameters.
    ///
    /// This method extracts the parameters but does not check the validity of the values.
    pub fn extract_public_key_jwk(&self) -> Option<Jwk> {
        match self.key_type() {
            Some(JwkType::RSA) => {
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

                Some(Jwk::new(JwkType::RSA, Some(public_key)))
            }
            Some(JwkType::EC) => {
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

                Some(Jwk::new(JwkType::EC, Some(public_key)))
            }
            Some(JwkType::OKP) => {
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

                Some(Jwk::new(JwkType::OKP, Some(public_key)))
            }
            Some(JwkType::OCT) => None,
            None => None,
        }
    }

    /// Get the private key of jwk. Discards unknown parameters.
    ///
    /// This method extracts the parameters but does not check the validity of the values.
    pub fn extract_private_key_jwk(&self) -> Option<Jwk> {
        match self.key_type() {
            Some(JwkType::RSA) => {
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

                Some(Jwk::new(JwkType::RSA, Some(private_key)))
            }
            Some(JwkType::EC) => {
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

                Some(Jwk::new(JwkType::EC, Some(private_key)))
            }
            Some(JwkType::OKP) => {
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

                Some(Jwk::new(JwkType::OKP, Some(private_key)))
            }
            Some(JwkType::OCT) => None,
            None => None,
        }
    }

    /// Checks if a [Jwk] is a valid public key structurally
    pub fn is_valid_public_key(&self) -> bool {
        match self.key_type() {
            Some(JwkType::RSA) => {
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
            Some(JwkType::EC) => {
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
            Some(JwkType::OKP) => {
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
            Some(JwkType::OCT) => false,
            None => false,
        }
    }

    /// Checks if a [Jwk] is a valid private key structurally
    pub fn is_valid_private_key(&self) -> bool {
        match self.key_type() {
            // Add validation for multiprime check?
            Some(JwkType::RSA) => {
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
            Some(JwkType::EC) => {
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
            Some(JwkType::OKP) => {
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
            Some(JwkType::OCT) => self
                .params
                .get("k")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty()),

            None => false,
        }
    }
}
