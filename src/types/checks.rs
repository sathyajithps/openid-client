/// # StateCheck
/// Represents the StateCheck
pub enum StateCheck {
    /// Expect no state parameter to be returned
    ExpectNoState,
    /// Skip the state check
    Skip,
    /// Expect this exact state parameter
    Expected(String),
}

/// # MaxAgeCheck
/// Represents the MaxAgeCheck
#[derive(Clone)]
pub enum MaxAgeCheck {
    /// Skip the max age check
    Skip,
    /// Enforce the max age constraint with the given value
    MaxAge(u64),
}

/// # NonceCheck
/// Represents the NonceCheck
#[derive(Clone)]
pub enum NonceCheck {
    /// Expect no nonce parameter to be returned
    ExpectNoNonce,
    /// Expect this exact nonce parameter
    Nonce(String),
}
