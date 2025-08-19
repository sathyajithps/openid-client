use std::str::FromStr;

use crate::{
    helpers::base64_url_encode,
    jwk::{Jwk, JwkType},
    types::{Header, OpenIdCrypto, Payload},
};
use base64::Engine;
use ed25519_dalek::{SigningKey, SECRET_KEY_LENGTH};
use elliptic_curve::{JwkEcKey, SecretKey};
use jsonwebtoken::{crypto, Algorithm, DecodingKey, EncodingKey};
use rsa::{pkcs1::EncodeRsaPrivateKey, pkcs8::EncodePrivateKey, BigUint, RsaPrivateKey};
use serde_json::{Map, Value};

// Note for future - Use https://github.com/conradludgate/delicious?
// Its not a popular lib

/// Provides JWS only crypto. JWE is not supported.
/// Use OpenSSL Crypto feature (openssl_crypto) for JWE
pub struct JwsOnlyCrypto;

impl OpenIdCrypto for JwsOnlyCrypto {
    fn jwe_serialize(
        &self,
        _payload: String,
        _header: Header,
        _jwk: &Jwk,
    ) -> Result<String, String> {
        Err("JWE not implemented. Use OpenSSL Crypto feature (openssl_crypto) for JWE".to_owned())
    }

    fn jwe_deserialize(&self, _jwe: String, _jwk: &Jwk) -> Result<String, String> {
        Err("JWE not implemented. Use OpenSSL Crypto feature (openssl_crypto) for JWE".to_owned())
    }

    fn jws_serialize(&self, payload: Payload, header: Header, jwk: &Jwk) -> Result<String, String> {
        let encoding_key = match jwk.key_type() {
            JwkType::Oct => {
                let secret_b64_url = get_jwk_param(jwk, "k")?;

                EncodingKey::from_secret(&base64_url_to_buf(secret_b64_url)?)
            }
            JwkType::Rsa => {
                let n_b64url = get_jwk_param(jwk, "n")?;

                let e_b64url = get_jwk_param(jwk, "e")?;

                let d_b64url = get_jwk_param(jwk, "d")?;

                let p_b64url = get_jwk_param(jwk, "p")?;

                let q_b64url = get_jwk_param(jwk, "q")?;

                let n_buf = base64_url_to_buf(n_b64url)?;
                let e_buf = base64_url_to_buf(e_b64url)?;
                let d_buf = base64_url_to_buf(d_b64url)?;
                let p_buf = base64_url_to_buf(p_b64url)?;
                let q_buf = base64_url_to_buf(q_b64url)?;

                let n = BigUint::from_bytes_be(&n_buf);
                let e = BigUint::from_bytes_be(&e_buf);
                let d = BigUint::from_bytes_be(&d_buf);
                let p = BigUint::from_bytes_be(&p_buf);
                let q = BigUint::from_bytes_be(&q_buf);

                let rsa_private_key = RsaPrivateKey::from_components(n, e, d, vec![p, q])
                    .map_err(|e| e.to_string())?;

                let der_document = rsa_private_key.to_pkcs1_der().map_err(|e| e.to_string())?;

                EncodingKey::from_rsa_der(der_document.as_bytes())
            }
            JwkType::Ec => {
                let mut filtered_ec_keys = Map::new();

                let expected_keys = ["kty", "crv", "x", "y", "d"];

                for (key, value) in jwk.params.iter() {
                    if expected_keys.contains(&key.as_str()) {
                        filtered_ec_keys.insert(key.clone(), value.clone());
                    }
                }

                let ec_jwk: JwkEcKey = serde_json::from_value(Value::Object(filtered_ec_keys))
                    .map_err(|e| e.to_string())?;

                let der_document = if ec_jwk.crv() == "P-256" {
                    let ec_key = SecretKey::<p256::NistP256>::from_jwk(&ec_jwk)
                        .map_err(|e| e.to_string())?;

                    ec_key.to_pkcs8_der().map_err(|e| e.to_string())?
                } else if ec_jwk.crv() == "P-384" {
                    let ec_key = SecretKey::<p384::NistP384>::from_jwk(&ec_jwk)
                        .map_err(|e| e.to_string())?;

                    ec_key.to_pkcs8_der().map_err(|e| e.to_string())?
                } else {
                    return Err("Unsupported EC Curve".to_owned());
                };

                EncodingKey::from_ec_der(der_document.as_bytes())
            }
            JwkType::Okp => {
                let crv = get_jwk_param(jwk, "crv")?;
                if crv != "Ed25519" {
                    return Err("Invalid OKP Curve".to_owned());
                };

                let d_b64url = get_jwk_param(jwk, "d")?;

                let d_buf = base64_url_to_buf(d_b64url)?;

                let d_buf: [u8; SECRET_KEY_LENGTH] = d_buf
                    .try_into()
                    .map_err(|e| format!("Failed to convert Vec to array: {:?}", e))?;

                let okp_key = SigningKey::from_bytes(&d_buf);

                let der_document = okp_key.to_pkcs8_der().map_err(|e| e.to_string())?;

                EncodingKey::from_ed_der(der_document.as_bytes())
            }
        };

        let jsonwebtoken_alg =
            Algorithm::from_str(get_jwk_param(jwk, "alg")?).map_err(|e| e.to_string())?;

        let message = format!(
            "{}.{}",
            base64_url_encode(serde_json::to_string(&header.params).map_err(|e| e.to_string())?),
            base64_url_encode(serde_json::to_string(&payload.params).map_err(|e| e.to_string())?)
        );

        let signature = crypto::sign(message.as_bytes(), &encoding_key, jsonwebtoken_alg)
            .map_err(|e| e.to_string())?;

        Ok(format!("{message}.{signature}"))
    }

    fn jws_deserialize(&self, jws: String, jwk: &Jwk) -> Result<(Header, Payload), String> {
        let decoding_key = match jwk.key_type() {
            JwkType::Oct => {
                let secret_b64_url = get_jwk_param(jwk, "k")?;

                DecodingKey::from_secret(&base64_url_to_buf(secret_b64_url)?)
            }
            JwkType::Rsa => {
                let n = get_jwk_param(jwk, "n")?;

                let e = get_jwk_param(jwk, "e")?;

                DecodingKey::from_rsa_components(n, e).map_err(|e| e.to_string())?
            }
            JwkType::Ec => {
                let x = get_jwk_param(jwk, "x")?;

                let y = get_jwk_param(jwk, "y")?;

                DecodingKey::from_ec_components(x, y).map_err(|e| e.to_string())?
            }
            JwkType::Okp => {
                let crv = get_jwk_param(jwk, "crv")?;
                if crv != "Ed25519" {
                    return Err("Invalid OKP Curve".to_owned());
                };

                let x = get_jwk_param(jwk, "x")?;

                DecodingKey::from_ed_components(x).map_err(|e| e.to_string())?
            }
        };

        let parts: Vec<&str> = jws.split(".").collect();

        if parts.len() != 3 {
            return Err("Invalid JWS".to_owned());
        }

        let header = parts.first().ok_or("Header not found")?;
        let payload = parts.get(1).ok_or("Payload not found")?;

        let signature = parts.get(2).ok_or("Signature not found")?;
        let message = format!("{header}.{payload}");

        let jsonwebtoken_alg =
            Algorithm::from_str(get_jwk_param(jwk, "alg")?).map_err(|e| e.to_string())?;

        if let Ok(result) = crypto::verify(
            signature,
            message.as_bytes(),
            &decoding_key,
            jsonwebtoken_alg,
        ) {
            if result {
                let header = Header {
                    params: serde_json::from_str(&String::from_utf8_lossy(&base64_url_to_buf(
                        header,
                    )?))
                    .map_err(|e| e.to_string())?,
                };

                if header.params.contains_key("kid") && jwk.params.contains_key("kid") {
                    if let (Some(kid), Some(key_kid)) =
                        (header.params.get("kid"), jwk.params.get("kid"))
                    {
                        if kid != key_kid {
                            return Err("JWS verification failed kid mismatch".to_owned());
                        }
                    }
                }

                let payload = Payload {
                    params: serde_json::from_str(&String::from_utf8_lossy(&base64_url_to_buf(
                        payload,
                    )?))
                    .map_err(|e| e.to_string())?,
                };

                return Ok((header, payload));
            }
        }

        Err("JWS verification failed".to_owned())
    }
}

fn base64_url_to_buf(input: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|e| e.to_string())
}

fn get_jwk_param<'a>(jwk: &'a Jwk, key: &str) -> Result<&'a str, String> {
    jwk.get_param(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("Jwk does not contain parameter: {}", key))
}

#[cfg(test)]
mod jws_only_crypto_tests {
    use super::*;

    const JWK_HS256: &str = r#"{
    "kty": "oct",
    "k": "n3r3cKt0c0FaRcKGb8oREXm8StLeewv5tk88gxAYnsqLEfJja4rO27loi8W3UNnXlE4tdeOXS6QNhkUU7Qk4y-iizKdyx5XsAOkOfFvIZ673EfbeT1y5oCvl8itwvy9YaxbxSoefDoSZB5fLvPFJjRySE4QNtJbSzx_z5ojpAWAxSBbHDrlHcexGbby6zsZLrQinvwDA0l5CoezDYHHc401KPD1JzXKFZ-VslF6tIbpKH_K9WpozFZwX3vF1LrHItzwVf65hvMK8prSN31eoL8opLZIeZTJy_xcoBGD3wVD8PeyustH2Mw2k6TKNEPYFx22wjXI_IDMOSMMbj57l0Q",
    "alg": "HS256"
}"#;

    const JWK_HS384: &str = r#"{
    "kty": "oct",
    "k": "n3r3cKt0c0FaRcKGb8oREXm8StLeewv5tk88gxAYnsqLEfJja4rO27loi8W3UNnXlE4tdeOXS6QNhkUU7Qk4y-iizKdyx5XsAOkOfFvIZ673EfbeT1y5oCvl8itwvy9YaxbxSoefDoSZB5fLvPFJjRySE4QNtJbSzx_z5ojpAWAxSBbHDrlHcexGbby6zsZLrQinvwDA0l5CoezDYHHc401KPD1JzXKFZ-VslF6tIbpKH_K9WpozFZwX3vF1LrHItzwVf65hvMK8prSN31eoL8opLZIeZTJy_xcoBGD3wVD8PeyustH2Mw2k6TKNEPYFx22wjXI_IDMOSMMbj57l0Q",
    "alg": "HS384"
}"#;

    const JWK_HS512: &str = r#"{
    "kty": "oct",
    "k": "n3r3cKt0c0FaRcKGb8oREXm8StLeewv5tk88gxAYnsqLEfJja4rO27loi8W3UNnXlE4tdeOXS6QNhkUU7Qk4y-iizKdyx5XsAOkOfFvIZ673EfbeT1y5oCvl8itwvy9YaxbxSoefDoSZB5fLvPFJjRySE4QNtJbSzx_z5ojpAWAxSBbHDrlHcexGbby6zsZLrQinvwDA0l5CoezDYHHc401KPD1JzXKFZ-VslF6tIbpKH_K9WpozFZwX3vF1LrHItzwVf65hvMK8prSN31eoL8opLZIeZTJy_xcoBGD3wVD8PeyustH2Mw2k6TKNEPYFx22wjXI_IDMOSMMbj57l0Q",
    "alg": "HS512"
}"#;

    const JWK_RS256: &str = r#"{
    "p": "yuXoRLMkoiVD-M6n7xA4_CD3t0I0hmZ6YNO9Sn-dgUrh4ccRUYctyOC_uJ17Mcdlp2KALZiwVlDOWsv4Z6HsDNKgDVdB4WUiPXYfuX4pPKuNiXKQwLCcKqHkAmNZGvl9-8PH0k0H0GXUEUFRA2Dv33zbatrJnDSjnANFidEodvc",
    "kty": "RSA",
    "q": "rhvsOOz3ex8fNA20UGrrqK6vYKPP-_-H7rbOxdAfwqxxBb_MjHASbEU0S--XKprCn2zOOq_Y81pM3zrJZNGcifxwZ0VHb9Jh4uYKOF-hflovcF3l5LIz8LggBHkvHHjmwzcFUe0zesI-q3nae-_vM_sJTAd_5i3FWntgdOc4G20",
    "d": "NowbHxyoT72BeKmwPCdo6FNxdVSFsR116iWCdXHOd0aPw_P0NjFULlyfdZeS_bXIwYeEffsaXdnUeRebqMJCJo8-9BPNrgN8CLwSoyMsp70_hJ-yTG7kDhMz0rJBJlW8JZQR8KBPv-NZ0p59qznLn0qB3kqpefLvqlWb1zYI6SYhYXFhl_ryy3B-qxLK1Gj7jXeZOeZc8RM2iddKGBHFp_9V8eI033gEuQPeNriKDCsy3jihUNdsqYNnVULVAvRS-CWtlImbsGDC8G4VtjA0YpPIqFm_NjMSQf-dFbnd2ZsJfpX3ikycluwAQ8u1WO2rUI_H7shR6XqowcmOOcWBEQ",
    "e": "AQAB",
    "qi": "FFpNLRvQuLDo5cNTNsW-FR7V3cdNWlLQ7D8iOEnZh7SJstqfMeRe2p6hoH3Xn1LwQp_n3wLwOWTQL2nJX5uhfogoOMoMsznCQgCmxE0uESTuQj1Yv5yNNXeJjm1xYGEIX5-CRtdEi7XNieafFJSsw6OIAxm6FizarFC1504TeEg",
    "dp": "dstDQa3tfe35rRw54NOLubsHrklZ_XLUpgpy4sJzEncoZ4upDSXrXZiRR-MUdSG819LpH0ktvWvUVf7kcrCwRxWu1gDHttMCyB94FZ_TPw1mchocvGTrGl7s46UNT6jR5W1MeknVkGN-VZf7edHwv9YXlamBry52uGqF9Vn7qiM",
    "alg": "RS256",
    "dq": "mG-kE3cNeoOWCzoQa_Qg3bALpn3l5Akm107AnJqKpCPcVJ9HlJGu35J7phxf6pJS4cgei21Ycj_WW_-ZQibvejRFqXUThYjZ4RFtU0wPFZQaQrRDSkbniNN8XM5I_BGyYKp0gvU9hDY7LmDidG5urMEWs7VBOqNKTd0FZ3TlP8U",
    "n": "if5lV0E8Bsb0OPNrWu33V0KuSNRK67vYT3vxzJ3pXIY52oZvSotbpDmcDoldKMfBxuKruOzucH9NNNRPS7viIBIUOz1OBoiWe8MAuTRQCFHQi8L1d5oukq3me-ZYWY7vsCgTfnN2rvCe9aqptWgBWsvGnSqq7EyzCF9mwoiRnIFoo3cyPXloLPXX2kKS6m5XrXkH55g7ZsgGB8nTJ_QbcrgD5l3dWZWWxY0o19hw3Z01ke9Rv1fz1_iClfJ1r7AYmiSw35Eqa6M6UlTkkWyFui7Y2YTuUFEcA6-0ni_UMCJo8b6Ef9dRR1hlfev313PwaOI_sbrmn81JOvDcOc60Kw"
}"#;

    const JWK_RS384: &str = r#"{
    "p": "_F2mTRbOeTmAjBbAL4iyIeT2cIE60Ywsjh5xDF0nOYSvyQlZ58iCrANJaGha8BHW0ocrm8GtHHIwN8ptR5QID1rKjxTmL_xe_9WIdHmCcwAMJ0Rn5Rvk13-NzCJZ5BwkUJTo_UDnh98oNm2SP8WzLysTOjKYkjk8n1oiWO90UFs",
    "kty": "RSA",
    "q": "wgD_OHbW6Uke0JGX1h4APcgH2a7n-pd90LKuxEY0N0rBk_2mxmouEA87eDpJcNC6Fh76ghRNy2dTb5n3DTSK8k3i8PBZnX4NdYwIXybiGRQNdFbgb5Ega53PMoRFXxD78YkGzSP6HvS32gtbuTO5m8irVLvJgvREBLSOTgH_Njc",
    "d": "rovKaEd5hDJ3lLtv3oTAvZQkfIYifSp_ZyCnUKQb0syeGImT1l5MatzW9KoNAm1LQqmjzX05K4jwzN-5Bo9Rd069gDEUqos-hkkXvoXQtrW650Sz1bLAmYZ2CrW0MoOjZv_AG0ASMQlmeyDKH7b3xxJlkY0Rumu49IQYKi-LUc8x8PQjhDuS6hfYGzLn-Tqc502yuVbIbIVPuM3OtyCr3n_nEo6Oswu2O9k0-D7ftWtF0u0yQpmlBMF-elrzSmRbxZq-PM-rPWdnt018D4jIqUT2RNpAxIVUKXajbAczt88lUJABBHtVFnrKQazOMw0g28iHwnJRfwq9An7pHvVkbQ",
    "e": "AQAB",
    "qi": "G7gsu-Uxwvld146aO_-lI3t0MWkw4FRTIGymX7lsofCziQIF18WqE6YXSm9rIePUYaIi4HCp0r9b-gsfRlj4eyQDGlBZQaGHvUTYqIo1yJJ-obFg-3htBWEfEpwNLJn5tmlLyoqEKTZIV202uwPIijbkferbsUY0h0Ju_Z0RGg8",
    "dp": "DIq27hPZFQs3iT7ENFiNycNwP-0cODfIKxP2OFAU1_XxKoONdUhwvg23wzmUc2PfkjznfOkmKki-frdPsQP5VpIDiRLX0cCwE_TPwEIdqotxDy6GH0vAlrkfGesHHqALafnMjnGAUC9V90aAwyyXGBwC65yCGpo_mgfHtzXHSQs",
    "alg": "RS384",
    "dq": "YljtCOu9wN9vfp4AEex9hNRNnn27Xd7ESjL6w8cvG0SLY4F3tSgIl92Q8T7jEgzN-P7VUXIHifCkbHPpuMkFExaG0EuXsm4_VnKZn9rvTXVL6MlN12EDxWpnqh1BqZLLlcM4LnBpkJ3QQfn2Eqn1EtMkf7z-x6MahCQf6825Wfs",
    "n": "vz_zn12SqVwZulwvcq1G83noXmB1Y5ZNrASZPzNMQI--WYK5z9vsQ_0u17Dg36GxaQxMZycMn_7jfXZJPZy2aHEMBspjVlt34p7SlU1FsY7VwZ8a-oUTQcaAI8wAdpKUz1qmpo2LxLHKFS7TCDoAHrj-P88ehvALtgvF3sKeSfwROQNIEX30KEzuDLFiky_N3TkWsO-yiaGY74KjZe6klP58d0l67RYdyYrk9t84Q8YB8L_eNVr4AQ4fIzR5lIYJ7GXwDVIn0Q3Cdnha6ugxQ_zGlwJRGeDun0lI6W1X9t0O9O-CtvBxCAxJ3FZXB_cunsicL677Oa81IRKEYJV1jQ"
}"#;

    const JWK_RS512: &str = r#"{
    "p": "6SIA9wYd_xJUZh_4kwEyhG7h57rHvn4GfssOPsSXK7lN37fMY_bvQGxOjRiDKtNk3HYN4Dl5CADjfKvciUe13bRpEJxrdrNqLaPYoObWk2anehXv0Wd1Iu04w7ezEiFxSLj82Q_mIlRXjNVVf5zbY2poUy8DguQrovgLF_YCPxc",
    "kty": "RSA",
    "q": "whp4HVryE8T0InxLPlRbI20iUOxZvLgkwa7ysv8SmsJ1e8TGccbofyh4xkpFCfhP4KxbQbzxI5T78vEIK9ot8vSxv3P7DPqp2NQfdUKyV-pqDa_IJrswH3w0YiVoIfyRRV5zTT1kyaBHMBGQtgtmkt0W3u8es7Csw6OdoCvzZ8U",
    "d": "QgboW_3YsCkA2Up0kLuaI-MZfpI0iL5FJ8AEwF11xCKfwTSkjeBrBkp-5D3gRt64A_brBMmbAU-GJU7HaE8CEUcmGeosohQxlUDQ8H1B4ucQ6o08XXZ8D6511tBbbk_98_vOy54GSEa6HfbkxAfXpmlJlO5A6DDd3v5-NwNGR6Y1tBWj1rfYHRvoxRg5RW8s9VjWkOMaXpfgKpS7iTzEVYzKC-KC2Xsc8bDPOli-G_Rt2YpTaLRUB5xczLIBTSvix2YYdvslHrrz4GWX_eYo_wE8MiTwQv09-icOanETLfe_xArFB9BpKBQ5vtDRs9FzC2BajQ7AhX0FpOGtQQFvAQ",
    "e": "AQAB",
    "qi": "mw4o1oqUQnRI_dIB7gZGg34aaZEm4OYcwmkD0MH-OqIW7AGHz3b4FE7IKD_NMZXJ8rE8RJEao6JGwh5zbULnaa3-DYnN1kKGu99a5XcJzr1hzACKBamtIwe0kuAsX8dCZJ5OCCxFj7RWeQMsodri6s3oFk1YKovRddWW5W_57HE",
    "dp": "DwBCIaMCIRyT07Jw8zybfIwJ-zg4jBhd4KC-POm3dHfK-_8-ppwIDxQpBcky_3l0vv7Vq7zm_c3Y1XfVi_vSRv7J1-jIvW2UAnXNhaT03602T5PDx6ypi-LJyUYzvpHqUSyeEHWGcGUO8R_1DW4Ra9c3-UpIJo76A9WEGTmaMWc",
    "alg": "RS512",
    "dq": "qu8IbEGVAZfmrx_qW1-KSy5mlAEwHaPEqtRYYw2B4svxDigB4lyajrCje2wYVGlaXq8qRkAP05f2MMHWwleHM3gNuF547bspLAvSED_GMun6r0bn6kPaYz_MGcp7Y8K6Y-6Dd7fjNDRzvH8bg1WS5S7SX00RKokh-7_wpgdOeUk",
    "n": "sMPfkffZqa4w4ap6F-21Xqylqh6m7subVg6FMOFxy2HBdldmwtASebMWPYpA-ErypHb0Ph_J5wMW-TD9kHbn6KvqQm3Un_eBRSDcCjALts6uMoLqseQoOKoOHCyyryLuTj2aWNBVZjOPRnPQbY8uVFbW0hGhMmHHRufgbx3BM6v5JdYGdBeXPjo0oEp-UaBA1mNiP_7L4LEYWGxtj2D3MqfpodmZITWupf02Y4jhWh9BzFOENhPMgUvn1_Hnp4ykBTlDfAZuiJloIpFFt7zcT9Y_sVFCgijIgz8OnzFD1deHsHqeTC2mmz5haNmqfsuSMEZebjXDrT-WJZuF9vHNsw"
}"#;

    const JWK_PS256: &str = r#"{
    "p": "-yYbGnejMXAWd1fzHnxFkpYpO8SxjRRKdGjhEdb8FUFvoM5GniCEtIie_1_twFrTx2MRPOrtsdhPCuLjLuWislpxMOEMpY6LI3R5df2PHUS-4vpHCYr1yAEN7cZF6iInMqgkn1HaCGA4AIx5oJMJCNVUySgLIgbpclrj9wBjuoM",
    "kty": "RSA",
    "q": "1XE6t56dSERCXnUGrFOOuBwDhtSkN2hxfpUcxYdu8gUdTZTNBw2LAUewOjRbsa3MgtvpOXDZQr7k-vMXp66iKq2dWlG9PHCaLlvdu9fcWFVztHPrAxL5ex8Amt7qaG43CSzI4TtxJP7ryZ73vjlopVwt_ZYaLhsJKUUedbQ6xeU",
    "d": "zbkmZRXVAnq1DlUlNmnIPMcmg6OabDolMfdv-YDt3DYCP8CfBJ5i0jN-PG6NFv3_9YyIztpkVGpiMrB6iHnYshgSKz25MqmlqwrbrARPwXYKwu6I4iXMm2DOalIyhxVP73wzZ_u0Sdd-Syj1JjFQV8PXQEQs5UPeEYKP08c067n6ce5avryjtjq7Ou4RJBrcAQ_cmPMCy2uKuRKyD84fhWMKrtcAJ7yXu885CpIgftlqQVgbBQ5yk4tpt9wVgHYkTb7YLA6nkGYwwavCl5chZjuPaTMmO4EAVFEHGsIAd393_GDFk2_YKJv2jDEsXMYG3ENfniJT0NdSFcmLZCltWQ",
    "e": "AQAB",
    "qi": "WDX2qSjtUvKJju5Pbr3q80-kmpicbTf97-g-SA2oJq3VhRDubwaIwDKJH1JDs7lJyolDTuapsRsZQ9SSI4WP0GvBvHD6qgN6BIwITPzAZqJe-Jb4aIWy8meoJYyJmfxJmrvhiwsd5pGsNMwCYVkVZx_x1kYBHNCHmK0DluGluh0",
    "dp": "BJRWTC5ASId9sWFmKnkjn5-jUtasUiE7llHPQM8Fu7F8wpbgTMPVB6GyHH_4StidIfaZet3hxatnDZDDibhgNhZWGAkSfPZTbSsTh-Y-tM7rGCJuJytkfegfA-XoonNK-a59NHZ-nkZ63u-wzA_CS2nwaNaVFWLA4PftTjSwnNc",
    "alg": "PS256",
    "dq": "r-_Oq66mDPyfDIdAQen6WY5V5dz_o-CGtQWqmrPhYsOOfPWr7yVdsGdsPv4LmzEcw70LyNpZa-g4jRa2J_UOHUnQy7NW3iwfGxmEc6MiMPn3DwcB8B3C4ZcTg5U9-WjoGrr8tpOt1wX-S8qqgfWGac_K5R3GZLzKV2dvDSzLyXU",
    "n": "0WXJ-cI2yDA39C0iHa41jOjUS6GSPTE3UWT0DEwY6PFh2fISQSvph7yJpbmblNYb7uvW3skf4uw0xe8PMB9d9KPHWQqIuATFwEBnyK-4dKlok1aXdn2ACNUOCyiygnt7POyUu72-52BDMDallFEmxBI0usW2jcssOuT2_u03ZI8EhVHCiY1cO_HhKqaHK2dNokhL2SjWk1nLl8V3eolq_6VAngfumldzRg-vPjAtseDaH3-H-P8REQCuqwTRvRa3rk3bSCB7TEItfi73iyXUEY0-9NwE7A0a5tcWNFTk7tAQNwJ6qAqmWZPyuZ87MJF0cJYcZx6pOf6stczbdWqmLw"
}"#;

    const JWK_PS384: &str = r#"{
    "p": "2KdLtpbx-mbVzzde83MjBI-N8FSEYd2zawfJtKcvzpUj5d7g33nXwF_987wkipsijEMbL4skbbspCA5n8xNJwxiqn8r252wU0lyDyKcqm5evj7MzvajeMTl2ZrDpIBY8SRRbSrI1qeJNMHA1rX7pSVH3GpJ4aMvPrp8-bBcylzM",
    "kty": "RSA",
    "q": "nw6I9RNo65NRNANrhUbImBzRFvPFH-ABFbPrP0ocvAVQJ7Z90cHTSy4vHHvs2YSXBpYHx6jPEHqYqwksjHHP9nG1bF-EhsWn4of5VB2EC4FkzdruvKP08i4Ye8wUlmDAQbM3MwIvc8rF6Hs7aosxZutc7iC2iKn1kBSn0CT0ybU",
    "d": "Cql-ztqR8MhQXu-_TIS2FxY9s7wwDOURNb3_t3xnO67daA7HeyY4gnGZwrmcfjKdhGCXasDFMD4eyPy3iC5uKZVI-krBgaX4B-ugw--aJxVtsTI2l04c7aPAUEJDL-saZGGro36phD6sty3ZYEpElnD00VQSfGwUxFKgWO0-gJvggAcfBqKb2Ggofh6-4ahel8baBHoUXIGbsnxuuZFQXFjUR7Bn5kxQNF8IWri-05BfRi_K6y3KjK4L7oG0Zc9I17TfIr6VJ72xXPy6xN-0tO7IKHIK5C-Xsl-zTq5kkX_R3G_Ir6fRmwQGXA3LKI5Z-4ChKnPP9xivI4dCmPZiGQ",
    "e": "AQAB",
    "qi": "lEGiwegm53Vip4_47OrJia0u1XmDoabV2XiRn645DDN7C2fB48IVa6wJVgYlTybUZazGO4plghaU0kTfmwiZNGWCozwqTEq4Mvi37z6rhxqZQnon6JsUleLlItEv5pZpivqXzn9UacfzRs6bKRTaA4IeYrg_rCuTVDBt-uegqc8",
    "dp": "RDPOIum7vT8YOcZNjsgFEw95-Fky33giXiQyfDtRUnAiv9983P0HTVkqocrtmfCiXJNXgI0F58FOdmnKkXvV8aPXOrxzI4EjwOE83zK4uAh1TQB13lPFtqtHOaahjOdTDRJqdsZJHHTQJdp9G2PjXqB98JCBdUQL2gXpaa-Xzn8",
    "alg": "PS384",
    "dq": "TuJPjHR26bbjZA96KNxFKiPIk0CM-FUJVLEpr_bar2lXKor4dapSV4vtM4xGmE6I9Gw-KYiQQVT8GH9xR6o-gLQ-TSRGPu0SaWgUgOIuleIzk2DMXGRYXC_-Vo-NelM7ppnye2rPC_d6FeXgPuQPuUJrkXJJ9ReNwUptO-7INK0",
    "n": "hpw1FNR-N6Qhsfza-giDK8J-DQOW6VIEk7ZLhuKxPxSFGbPuid-IfZB0_nCytlO5huKMUkS-aQJeWNfVPOdPQG3OK3vSpith4xV8gG_ztG1SoqPRUrzka4rr1IgVzoA8u2eD-mSOXv4GgKTwxKe31g8N3zMIdRq9GRJtjvKCL_Wvuovh81Mt7h6TGTfndfmhUPYGNq-h7I3Mu-kXJ3_Tn7CxiSxenS03FgEb8bLhDpKbHI4V4Evz5sgXbasH54URnmIpC9fLau-0YjM5jKIbEljrWawWGdsSiWiZhOqKhNBsBNrLZjRa6yU3AaQ-xRY6K2hJW3-L3USKnFiOaBfyDw"
}"#;

    const JWK_PS512: &str = r#"{
    "p": "937Ls_XFLFGoeDVGt6O306LV2nw-aYndh_jKOCh94Ti5eiKCCIG_FvCNNgrKpwLuzxfL-2eXkj4fHh7gIHAhksdwbPEJtw-W0pBpJtMp4GHz4xIlDa0E8JeEmptdSigkXKeW-dUGqF3cqw-uiBI5JQrv2s4KISekDKTFb5C7NiM",
    "kty": "RSA",
    "q": "xB4XnO-W6U_c270qq6OSBzJ5G8WtovdQEMfAApT5eWUyILRVFIKcQVaktQ3mFuFnhSdtSU0goEJ4cq-eudp5cqjTZNk3pYi2mrc_y6o59XOzpoFOYY5XaC7bn-NSsGx5uimpSGFDvNXgn_mjXCqywaY04mczRuQC_GRzeEd8a5c",
    "d": "Yxz7oh0PP2iiXHRZqBzQzXn6CNL2mN1m9bOebNwD18RJfeFtd3TsqgbNg6OsD3737qq7ZiH0TaRXKQA3PVOB2T6ZiHAv7rHujc_zTn2snjTET5J1ycDZ9OpN8S8Gdv_mi2EUiAMBGwpH7MbcLFnzI5L6K-q61xcyq7ATBwWg-EKmaiQtyQgepZCfm0d_OCH2fWqH5SOXneZSaBtFC8slRgASsau79NO2zT2Ojg6wMz8nakJwE30uW9Z6vDPRwz9hnj_JbFJ09s00_FhYc9qkqZSvchqxE_hIOJMiJ0oZVZbJGOb032MuqwTx6FAaywDnwmdl7YF0zcfXTmBQYoW1hQ",
    "e": "AQAB",
    "qi": "VwgnUnN44bYHs03aXiSvnk5QfXez-eC4mKv52aaTN0gsgmkaIGpCupyb9rM6BS0SSO6CY0-k2CbpSyjSEIJ3MSz4N9qZdw3VSyKP9eb5bvelQ6KE2shqJwVtAbFbNdDW6cyZeUeGmuyer1V7GzoDJax_jy67MSJOaRoCOmvZcPc",
    "dp": "BAOrfCzFWPWuHN0IW5wtNCKVA2k2ffG9hSIU7ZpCiG-qGoAKyeaI2e9m6vR72v-iLfu91EMW40lcqdloWz5WXRIdEbdLKAv5r0qmWfnc2QXdtdYqgbFHvjtG7FcOyVAjXtldCopZBEwZczDa7NwWzzIBN_RVl7oT4BygEzIuxy8",
    "alg": "PS512",
    "dq": "mNlzQech0TljQwfOJ_PWLjHSXijVSbxC9LEaH2kIfuq2BPNHlDKvoeTrfgkVGSQYUJkH_idUlFL6GThzFxsFqK2YBHOfgS5qU28bE5rajUjd7Zm-Ax6zVQmgNp8vpT0GKmep_jWAW7690TD5dy34ICFv-jzApDG1egy4Sjg86oU",
    "n": "vZorpcR0VdAsokNQIYZt7_wcU6O5spHvt91rE62ojihYjN0AX202GbdhAPFjmDb-RWjRLSbDV8EWb1mxr1UkkYmcmADW9dBhM0HwKWAB4dYgxuDqyYXaP0s_NLnDcXFNTCoN86q7eFrT7X0xlsnMWLqtAn69M7t5udqVR1RufMeQiEptptJdNwweMlsbyztJwfhEuUD-iOOmtsN2XvxKQNK77tZwI0DK1L3W1AM3sWo0EOh6dHr_F3uZtDgLCt3FoNETtKivmezdo_CwZ5QYszlLxPrHD5yr4BlOGS7Z9fZpXwEoxVRToNmNs03dW0t-sxwl8RBR2p9xozZmjAGPpQ"
}"#;

    const JWK_ES256: &str = r#"{
    "kty": "EC",
    "d": "mZKvlwPYqPwYOPNDTC5eYrskeTeZKsiwi-01kE-HvGY",
    "crv": "P-256",
    "x": "x_YLaRgdiqG2xvIJCPaSxiy49j1MHsMBwpDBSIquceU",
    "y": "w-Ldf_OXRyjwr9Uc-WiqvzAfY-MEmVlJtRM5UhdkOQw",
    "alg": "ES256"
}"#;

    const JWK_ES384: &str = r#"{
    "kty": "EC",
    "d": "Q5eHxQ-Kd0FiRXLk6BZQD2tZeByoXWM8YXE394RmxuMwzvvvC63DvQ-RyynVPaBC",
    "crv": "P-384",
    "x": "iSfnaA8w2PjfiOX4OG8ymN3MS2Sgi5PKVYMAKgH4jMTSCRsTyfSWw2A_t870xitk",
    "y": "ja3lVCu6hCN10DPuE0qSPDAcyIN1FXpo7qLOIOKkmK2h06eJiY_gQKPSZi6sFoI1",
    "alg": "ES384"
}"#;

    const JWK_EDDSA_ED25519: &str = r#"{
    "kty": "OKP",
    "d": "D8cJfcLB0pLCRUC9uM43ispYfExCxLX78gSI7MZForQ",
    "crv": "Ed25519",
    "x": "dV_CEdInYbWjQDwIIrHY7F-KhOLcyC7DG6Sku0hSOFA",
    "alg": "EdDSA"
}"#;

    fn serialize(jwk_str: &str, alg: &str) -> Result<String, String> {
        let jwk = Jwk::try_from(jwk_str).unwrap();

        let mut header: Map<String, Value> = Map::new();
        header.insert("alg".to_owned(), Value::String(alg.to_owned()));

        let header = Header { params: header };

        let mut payload: Map<String, Value> = Map::new();
        payload.insert("iss".to_owned(), Value::String("client_id".to_owned()));

        let payload = Payload { params: payload };

        JwsOnlyCrypto.jws_serialize(payload, header, &jwk)
    }

    mod serialize {
        use super::*;

        #[test]
        fn should_serialize_with_oct_key_hs256() {
            let result = serialize(JWK_HS256, "HS256");

            assert!(result.is_ok());
            assert_eq!("eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJjbGllbnRfaWQifQ.bmi-11GfR1I1WnSL8qK-zCh30FWcwZ6kJkEvLW72_ts", result.unwrap());
        }

        #[test]
        fn should_serialize_with_oct_key_hs384() {
            let result = serialize(JWK_HS384, "HS384");

            assert!(result.is_ok());
            assert_eq!("eyJhbGciOiJIUzM4NCJ9.eyJpc3MiOiJjbGllbnRfaWQifQ.hEz5AG8lI9vB9STkwpNdji_J8Ksv5NPJwbO0ndPEtIkqyTUJbOIQpprf9EqrZa4J", result.unwrap());
        }

        #[test]
        fn should_serialize_with_oct_key_hs512() {
            let result = serialize(JWK_HS512, "HS512");

            assert!(result.is_ok());
            assert_eq!("eyJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJjbGllbnRfaWQifQ.yf2a5Yd9zB27CJQZwhAJXjB1Lt7qMDR1m9J53G4eDsiWdwivMZLEBg2DY8g9t3_DgR1sTZaqzjfPWjImIfZsTg", result.unwrap());
        }

        #[test]
        fn should_serialize_with_rsa_key_rs256() {
            let result = serialize(JWK_RS256, "RS256");

            assert!(result.is_ok());
            assert_eq!("eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJjbGllbnRfaWQifQ.QN8b_tWT0AwxeQsDlQD0vAkc64IeemAy4Zkpi7T-07Y0S2iic5uc3rv8AeWtOuHeWud7j3-ZiXI9WAnM8MPspsVIlloPGaT6fPIHlvh3QdRYepyaqHWD1dnCcEUg60wusX97s_G1ds-t-_xJaUX5bDUa9YcKLrS7TNJv7y83XXLiodMH-WBrPFRmxgUnRSZ8WY_UI-IIsBPUg1OzOeOodfPUFdLpQfADCnWGOO4KYm370V96-kBvpZ3apu_d-N9PX_85RPERSaaTeL7c73GCUWNjW05cJYEE8hG0M_4fMCwTF_jm9VzsjVnw-oKN-1mFNXvJWQNPAkhA2pJJg6DDPQ", result.unwrap());
        }

        #[test]
        fn should_serialize_with_rsa_key_rs384() {
            let result = serialize(JWK_RS384, "RS384");

            assert!(result.is_ok());
            assert_eq!("eyJhbGciOiJSUzM4NCJ9.eyJpc3MiOiJjbGllbnRfaWQifQ.S48o75yVYUZE9KurQtEkoExJeC_Z_oJiG9Bc14I1hNdteoZBiMFZsDsiheIu8Xy4A_99pV_LsLArqi5dGHJPhCG4Um0LGBjKA7Efu59yYXBZ862dTyCuN3Dk-KaTmcY4oon3pXGXBPdgAb-c29i205SBA4lwj4LozNc2Wv8xeBaVhVRnYDpdVRItNwP255nxWIja2NM7n2TvStITQBKXZcHEKcJfirXciY0F2MRpkfeMSmgme3LB3l_hOMm4pitL41RQwarnq8UJA3XX7b3JsfT7UXFXjK1EF-f3zk48FAiIovhL_q27S3XkiQg0s3qBDQvPVjy59rnfhu9FUOuCTg", result.unwrap());
        }

        #[test]
        fn should_serialize_with_rsa_key_rs512() {
            let result = serialize(JWK_RS512, "RS512");

            assert!(result.is_ok());
            assert_eq!("eyJhbGciOiJSUzUxMiJ9.eyJpc3MiOiJjbGllbnRfaWQifQ.QsjmWmxX7NAWgmM6wSxHF1vA1ahfo5UuGiZUACnpGmDyCW18xBwWYo0bEu1LCXEetgXSh0hPZ50XyXCyKXxuo9WoMBD3_eKYKGcP-dujjQHDPT67fKdOuiWbH1jGukLi6PDFkgHL6jCGlg9TE7OjBkbhzMOA78EeR2603gC8jBni88GuLb2YL7NO3Kud815OiHrT--CsYRdovfcXoyiIye3vCHHfpytQv5lC3vtCUI9le39SbkWX4pBnuYfXvNUCL0iICu2a_5vQxHp5xha3zlxEC8fOtAUM_MDrhe9XkDJnQhH2Kvghrke7DZkCKxpwSzEAApDDl2ZMWKTxkmZooA", result.unwrap());
        }

        #[test]
        fn should_serialize_with_rsa_key_ps256() {
            let result = serialize(JWK_PS256, "PS256");

            assert!(result.is_ok());
            assert!(result
                .unwrap()
                .starts_with("eyJhbGciOiJQUzI1NiJ9.eyJpc3MiOiJjbGllbnRfaWQifQ."));
        }

        #[test]
        fn should_serialize_with_rsa_key_ps384() {
            let result = serialize(JWK_PS384, "PS384");

            assert!(result.is_ok());
            assert!(result
                .unwrap()
                .starts_with("eyJhbGciOiJQUzM4NCJ9.eyJpc3MiOiJjbGllbnRfaWQifQ."));
        }

        #[test]
        fn should_serialize_with_rsa_key_ps512() {
            let result = serialize(JWK_PS512, "PS512");

            assert!(result.is_ok());
            assert!(result
                .unwrap()
                .starts_with("eyJhbGciOiJQUzUxMiJ9.eyJpc3MiOiJjbGllbnRfaWQifQ."));
        }

        #[test]
        fn should_serialize_with_ec_key_es256() {
            let result = serialize(JWK_ES256, "ES256");

            assert!(result.is_ok());
            assert!(result
                .unwrap()
                .starts_with("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJjbGllbnRfaWQifQ."));
        }

        #[test]
        fn should_serialize_with_ec_key_es384() {
            let result = serialize(JWK_ES384, "ES384");

            assert!(result.is_ok());
            assert!(result
                .unwrap()
                .starts_with("eyJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJjbGllbnRfaWQifQ."));
        }

        #[test]
        fn should_return_error_with_ec_key_es512() {
            let jwk_str = r#"{
    "kty": "EC",
    "d": "Ac5xBxOokbAZKj8T3ybWxR7bvRSIaO4LA7FFZmk6JaDGTdeCWiZtweWXyQDn9FVK7dSpYEJX47v4TOqmUCb2eYQr",
    "crv": "P-521",
    "x": "AJVkClwyaqSWg5_kDtksB6LeQ5J9Snv0RJHMgdrk_5M4YsZyPAUNSuZL17VXxHoWh9okIncbElOa4xqMWcabVvAK",
    "y": "Aa9W5s406asW8ZJvrjVmjmB4cEQgNon9cBZx44xbNEGQpAvr-xXhHifP8pI-RRqxO0YOKsX4QcS-ORzysMlugwFT",
    "alg": "ES512"
}"#;

            let result = serialize(jwk_str, "ES512");

            assert!(result.is_err());
        }

        #[test]
        fn should_return_error_with_ec_key_other_curves() {
            let jwk_str = r#"{
    "kty": "EC",
    "d": "Q0y0vW-qJpGVAoCKZizON5lkVaB5GrGyrmulHnZqi7A",
    "crv": "secp256k1",
    "x": "BD_OHD267hFxdR7BSRmaaUpTT0Na37QyrB_76nohRzU",
    "y": "4EglJVCaCUMaaV5LTpV80_2taFoRacZGJt8aBeVYqL8",
    "alg": "ES256"
}"#;

            let result = serialize(jwk_str, "ES256");

            assert!(result.is_err());
        }

        #[test]
        fn should_return_error_with_ec_key_other_algs() {
            let jwk_str = r#"{
    "kty": "EC",
    "d": "Cw3vGw-ZdirJFXArd75hqw5cnYDhfn4xeyQNqSr2upw",
    "crv": "P-256",
    "x": "jx0Hf79tRVO1mxq7ZwpgYJrlgb1lfbHvWjKJ7tIOphw",
    "y": "Cxy9D3C-c8vW2B_6qpzujnvrYVXB9KXS5DJmPbfIDzo",
    "alg": "ECDH-ES"
}"#;

            let result = serialize(jwk_str, "ECDH-ES");

            assert!(result.is_err());
        }

        #[test]
        fn should_serialize_with_okp_key_eddsa() {
            let result = serialize(JWK_EDDSA_ED25519, "EdDSA");

            assert!(result.is_ok());
            assert_eq!("eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJjbGllbnRfaWQifQ.FfFO-lQFa7dfsmr8nx-H7sNdUsp5Bo4ERT3KcezJxzbKwxH0vE3hvHod522Bmns0_WwaayF-sCfYt6zw1b_tBA", result.unwrap());
        }

        #[test]
        fn should_return_error_with_okp_key_eddsa_other_curves() {
            let jwk_str = r#"{
    "kty": "OKP",
    "d": "r0b_riz247OAdWEUg6tS1ZCrYf26CCm6gJmIkXhV4P-HfVvz7VAGHymTYOKut6MvWshCvhTwD4Qo",
    "crv": "Ed448",
    "x": "O6mzjLEZjb9DqTB1P8F3wGoZY-SQu-LWPsxike5y7gLx4xCN7xzq6FiCdNY-itxOrDuSKgY0UBsA",
    "alg": "EdDSA"
}"#;

            let result = serialize(jwk_str, "EdDSA");

            assert!(result.is_err());
        }

        #[test]
        fn should_return_error_with_okp_key_eddsa_other_alg() {
            let jwk_str = r#"{
    "kty": "OKP",
    "d": "2VssemWr0oSNK7ZRGEJ4iYPeedb6AL24eGhq2Srx-N0",
    "crv": "Ed25519",
    "x": "jjxuTOeoe_vhe_FNeyyEHIilguj3aFYIvCyqqaeGvc0",
    "alg": "ECDH-ES"
}"#;

            let result = serialize(jwk_str, "ECDH-ES");

            assert!(result.is_err());
        }
    }

    mod deserialize {
        use super::*;

        #[test]
        fn should_deserialize_with_oct_key_hs256() {
            let token = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJjbGllbnRfaWQifQ.bmi-11GfR1I1WnSL8qK-zCh30FWcwZ6kJkEvLW72_ts".to_owned();

            let jwk = Jwk::try_from(JWK_HS256).unwrap();

            let result = JwsOnlyCrypto.jws_deserialize(token, &jwk);

            assert!(result.is_ok());

            let (header, payload) = result.unwrap();

            assert_eq!(
                header.params.get("alg"),
                Some(&Value::String("HS256".to_owned()))
            );
            assert_eq!(header.params.len(), 1);

            assert_eq!(
                payload.params.get("iss"),
                Some(&Value::String("client_id".to_owned()))
            );
            assert_eq!(payload.params.len(), 1);
        }

        #[test]
        fn should_deserialize_with_oct_key_hs384() {
            let token = "eyJhbGciOiJIUzM4NCJ9.eyJpc3MiOiJjbGllbnRfaWQifQ.hEz5AG8lI9vB9STkwpNdji_J8Ksv5NPJwbO0ndPEtIkqyTUJbOIQpprf9EqrZa4J".to_owned();

            let jwk = Jwk::try_from(JWK_HS384).unwrap();

            let result = JwsOnlyCrypto.jws_deserialize(token, &jwk);

            assert!(result.is_ok());

            let (header, payload) = result.unwrap();

            assert_eq!(
                header.params.get("alg"),
                Some(&Value::String("HS384".to_owned()))
            );
            assert_eq!(header.params.len(), 1);

            assert_eq!(
                payload.params.get("iss"),
                Some(&Value::String("client_id".to_owned()))
            );
            assert_eq!(payload.params.len(), 1);
        }

        #[test]
        fn should_deserialize_with_oct_key_hs512() {
            let token = "eyJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJjbGllbnRfaWQifQ.yf2a5Yd9zB27CJQZwhAJXjB1Lt7qMDR1m9J53G4eDsiWdwivMZLEBg2DY8g9t3_DgR1sTZaqzjfPWjImIfZsTg".to_owned();

            let jwk = Jwk::try_from(JWK_HS512).unwrap();

            let result = JwsOnlyCrypto.jws_deserialize(token, &jwk);

            assert!(result.is_ok());

            let (header, payload) = result.unwrap();

            assert_eq!(
                header.params.get("alg"),
                Some(&Value::String("HS512".to_owned()))
            );
            assert_eq!(header.params.len(), 1);

            assert_eq!(
                payload.params.get("iss"),
                Some(&Value::String("client_id".to_owned()))
            );
            assert_eq!(payload.params.len(), 1);
        }

        #[test]
        fn should_deserialize_with_rsa_key_rs256() {
            let token = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJjbGllbnRfaWQifQ.QN8b_tWT0AwxeQsDlQD0vAkc64IeemAy4Zkpi7T-07Y0S2iic5uc3rv8AeWtOuHeWud7j3-ZiXI9WAnM8MPspsVIlloPGaT6fPIHlvh3QdRYepyaqHWD1dnCcEUg60wusX97s_G1ds-t-_xJaUX5bDUa9YcKLrS7TNJv7y83XXLiodMH-WBrPFRmxgUnRSZ8WY_UI-IIsBPUg1OzOeOodfPUFdLpQfADCnWGOO4KYm370V96-kBvpZ3apu_d-N9PX_85RPERSaaTeL7c73GCUWNjW05cJYEE8hG0M_4fMCwTF_jm9VzsjVnw-oKN-1mFNXvJWQNPAkhA2pJJg6DDPQ".to_owned();

            let jwk = Jwk::try_from(JWK_RS256).unwrap();

            let result = JwsOnlyCrypto.jws_deserialize(token, &jwk);

            assert!(result.is_ok());

            let (header, payload) = result.unwrap();

            assert_eq!(
                header.params.get("alg"),
                Some(&Value::String("RS256".to_owned()))
            );
            assert_eq!(header.params.len(), 1);

            assert_eq!(
                payload.params.get("iss"),
                Some(&Value::String("client_id".to_owned()))
            );
            assert_eq!(payload.params.len(), 1);
        }

        #[test]
        fn should_deserialize_with_rsa_key_rs384() {
            let token = "eyJhbGciOiJSUzM4NCJ9.eyJpc3MiOiJjbGllbnRfaWQifQ.S48o75yVYUZE9KurQtEkoExJeC_Z_oJiG9Bc14I1hNdteoZBiMFZsDsiheIu8Xy4A_99pV_LsLArqi5dGHJPhCG4Um0LGBjKA7Efu59yYXBZ862dTyCuN3Dk-KaTmcY4oon3pXGXBPdgAb-c29i205SBA4lwj4LozNc2Wv8xeBaVhVRnYDpdVRItNwP255nxWIja2NM7n2TvStITQBKXZcHEKcJfirXciY0F2MRpkfeMSmgme3LB3l_hOMm4pitL41RQwarnq8UJA3XX7b3JsfT7UXFXjK1EF-f3zk48FAiIovhL_q27S3XkiQg0s3qBDQvPVjy59rnfhu9FUOuCTg".to_owned();

            let jwk = Jwk::try_from(JWK_RS384).unwrap();

            let result = JwsOnlyCrypto.jws_deserialize(token, &jwk);

            assert!(result.is_ok());

            let (header, payload) = result.unwrap();

            assert_eq!(
                header.params.get("alg"),
                Some(&Value::String("RS384".to_owned()))
            );
            assert_eq!(header.params.len(), 1);

            assert_eq!(
                payload.params.get("iss"),
                Some(&Value::String("client_id".to_owned()))
            );
            assert_eq!(payload.params.len(), 1);
        }

        #[test]
        fn should_deserialize_with_rsa_key_rs512() {
            let token = "eyJhbGciOiJSUzUxMiJ9.eyJpc3MiOiJjbGllbnRfaWQifQ.QsjmWmxX7NAWgmM6wSxHF1vA1ahfo5UuGiZUACnpGmDyCW18xBwWYo0bEu1LCXEetgXSh0hPZ50XyXCyKXxuo9WoMBD3_eKYKGcP-dujjQHDPT67fKdOuiWbH1jGukLi6PDFkgHL6jCGlg9TE7OjBkbhzMOA78EeR2603gC8jBni88GuLb2YL7NO3Kud815OiHrT--CsYRdovfcXoyiIye3vCHHfpytQv5lC3vtCUI9le39SbkWX4pBnuYfXvNUCL0iICu2a_5vQxHp5xha3zlxEC8fOtAUM_MDrhe9XkDJnQhH2Kvghrke7DZkCKxpwSzEAApDDl2ZMWKTxkmZooA".to_owned();

            let jwk = Jwk::try_from(JWK_RS512).unwrap();

            let result = JwsOnlyCrypto.jws_deserialize(token, &jwk);

            assert!(result.is_ok());

            let (header, payload) = result.unwrap();

            assert_eq!(
                header.params.get("alg"),
                Some(&Value::String("RS512".to_owned()))
            );
            assert_eq!(header.params.len(), 1);

            assert_eq!(
                payload.params.get("iss"),
                Some(&Value::String("client_id".to_owned()))
            );
            assert_eq!(payload.params.len(), 1);
        }

        #[test]
        fn should_deserialize_with_rsa_key_ps256() {
            let token = serialize(JWK_PS256, "PS256").unwrap();

            let jwk = Jwk::try_from(JWK_PS256).unwrap();

            let result = JwsOnlyCrypto.jws_deserialize(token, &jwk);

            assert!(result.is_ok());

            let (header, payload) = result.unwrap();

            assert_eq!(
                header.params.get("alg"),
                Some(&Value::String("PS256".to_owned()))
            );
            assert_eq!(header.params.len(), 1);

            assert_eq!(
                payload.params.get("iss"),
                Some(&Value::String("client_id".to_owned()))
            );
            assert_eq!(payload.params.len(), 1);
        }

        #[test]
        fn should_deserialize_with_rsa_key_ps384() {
            let token = serialize(JWK_PS384, "PS384").unwrap();

            let jwk = Jwk::try_from(JWK_PS384).unwrap();

            let result = JwsOnlyCrypto.jws_deserialize(token, &jwk);

            assert!(result.is_ok());

            let (header, payload) = result.unwrap();

            assert_eq!(
                header.params.get("alg"),
                Some(&Value::String("PS384".to_owned()))
            );
            assert_eq!(header.params.len(), 1);

            assert_eq!(
                payload.params.get("iss"),
                Some(&Value::String("client_id".to_owned()))
            );
            assert_eq!(payload.params.len(), 1);
        }

        #[test]
        fn should_deserialize_with_rsa_key_ps512() {
            let token = serialize(JWK_PS512, "PS512").unwrap();

            let jwk = Jwk::try_from(JWK_PS512).unwrap();

            let result = JwsOnlyCrypto.jws_deserialize(token, &jwk);

            assert!(result.is_ok());

            let (header, payload) = result.unwrap();

            assert_eq!(
                header.params.get("alg"),
                Some(&Value::String("PS512".to_owned()))
            );
            assert_eq!(header.params.len(), 1);

            assert_eq!(
                payload.params.get("iss"),
                Some(&Value::String("client_id".to_owned()))
            );
            assert_eq!(payload.params.len(), 1);
        }

        #[test]
        fn should_deserialize_with_ec_key_es256() {
            let token = serialize(JWK_ES256, "ES256").unwrap();

            let jwk = Jwk::try_from(JWK_ES256).unwrap();

            let result = JwsOnlyCrypto.jws_deserialize(token, &jwk);

            assert!(result.is_ok());

            let (header, payload) = result.unwrap();

            assert_eq!(
                header.params.get("alg"),
                Some(&Value::String("ES256".to_owned()))
            );
            assert_eq!(header.params.len(), 1);

            assert_eq!(
                payload.params.get("iss"),
                Some(&Value::String("client_id".to_owned()))
            );
            assert_eq!(payload.params.len(), 1);
        }

        #[test]
        fn should_deserialize_with_ec_key_es384() {
            let token = serialize(JWK_ES384, "ES384").unwrap();

            let jwk = Jwk::try_from(JWK_ES384).unwrap();

            let result = JwsOnlyCrypto.jws_deserialize(token, &jwk);

            assert!(result.is_ok());

            let (header, payload) = result.unwrap();

            assert_eq!(
                header.params.get("alg"),
                Some(&Value::String("ES384".to_owned()))
            );
            assert_eq!(header.params.len(), 1);

            assert_eq!(
                payload.params.get("iss"),
                Some(&Value::String("client_id".to_owned()))
            );
            assert_eq!(payload.params.len(), 1);
        }

        #[test]
        fn should_deserialize_with_okp_key_eddsa() {
            let token = serialize(JWK_EDDSA_ED25519, "EdDSA").unwrap();

            let jwk = Jwk::try_from(JWK_EDDSA_ED25519).unwrap();

            let result = JwsOnlyCrypto.jws_deserialize(token, &jwk);

            assert!(result.is_ok());

            let (header, payload) = result.unwrap();

            assert_eq!(
                header.params.get("alg"),
                Some(&Value::String("EdDSA".to_owned()))
            );
            assert_eq!(header.params.len(), 1);

            assert_eq!(
                payload.params.get("iss"),
                Some(&Value::String("client_id".to_owned()))
            );
            assert_eq!(payload.params.len(), 1);
        }
    }
}
