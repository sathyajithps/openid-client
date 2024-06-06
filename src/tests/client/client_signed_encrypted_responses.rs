use josekit::jwk::Jwk;
use serde_json::json;

use crate::{
    issuer::Issuer,
    jwks::Jwks,
    tokenset::{TokenSet, TokenSetParams},
    types::{
        CallbackParams, ClientMetadata, HttpMethod, IssuerMetadata, OAuthCallbackChecks,
        OpenIDCallbackChecks, OpenIdCallbackParams, UserinfoOptions,
    },
};

use crate::tests::test_http_client::TestHttpReqRes;

fn get_jwks() -> Jwks {
    let mut jwk = Jwk::new("EC");

    // jwk.set_key_id("L3qrG8dSNYv6F-Hvv-qTdp_EkmgwjQX76DHmDZCoa4Q");
    jwk.set_curve("P-256");
    jwk.set_algorithm("ECDH-ES");
    jwk.set_parameter(
        "x",
        Some(json!("PDsKZY9JxlbrE-hHce_e_H7yjWgxftRIowdW9qxBqNQ")),
    )
    .unwrap();
    jwk.set_parameter(
        "y",
        Some(json!("EAmrpjkbBkuBZAD2kvuL5mOXgdK_8t1t93yKGGHq_Y4")),
    )
    .unwrap();
    jwk.set_parameter(
        "d",
        Some(json!("59efvkfuCuVLW9Y4xvLvUyjARwgnSgwTLRc0UGpewLA")),
    )
    .unwrap();

    Jwks::from(vec![jwk])
}

#[tokio::test]
async fn handles_signed_and_encrypted_id_tokens_from_implicit_and_code_responses_test_by_hybrid() {
    let http_client = TestHttpReqRes::new("https://op.example.com/token")
        .assert_request_method(HttpMethod::POST)
        .assert_request_header("accept", vec!["application/json".to_string()])
        .assert_request_header("content-length", vec!["697".to_string()])
        .assert_request_header("authorization", vec!["Basic NGU4N2RkZTQtZGRkMy00YzIxLWFlZjktMmYyZjZiYWI0M2NhOkdmc1Q0NzlWTXk1WlpaUHF1YWRQYk4zd0t6YUZHWW8xQ1RrYjBJRkZ6RE5PRExFQXVDMkdVVjNRc1R5ZTN4TlE=".to_string()])
        .assert_request_header(
            "content-type",
            vec!["application/x-www-form-urlencoded".to_string()],
        )
        .assert_request_body("grant_type=authorization_code&redirect_uri=https%3A%2F%2Foidc-client.dev%2Fcb&code=eyJraW5kIjoiQXV0aG9yaXphdGlvbkNvZGUiLCJqdGkiOiI3YzM5NzQyZC0yMGUyLTQ3YjEtYmM1MC1lN2VlYzhmN2IzNmYiLCJub25jZSI6ImM2NDVmZmZhNDAwNzU1MzJlZjI5YTJlYTYyN2NmYTM3IiwiaWF0IjoxNDczMDc2NDEyLCJleHAiOjE0NzMwNzcwMTIsImlzcyI6Imh0dHBzOi8vZ3VhcmRlZC1jbGlmZnMtODYzNS5oZXJva3VhcHAuY29tL29wIn0.jgUnZUBmsceb1cpqlsmiCOQ40Zx4JTRffGN_bAgYT4rLcEv3wOlzMSoVmU1cYkDbi-jjNAqkBjqxDWHcRJnQR4BAYOdyDVcGWD_aLkqGhUOCJHn_lwWqEKtSTgh-zXiqVIVC5NTA2BdhEfHhb-jnMQNrKkL2QNXOFvT9s6khZozOMXy-mUdfNfdSFHrcpFkFyGAUpezI9QmwToMB6KwoRHDYb2jcLBXdA5JLAnHw8lpz9yUaVQv7s97wY7Xgtt2zNFwQxiJWytYNHaJxQnOZje0_TvDjrZSA9IYKuKU1Q7f7-EBfQfFSGcsFK2NtGho3mNBEUDD2B8Qv1ipv50oU6Q")
        .set_response_body(r#"{
            "access_token":
            "eyJraW5kIjoiQWNjZXNzVG9rZW4iLCJqdGkiOiJlMDk5YTI1ZC02MzA0LTQwMGItOTdhYi1hOTJhMzMzOTBlODgiLCJpYXQiOjE0NzMwNzY0MTMsImV4cCI6MTQ3MzA4MzYxMywiaXNzIjoiaHR0cHM6Ly9ndWFyZGVkLWNsaWZmcy04NjM1Lmhlcm9rdWFwcC5jb20vb3AifQ.p_r4KvAu6lEY6JpGmRIGCkRRrovGeJcDfOw3O_gFkPRaY7bcJjNDUPlfY7_nyp3bWyqtveq55ozTZuddUL01KET7bKgxMq-dQ2SxGBvgN3KtHIRBud7Bw8Ax98YkiBKJJXC8xF00VZkkX-ZcUyXptPkUpBm0zeN6jmWmyFX-2QrbclLS8ZEK2Poc_y5PdNAtCCOTBfnq6roxzVQ5lM_aMQaSuPVd-Og6E_jBE6OE9oB4ikFa4S7EvZvFVDpGMLtUjxOazTURbqWY6OnuhuAiP6WZc1FxfQod462IqPERzl2qVJH9qQNr-iLuVLt_bzauHg33v1koTrdfETyoRAZH5w",
            "expires_at": 1473083613,
            "id_token":
              "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Inc2Ukx4a3phWDV5cGtwU1pMemJVbkVfWjh4WEYtS3R2OXc0Tno0MVZFeVEiLCJ5IjoiUTFwM1l6a3h3VHhFZ1lnZ0szNFpKcnkyT1JCMGloYXEyOXdtSUVqTnZNWSJ9fQ..EqZ4s3iLxrVhuZwF4NDa7A.tkg5i4LQXECXNFXh1j9yo5TjhhIlrzp_BZbdEI18f2jINVIwXu08eRrpQAI-OAaO4MbxiX73fLD_jDplHIUz5NDxiuxuQT2DCzynK66Tqs76OELATBAkW7FUGDJPWjotXXuUzNBgvs0xKz8q6a04udqfATH4-tZkyVLkNS0Z8mpAejRdkacYfvdSSJk842e3qHsOowlX7Tiu7OY60dBkKXO7hrPtvsX2XdseREYnA_A3P4jNdIhWhZMUxR2X-FSgChzwRIFPFRJsp1xiHkfxfHaPjHPmj3JlDPlubNrUcz-2WWxeBd9qVjqlAyqRorNr30KwCwVTaIHwfLrTjXzFfVOJBXAdIJ7FjX7lUbnc9DjcV6cNN2IdHTET7aoC6ysfGYLAwVtN9sLXRgeJXdl6-56f0eg_ZbLbOWLj3qJPuDSTVu7r6L3sebNx4uBTzAu-e8i1uukw6e63AHzVa3Z57tTGtzaFHogDH0f_JuQRhaJcwDJdoJKmksVT33W6mxza0WttqXXj9NXzfJUdRs3B9vpf1h9Yvol9Rlii2OmwLGC17sZe-W2NX1ibS87ZQiEFzuLWfmU4ygagg7O7A5fJ4Olo_aY6Ow7qqggIjAhL3J24lsMtlVR3VGKWsmvtW4eoojy6nnfkcJreSHAjPby9c4_giSic_MCSe9K1jU2Kyftj-XBJD5DSZlt97ZT9NA4aI-DXBs6Mx14dXrZ15BYDVxvYU-YmUnJpASueGB7bp5TMjE2YC2cEPsHgiJnU1Yi0.KMTcJ07KhD0-g4V89Z0PBg",
            "refresh_token":
              "eyJraW5kIjoiUmVmcmVzaFRva2VuIiwianRpIjoiMzhmZTY1NmItNjYyMC00MzdiLWJmY2YtZTRjNzRhZTRiNjMzIiwibm9uY2UiOiJjNjQ1ZmZmYTQwMDc1NTMyZWYyOWEyZWE2MjdjZmEzNyIsImlhdCI6MTQ3MzA3NjQxMywiZXhwIjoxNDc1NjY4NDEzLCJpc3MiOiJodHRwczovL2d1YXJkZWQtY2xpZmZzLTg2MzUuaGVyb2t1YXBwLmNvbS9vcCJ9.hySAknc2L2ngSoTiRxUTJLOUxKmyRTUzLsRlGKip4OXNYXre9QEDH8z9c8NKBHdnRbBxg8Jo45cZbDb-5bZ6mt5noDmT42xtsCOiN25Is9SsRSzVarIDiwyqXVlTojh5XuKPulK4Ji6vp2jYUZNoVnlsA7G96cuHWVAqZd5e8GBb9YlUNZ5zSX6aggFgTGDJs46O42_g4JULB8cAb9MZAzcZOORGpmRIPpSKAZFgT2_5yW-yqh0f66JaAQUtW9TKoAsdttV4NnivzJYeyR0hlgEeKzo9zNuTkJedXbjRAIP6ybk9ITcZveuJ11CFsyHZcNd_0tZuiAlvUpJIeHK0aA",
            "token_type": "Bearer"
          }"#)
        .set_response_content_type_header("application/json")
        .build();

    let issuer_metadata = IssuerMetadata {
        issuer: "https://guarded-cliffs-8635.herokuapp.com/op".to_string(),
        token_endpoint: Some("https://op.example.com/token".to_string()),
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let mut issuer = Issuer::new(issuer_metadata);

    issuer.now = || 1473076413;

    let client_metadata = ClientMetadata {
        client_id: Some("4e87dde4-ddd3-4c21-aef9-2f2f6bab43ca".to_string()),
        client_secret: Some(
            "GfsT479VMy5ZZZPquadPbN3wKzaFGYo1CTkb0IFFzDNODLEAuC2GUV3QsTye3xNQ".to_string(),
        ),
        id_token_encrypted_response_alg: Some("ECDH-ES".to_string()),
        id_token_signed_response_alg: Some("HS256".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, Some(get_jwks()), None, None)
        .unwrap();

    client.now = || 1473076413;

    let params = CallbackParams {
        code: Some("eyJraW5kIjoiQXV0aG9yaXphdGlvbkNvZGUiLCJqdGkiOiI3YzM5NzQyZC0yMGUyLTQ3YjEtYmM1MC1lN2VlYzhmN2IzNmYiLCJub25jZSI6ImM2NDVmZmZhNDAwNzU1MzJlZjI5YTJlYTYyN2NmYTM3IiwiaWF0IjoxNDczMDc2NDEyLCJleHAiOjE0NzMwNzcwMTIsImlzcyI6Imh0dHBzOi8vZ3VhcmRlZC1jbGlmZnMtODYzNS5oZXJva3VhcHAuY29tL29wIn0.jgUnZUBmsceb1cpqlsmiCOQ40Zx4JTRffGN_bAgYT4rLcEv3wOlzMSoVmU1cYkDbi-jjNAqkBjqxDWHcRJnQR4BAYOdyDVcGWD_aLkqGhUOCJHn_lwWqEKtSTgh-zXiqVIVC5NTA2BdhEfHhb-jnMQNrKkL2QNXOFvT9s6khZozOMXy-mUdfNfdSFHrcpFkFyGAUpezI9QmwToMB6KwoRHDYb2jcLBXdA5JLAnHw8lpz9yUaVQv7s97wY7Xgtt2zNFwQxiJWytYNHaJxQnOZje0_TvDjrZSA9IYKuKU1Q7f7-EBfQfFSGcsFK2NtGho3mNBEUDD2B8Qv1ipv50oU6Q".to_string()),
        id_token:
          Some("eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlBWMGt5MEMyWmpoY0tJeGM4dDRfMmR1S0NNMGlLbTFlUHRoM3RtNkV4c0EiLCJ5Ijoib3hpOXhUNEZzWUdnU1hzdUVDb3kzYnN6X0VHNDAxcFppbG81MjVDTFZCUSJ9fQ..Fk7uOrLHo3StxuO7JKmqhA.ShAxwMhoneNdxPpc5bDvag-ISjcTAjIKVHTVwMCBIWofVpqCWCL-WiNtm9S-YQf08oVm0hEptqaWIkIUFuqRK56DAP_anxtBPjQhX_oFDOnN76rPg0KNW9hgcRYOQ9MkUEYtaDgslcWAlv-xy_DpQ7_V2lYudVCcSLW26YK0TZlH5bOTPkVD6t1JgYb4cdgATzjzZCAgiDvWYuDZ1FmzRf53FRlQfCeB_sPjvag-sr-ZkcygEjLF86-JvOs4a6Ccz6gPs2WBtVSycYi6NuKJt0nlIBYbSazF5cT_ACHcfveMbgLeO2-GFekY6DhiRyHFgbA03G-yRlFLUbtzxZI_vBe_NuZf2pyiyv4xCNI9bvl_0LCvu0T_R6ss0OzBm9dK6tfEe5mkmi1ku_eiA2HHzk_BK4VLbP0urinZGethJcqXEIjuBr1pUKduQfVtUQMfnVPxLUI9PykO1H-QxVAcnsB6p3q0jkXvTvFBhsbFhA0cwKWF2qqpW6JXH19ULt0wNgzAGxghtox-t8QWb_qUO0Ql69AdmoTlydLB16aLf7JEH_vQBHXtSuDwAyEqccU8-EKMXHh4w6T92t6IjsXXr1x_JlCoByTEqG-bpGilPuYbh90cin7DyyniC2p-gM8pOIdpP9cDnKwRHGTPyw7YR16_0JCdmJOn7NO07zlYZMfgdmD-S2S49D23nd1SkECw.V__rYTSwfHvJsRe4auyNjw".to_string()),
        state: Some("36853f4ea7c9d26f4b0b95f126afe6a2".to_string()),
        session_state: Some("foobar.foo".to_string()),
        ..Default::default()
    };

    let checks = OpenIDCallbackChecks {
        nonce: Some("c645fffa40075532ef29a2ea627cfa37"),
        oauth_checks: Some(OAuthCallbackChecks {
            state: Some("36853f4ea7c9d26f4b0b95f126afe6a2"),
            ..Default::default()
        }),
        ..Default::default()
    };

    let params = OpenIdCallbackParams::default()
        .redirect_uri("https://oidc-client.dev/cb")
        .checks(checks)
        .parameters(params);

    let _ = client.callback_async(&http_client, params).await.unwrap();
}

#[tokio::test]
async fn handles_signed_and_encrypted_id_tokens_from_refresh_grant() {
    let http_client = TestHttpReqRes::new("https://op.example.com/token")
    .assert_request_method(HttpMethod::POST)
    .assert_request_header("accept", vec!["application/json".to_string()])
    .assert_request_header("content-length", vec!["646".to_string()])
    .assert_request_header("authorization", vec!["Basic NGU4N2RkZTQtZGRkMy00YzIxLWFlZjktMmYyZjZiYWI0M2NhOkdmc1Q0NzlWTXk1WlpaUHF1YWRQYk4zd0t6YUZHWW8xQ1RrYjBJRkZ6RE5PRExFQXVDMkdVVjNRc1R5ZTN4TlE=".to_string()])
    .assert_request_header(
        "content-type",
        vec!["application/x-www-form-urlencoded".to_string()],
    )
    .assert_request_body("grant_type=refresh_token&refresh_token=eyJraW5kIjoiUmVmcmVzaFRva2VuIiwianRpIjoiMzhmZTY1NmItNjYyMC00MzdiLWJmY2YtZTRjNzRhZTRiNjMzIiwibm9uY2UiOiJjNjQ1ZmZmYTQwMDc1NTMyZWYyOWEyZWE2MjdjZmEzNyIsImlhdCI6MTQ3MzA3NjQxMywiZXhwIjoxNDc1NjY4NDEzLCJpc3MiOiJodHRwczovL2d1YXJkZWQtY2xpZmZzLTg2MzUuaGVyb2t1YXBwLmNvbS9vcCJ9.hySAknc2L2ngSoTiRxUTJLOUxKmyRTUzLsRlGKip4OXNYXre9QEDH8z9c8NKBHdnRbBxg8Jo45cZbDb-5bZ6mt5noDmT42xtsCOiN25Is9SsRSzVarIDiwyqXVlTojh5XuKPulK4Ji6vp2jYUZNoVnlsA7G96cuHWVAqZd5e8GBb9YlUNZ5zSX6aggFgTGDJs46O42_g4JULB8cAb9MZAzcZOORGpmRIPpSKAZFgT2_5yW-yqh0f66JaAQUtW9TKoAsdttV4NnivzJYeyR0hlgEeKzo9zNuTkJedXbjRAIP6ybk9ITcZveuJ11CFsyHZcNd_0tZuiAlvUpJIeHK0aA")
    .set_response_body(r#"{
        "access_token":
          "eyJraW5kIjoiQWNjZXNzVG9rZW4iLCJqdGkiOiJlMDk5YTI1ZC02MzA0LTQwMGItOTdhYi1hOTJhMzMzOTBlODgiLCJpYXQiOjE0NzMwNzY0MTMsImV4cCI6MTQ3MzA4MzYxMywiaXNzIjoiaHR0cHM6Ly9ndWFyZGVkLWNsaWZmcy04NjM1Lmhlcm9rdWFwcC5jb20vb3AifQ.p_r4KvAu6lEY6JpGmRIGCkRRrovGeJcDfOw3O_gFkPRaY7bcJjNDUPlfY7_nyp3bWyqtveq55ozTZuddUL01KET7bKgxMq-dQ2SxGBvgN3KtHIRBud7Bw8Ax98YkiBKJJXC8xF00VZkkX-ZcUyXptPkUpBm0zeN6jmWmyFX-2QrbclLS8ZEK2Poc_y5PdNAtCCOTBfnq6roxzVQ5lM_aMQaSuPVd-Og6E_jBE6OE9oB4ikFa4S7EvZvFVDpGMLtUjxOazTURbqWY6OnuhuAiP6WZc1FxfQod462IqPERzl2qVJH9qQNr-iLuVLt_bzauHg33v1koTrdfETyoRAZH5w",
        "expires_at": 1473083613,
        "id_token":
          "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Ik8yQzZHZnBFVGgyUDBCWVNSN1dtWDZXVTBiV1FXcVZud1lwRGVwbVI1NVkiLCJ5IjoiVG5pc0dTSWZMQUxNYzZHVUlydVBmeWFzMm9mQ3JPV3llZ2EyMW5pZG1KTSJ9fQ..RiTOrMAlM4pq6RfwnitLKA.oSERr76vgdbiYm1yQZfkwPonBzdrheypkueK9S5dRVodZDf1BKTr5-eM2VBgjYJ2R8KS5EAAJeJBxnlno3AnfO242ZQbqJP144S8sCj0lZmQoZJ6VzJavADXAf4LiprDblzV8J64pBnmvwjQN9Mk_KKNA34QoAebJZEP9A7RCLUck_oqb7vsLTM_LUyXyXxm7QiWUPdnUCzCCqcJW3SysFeJo1VZTZCwFxK0zrcja-vv9SUSoS7yvQuGRVXS3L08BglTN7SLWVujsPMJWbxmj_zYhoy14DQIckoBU7ver-2PoJOukl6m4yaY9n9LWZ5mUGDb3PbnwuFYxb1rDm2EmvlkhbXFdIuRciIOQTqgeei0TU61Ff_Vt0tinZNThYMQgX4DFc7HILBU7lMwwVUMdYqamE3suRr3qUIlD2RdSNiO87jxaiDFrosGU1fVVulcGmkFN4DX5kyd8lxMs33yPS1uO0G_NViFe-fwxd95JAYXOEiofnHFIYuHgrxfioBMoojYQl8PgLZFj8yxzGVflOyzJQgiYQA-BSAPI1bL2P_J2Jlnhdtv3cJ-bdG1pcwAa6zyzwSEXU5i6p9_TGs4nM15p-QlC3mgtjKkLtC64OL0ucc2Frb6dzKyZTOePu6PcecafNucSaMq1ERhRmQOdigDj1nwHUYs3akx31CHp-eXa9jctuy_C5l_YbBJOiUViZK2dJFNuMJQnMhPcSf6wQdVTQmXCxsSnRN158XYDhgVqqe4U6CROsKiCRQSKqpZ.Yo7zj4wMR89oWSH5Twfzzg",
        "refresh_token":
          "eyJraW5kIjoiUmVmcmVzaFRva2VuIiwianRpIjoiMzhmZTY1NmItNjYyMC00MzdiLWJmY2YtZTRjNzRhZTRiNjMzIiwibm9uY2UiOiJjNjQ1ZmZmYTQwMDc1NTMyZWYyOWEyZWE2MjdjZmEzNyIsImlhdCI6MTQ3MzA3NjQxMywiZXhwIjoxNDc1NjY4NDEzLCJpc3MiOiJodHRwczovL2d1YXJkZWQtY2xpZmZzLTg2MzUuaGVyb2t1YXBwLmNvbS9vcCJ9.hySAknc2L2ngSoTiRxUTJLOUxKmyRTUzLsRlGKip4OXNYXre9QEDH8z9c8NKBHdnRbBxg8Jo45cZbDb-5bZ6mt5noDmT42xtsCOiN25Is9SsRSzVarIDiwyqXVlTojh5XuKPulK4Ji6vp2jYUZNoVnlsA7G96cuHWVAqZd5e8GBb9YlUNZ5zSX6aggFgTGDJs46O42_g4JULB8cAb9MZAzcZOORGpmRIPpSKAZFgT2_5yW-yqh0f66JaAQUtW9TKoAsdttV4NnivzJYeyR0hlgEeKzo9zNuTkJedXbjRAIP6ybk9ITcZveuJ11CFsyHZcNd_0tZuiAlvUpJIeHK0aA",
        "token_type": "Bearer"
      }"#)
    .set_response_content_type_header("application/json")
    .build();

    let issuer_metadata = IssuerMetadata {
        issuer: "https://guarded-cliffs-8635.herokuapp.com/op".to_string(),
        token_endpoint: Some("https://op.example.com/token".to_string()),
        ..Default::default()
    };

    let mut issuer = Issuer::new(issuer_metadata);

    issuer.now = || 1473076413;

    let client_metadata = ClientMetadata {
        client_id: Some("4e87dde4-ddd3-4c21-aef9-2f2f6bab43ca".to_string()),
        client_secret: Some(
            "GfsT479VMy5ZZZPquadPbN3wKzaFGYo1CTkb0IFFzDNODLEAuC2GUV3QsTye3xNQ".to_string(),
        ),
        id_token_encrypted_response_alg: Some("ECDH-ES".to_string()),
        id_token_signed_response_alg: Some("HS256".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, Some(get_jwks()), None, None)
        .unwrap();

    client.now = || 1473076413;

    let token_set_params = TokenSetParams {
        refresh_token: Some("eyJraW5kIjoiUmVmcmVzaFRva2VuIiwianRpIjoiMzhmZTY1NmItNjYyMC00MzdiLWJmY2YtZTRjNzRhZTRiNjMzIiwibm9uY2UiOiJjNjQ1ZmZmYTQwMDc1NTMyZWYyOWEyZWE2MjdjZmEzNyIsImlhdCI6MTQ3MzA3NjQxMywiZXhwIjoxNDc1NjY4NDEzLCJpc3MiOiJodHRwczovL2d1YXJkZWQtY2xpZmZzLTg2MzUuaGVyb2t1YXBwLmNvbS9vcCJ9.hySAknc2L2ngSoTiRxUTJLOUxKmyRTUzLsRlGKip4OXNYXre9QEDH8z9c8NKBHdnRbBxg8Jo45cZbDb-5bZ6mt5noDmT42xtsCOiN25Is9SsRSzVarIDiwyqXVlTojh5XuKPulK4Ji6vp2jYUZNoVnlsA7G96cuHWVAqZd5e8GBb9YlUNZ5zSX6aggFgTGDJs46O42_g4JULB8cAb9MZAzcZOORGpmRIPpSKAZFgT2_5yW-yqh0f66JaAQUtW9TKoAsdttV4NnivzJYeyR0hlgEeKzo9zNuTkJedXbjRAIP6ybk9ITcZveuJ11CFsyHZcNd_0tZuiAlvUpJIeHK0aA".to_string()),
        ..Default::default()
    };

    let mut token_set = TokenSet::new(token_set_params);

    token_set.now = || 1473076413;

    client.set_skip_nonce_check(true);

    let _ = client
        .refresh_async(token_set, None, &http_client)
        .await
        .unwrap();
}

#[tokio::test]
async fn handles_encrypted_but_not_signed_responses_too() {
    let http_client = TestHttpReqRes::new("https://op.example.com/me")
    .assert_request_method(HttpMethod::GET)
    .assert_request_header("accept", vec!["application/jwt".to_string()])
    .assert_request_header("authorization", vec!["Bearer accesstoken".to_string()])
    .set_response_body("eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlNPZDJZYUZ0cE0xS3lPNkt4a2tCeGxEVEVXcGVvanlqandqald5c1BOVEUiLCJ5IjoiTEVKZGlqazRXc01XZU9JOHdBN1JLSEQ3Q2NxUXN3V25kVnVoeXl2aFl4byJ9fQ..Az5OORCn8IJCYCKg2AGs2A.ACZMiNTTclMiHui8cAgje6xmU4MWwUfU5aPduSxwmSZKMCEiQST3ZpRknWgitklLhd1B7w7zz9wcu7A-yt51ZTaVfO7B9ZrismOrQRX6pTc.xAu2T_3edWUipVASAaMBmw")
    .set_response_content_type_header("application/jwt;charset=utf-8")
    .build();

    let issuer_metadata = IssuerMetadata {
        issuer: "https://guarded-cliffs-8635.herokuapp.com/op".to_string(),
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let mut issuer = Issuer::new(issuer_metadata);

    issuer.now = || 1473076413;

    let client_metadata = ClientMetadata {
        client_id: Some("f21d5d1d-1c3f-4905-8ff1-5f553a2090b1".to_string()),
        userinfo_encrypted_response_alg: Some("ECDH-ES".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, Some(get_jwks()), None, None)
        .unwrap();

    client.now = || 1473076413;

    let token_set_params = TokenSetParams {
        access_token: Some("accesstoken".to_string()),
        ..Default::default()
    };

    let mut token_set = TokenSet::new(token_set_params);

    token_set.now = || 1473076413;

    let payload = client
        .userinfo_async(&token_set, UserinfoOptions::default(), &http_client)
        .await
        .unwrap();

    assert_eq!(
        payload.get("email").unwrap().as_str().unwrap(),
        "johndoe@example.com"
    );

    assert_eq!(
        payload.get("sub").unwrap().as_str().unwrap(),
        "0aa66887-8c86-4f3b-b521-5a00e01799ca"
    );
}

#[tokio::test]
async fn verifies_no_invalid_unsigned_plain_json_jwe_payloads_get_through() {
    let http_client = TestHttpReqRes::new("https://op.example.com/me")
    .assert_request_method(HttpMethod::GET)
    .assert_request_header("accept", vec!["application/jwt".to_string()])
    .assert_request_header("authorization", vec!["Bearer accesstoken".to_string()])
    .set_response_body("eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IkhqMWZtUGxHTEJ2VE5SbnE0SlpWcTNjd3FUTXUxYXYzYjBicEJUWlR0bWciLCJ5IjoieWs5Tkl1WkJiRl9UTjQwRHlCcERjMGNGek5EUUVzRVQ5ZTlJNk1NY2dTayJ9fQ..VonL8dThfAnH4qmUjGv5tA.7CZxo9EWjucIklvP8D7RWg.QpvgGnrKL4xLIKI86qkwRg")
    .set_response_content_type_header("application/jwt;charset=utf-8")
    .build();

    let issuer_metadata = IssuerMetadata {
        issuer: "https://guarded-cliffs-8635.herokuapp.com/op".to_string(),
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let mut issuer = Issuer::new(issuer_metadata);

    issuer.now = || 1473076413;

    let client_metadata = ClientMetadata {
        client_id: Some("f21d5d1d-1c3f-4905-8ff1-5f553a2090b1".to_string()),
        userinfo_encrypted_response_alg: Some("ECDH-ES".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, Some(get_jwks()), None, None)
        .unwrap();

    client.now = || 1473076413;

    let token_set_params = TokenSetParams {
        access_token: Some("accesstoken".to_string()),
        ..Default::default()
    };

    let mut token_set = TokenSet::new(token_set_params);

    token_set.now = || 1473076413;

    let err = client
        .userinfo_async(&token_set, UserinfoOptions::default(), &http_client)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(
        "failed to parse userinfo JWE payload as JSON",
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn handles_valid_but_no_object_top_level_unsigned_plain_json_jwe_payloads() {
    let http_client = TestHttpReqRes::new("https://op.example.com/me")
    .assert_request_method(HttpMethod::GET)
    .assert_request_header("accept", vec!["application/jwt".to_string()])
    .assert_request_header("authorization", vec!["Bearer accesstoken".to_string()])
    .set_response_body("eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlJDLUs1Q0oxaHM1OUVab3FRbDdIckZfYkRTNGtmbVRkV2NDUktiVUdNSlEiLCJ5IjoicDRLdGhQNlBZbE04LU5XQVBLSThjTThnOHRXUjU3RGp2V2s5QUVMTF9jdyJ9fQ..0UsI_8FRDyu9Ww3UsgPutg.RlHWtr8ezCPO4BahKEm2FA.6irHMjkZtOFnUVwrZkuxtw")
    .set_response_content_type_header("application/jwt;charset=utf-8")
    .build();

    let issuer_metadata = IssuerMetadata {
        issuer: "https://guarded-cliffs-8635.herokuapp.com/op".to_string(),
        userinfo_endpoint: Some("https://op.example.com/me".to_string()),
        ..Default::default()
    };

    let mut issuer = Issuer::new(issuer_metadata);

    issuer.now = || 1473076413;

    let client_metadata = ClientMetadata {
        client_id: Some("f21d5d1d-1c3f-4905-8ff1-5f553a2090b1".to_string()),
        userinfo_encrypted_response_alg: Some("ECDH-ES".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, Some(get_jwks()), None, None)
        .unwrap();

    client.now = || 1473076413;

    let token_set_params = TokenSetParams {
        access_token: Some("accesstoken".to_string()),
        ..Default::default()
    };

    let mut token_set = TokenSet::new(token_set_params);

    token_set.now = || 1473076413;

    let err = client
        .userinfo_async(&token_set, UserinfoOptions::default(), &http_client)
        .await
        .unwrap_err();

    assert!(err.is_rp_error());
    assert_eq!(
        "failed to parse userinfo JWE payload as JSON",
        err.rp_error().error.message
    );
}

#[tokio::test]
async fn handles_symmetric_encryption() {
    let http_client = TestHttpReqRes::new("https://op.example.com/me")
    .assert_request_method(HttpMethod::GET)
    .assert_request_header("accept", vec!["application/jwt".to_string()])
    .assert_request_header("authorization", vec!["Bearer accesstoken".to_string()])
    .set_response_body("eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlJDLUs1Q0oxaHM1OUVab3FRbDdIckZfYkRTNGtmbVRkV2NDUktiVUdNSlEiLCJ5IjoicDRLdGhQNlBZbE04LU5XQVBLSThjTThnOHRXUjU3RGp2V2s5QUVMTF9jdyJ9fQ..0UsI_8FRDyu9Ww3UsgPutg.RlHWtr8ezCPO4BahKEm2FA.6irHMjkZtOFnUVwrZkuxtw")
    .set_response_content_type_header("application/jwt;charset=utf-8")
    .build();

    let issuer_metadata = IssuerMetadata {
        issuer: "http://localhost:3000/op".to_string(),
        ..Default::default()
    };

    let mut issuer = Issuer::new(issuer_metadata);

    issuer.now = || 1473076413;

    let client_metadata = ClientMetadata {
        client_id: Some("0d9413a4-61c1-4b2b-8d84-a82464c1556c".to_string()),
        client_secret: Some(
            "l73jho9z9mL0GAomiQwbw08ARqro2tJ4E4qhJ+PZhNQoU6G6D23UDF91L9VR7iJ4".to_string(),
        ),
        id_token_encrypted_response_alg: Some("A128GCMKW".to_string()),
        id_token_signed_response_alg: Some("HS256".to_string()),
        ..Default::default()
    };

    let mut client = issuer
        .client(client_metadata, Some(get_jwks()), None, None)
        .unwrap();

    client.now = || 1473076413;

    let params = CallbackParams {
        id_token:
          Some("eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldUIiwidGFnIjoiUUF6cjEwTFI4M0gzYzdLN3ZfMDgyZyIsIml2IjoiUWM2c3RLVTg4Ty1oWnZiMyJ9.wvD9dnE40HVAMPuHI7h3wpFZx3OOnNjSUzsOtPXVL8w.XZlxpE3exE3l8kqZkWgoyg.vfK1f2HI_AuYzQbstHeMpq19qdRgESLQuk5RHj9IzPW9Zj0dvKsEJ8a7MQjo6zepNhpP-rUbV06WDw_c2T0riB5SfsVBNLSazxSo9HxCiuzIpYFledAmfkUI0nQDlR1swKxetYYPSR0jEjZNDjIV7vgG8RD3cqImqMYz43QgBSbZqgvMxLcvxzekXWwnXaUTxB0AA8tvQk94JgFl_vcZ3Hln82DPsw7ZdAcNoNqtC79JBI2W7o4SR4rv42OhUf3kJjuPHp9ch28wEAD7O3kfN-YFJE2HdLP97yWi0esR4MmKpCDJymIUBeuyZUrNqnrHTTv6BQEKFX8mL0KQf-XqeQpyw1-1iqfu57bZfAxXzcnRUnQc54XsRBKVHdjKh7lIK8TNmluI1vHEanFYRQntg86yjqIxmpXqiSogSxWfwi6cAF_Zgzr-4koG-ENtVz8c-Szi3ZaTCjLOvt-uPCe1kLR66t_iNCGDawMiLLkcF5bXm9tfUyUlb0_O0bdQW74P9fbVnyEXWp8v6vVu8WLEuYCK2pztMgjp8UuJmfPS6ls2uK42Samvk9soPO9HRNSiROO8nyGU-6V7iTJH5EB_lQ.2WIYHXy2FMNd78p7BYZvBQ".to_string()),
        ..Default::default()
    };

    let checks = OpenIDCallbackChecks {
        nonce: Some("9cda9a61a2b01b31aa0b31d3c33631a1"),
        ..Default::default()
    };

    let params = OpenIdCallbackParams::default()
        .redirect_uri("https://oidc-client.dev/cb")
        .checks(checks)
        .parameters(params);

    let _ = client.callback_async(&http_client, params).await.unwrap();
}
