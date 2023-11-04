use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use url::Url;

use crate::types::{Interceptor, Lookup, Request, RequestInterceptor, RequestOptions};

const CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIFUDCCAzigAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwgYExCzAJBgNVBAYTAkdC
MRAwDgYDVQQIDAdFbmdsYW5kMRIwEAYDVQQKDAlBbGljZSBMdGQxKDAmBgNVBAsM
H0FsaWNlIEx0ZCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkxIjAgBgNVBAMMGUFsaWNl
IEx0ZCBJbnRlcm1lZGlhdGUgQ0EwHhcNMTgwOTIxMTU1NTAwWhcNMTkxMDAxMTU1
NTAwWjCBizELMAkGA1UEBhMCQ1oxDzANBgNVBAgMBlByYWd1ZTESMBAGA1UEBwwJ
U3RyYXNuaWNlMRAwDgYDVQQKDAdCb2IgTHRkMRQwEgYDVQQLDAtFbmdpbmVlcmlu
ZzERMA8GA1UEAwwIY2xpZW50aWQxHDAaBgkqhkiG9w0BCQEWDXBhbnZhQGJvYi5s
dGQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDHZbAIXt6QFLYhBql9
pWBZx1R7A12o7gV5huVVeVEV9g+pmXdKU1Jq/OrQgNsS1ScY3cRqx6HLqmBxVh5w
rQ6g02d1QV2+RHJopC1kg7B4/pznfj44JxW0HQmSYYi+ATvfyuzBU+Rax87ALinL
r5gZTB69W/9Pr9smPbGHr3UM1mHz8Kd8Wvs494EQo/u7ivvbV8Kr8oR5VgsBCTMQ
A7fla7TxX8ObgRNSmwG/Sjr1Dv2baqGvuhQ70tqiZRRo1uuHjwOUzpQeF9LdFniK
HwhjnLlFucVK6inDZ2VD/oJyEOq4/pjTFemB6QgRNyqKUmd8lpenVSuujJ7TJNEy
Vw33AgMBAAGjgcUwgcIwCQYDVR0TBAIwADARBglghkgBhvhCAQEEBAMCBaAwMwYJ
YIZIAYb4QgENBCYWJE9wZW5TU0wgR2VuZXJhdGVkIENsaWVudCBDZXJ0aWZpY2F0
ZTAdBgNVHQ4EFgQUoT7Nh2gJLqlru7QH7sSgxBaNcOswHwYDVR0jBBgwFoAU9aXg
CTQVzkjeGVwlbmtKkYn5/rIwDgYDVR0PAQH/BAQDAgXgMB0GA1UdJQQWMBQGCCsG
AQUFBwMCBggrBgEFBQcDBDANBgkqhkiG9w0BAQsFAAOCAgEAqjXoNfaOG1Kxk9jO
vrHfTNdgGdrpaudZH4gRU2044m8JvazUxhnWgk+n4mkjVD5CrNu7FWza3twt2nIR
50GKWilg2fiBIPcH5RVYz7gdO3r2N1nWohx3P49bGEyyDwxR1aeM/O8w0gQ70Ayd
oPPKggpef61MsLgYl+tiVqKx3VHO5A6hPScH26p56DOq28fjLZPnTskoXxn1IHB4
Ea4fUC1x4gXDS38qvvcBVWmQWbeTm1dWEUsmRVp6D1jPAsikYjzb86lOzC0S7V6l
X1QwAL4nxDsBpxx1JlKeNDk5sdr7mHQtODjq8w+Uo0EPmgGdTsCiBgPfWHRgYAs9
HTFbC6FWeu+Bu2Nfuo8MAYCY2+FhGEwUHuUtYUR04V9F6+J4xmSsPZp46PNo4F2u
gL4Nm81py3eDOq9WcuoN0iB8XqcjmFb3BvirpSzmNuP1FsqDj+QGN73W/seHylFM
AGnsAaF3A3gBUFF26+xz7hSXLGbEhoR6FYBZKvLBQgS3zna6KbYdw0pqUBvrEJfr
VXCQPy/Y1C3EnEhQqJDx9Rmw5qm6RpuCPga4pDzQPBLny+ggmb4BqHieD+Xz3g0b
N/84lxiSg60mlyuEwOHcQMmlOxjYf2zliCqRptD/LlfITlmzGjds9BhLlkHIBR3I
kEejZluclYP0Dljd65DCTqY1z0c=
-----END CERTIFICATE-----"#;

const KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAx2WwCF7ekBS2IQapfaVgWcdUewNdqO4FeYblVXlRFfYPqZl3
SlNSavzq0IDbEtUnGN3Easehy6pgcVYecK0OoNNndUFdvkRyaKQtZIOweP6c534+
OCcVtB0JkmGIvgE738rswVPkWsfOwC4py6+YGUwevVv/T6/bJj2xh691DNZh8/Cn
fFr7OPeBEKP7u4r721fCq/KEeVYLAQkzEAO35Wu08V/Dm4ETUpsBv0o69Q79m2qh
r7oUO9LaomUUaNbrh48DlM6UHhfS3RZ4ih8IY5y5RbnFSuopw2dlQ/6CchDquP6Y
0xXpgekIETcqilJnfJaXp1Urroye0yTRMlcN9wIDAQABAoIBABT9hGltKzq5o26Y
l/ENHrZ0wFTuxsZIwDTJ2YyE599K9t0gtakSWmO+2i0201kJLUN13P5so4CgH+Tu
bufnn9mYR5TVW7vy0qRnXAvvvP0PuI66AGzC2IsMX3yUXeO6l4X4g7HaVfikfgRH
F8lEY9uN4tKGQ7ssxQIijnS9KLJAE6A+zVBA3NVvq4oXSxcyiSlEb7drmOe/2Ibr
srC2pnFAZy+XEJ8sIi1o2BXoz70bJkCaryi5gs+01v6Yi8oE72h/YNSZRMahr5Hl
CznXdOsmNAQ23zgDhi0UhtH5+5Xxi3k9dT8wxT4B14YDmw3sAmoUfbYwj3xWlQ3t
l4QofRkCgYEA4feLw/LgbRd94yunKm8IsaZ8ISUjazjgftKOtk1oxedsbIJyq+F/
rfO7XOMqsGyF1gNpXtDJaSJgSngqOwG13lk8MWtpGjqChkkmHHvMBK8IIWLkE/fu
reQ68V5BDA51PJf8HpLxEAgpH64s9wa1WtBXHO2ZppweMxjJVBO7nFUCgYEA4eYd
Nvz8WgWNUkeWLGC++7ublc5gXBr9kioXbTJ4Pp8Va2Ngaa/PZm0yMDSD9xxpHkCC
ZtlsZlUXVBwldh8A8C841YCOgJvprC4+UQobGndsgwQ8KmhwjIKj5z5uxm5mwBi8
xdmnfJF+sP3hwJMfK7DaS/uWRs98874eSHloTRsCgYBaV7hffUlRFGVWX+uTwZS+
Qgu6zLhec/z9d31rUYOkLCRjNbxXD+8WQy4TsxcsNhdEO1TzfZIpIH9TBrwLn2Fx
Jkg0kfcRb3cj7Tb5iF1HOhuMDZeWjDe2+lq+iaqEAXvJ4BICv0j12e1nJyH/GYWE
a2uIu04FGMHSOAS2QrVtiQKBgAVjMpEsKWyQM1WiBW/bgtKIH+bLvDqWHjQNMu/U
w09jBeTAwvziR4T+17KUng0XrV4eVb3UM6ShJORJo48UoDYaOjXFUiC5FzKXC79t
CUZxULIzOKgeQ4jmWLhcIdIzsdmk/WOOlFMBOU9JTsgD+jtVhW9IecYIjsdVYm2C
D72/AoGAIYwlwstX7x5dlJOVe9ytMBkbuFKdycGvVxjEzvHkjzrpxUY3v/lVRBFN
Ym+FYK6KtEjrawUvE9CwzkoXiQbisQsGkp1sJxYDkDzW1jf50T3DOOCbGmW6bi7H
2LZBr34osdcugbFGO07Y8gAiRrh+lbv1JBzALHt93QSVeN9mPNY=
-----END RSA PRIVATE KEY-----"#;

#[derive(Debug, Clone)]
pub(crate) struct TestLookup {
    pub test_server_port: u16,
}

impl Lookup for TestLookup {
    fn lookup(&mut self, _domain: &Url) -> Url {
        format!("http://127.0.0.1:{}", self.test_server_port)
            .parse()
            .unwrap()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TestInterceptor {
    pub test_server_port: Option<u16>,
    pub test_header: Option<String>,
    pub test_header_value: Option<String>,
    pub crt: Option<String>,
    pub key: Option<String>,
    pub pfx: Option<Vec<u8>>,
}

impl Interceptor for TestInterceptor {
    fn intercept(&mut self, _req: &Request) -> RequestOptions {
        let mut lookup: Option<Box<dyn Lookup>> = None;

        if let Some(p) = &self.test_server_port {
            lookup = Some(Box::new(TestLookup {
                test_server_port: p.to_owned(),
            }))
        }

        let mut headers: HeaderMap = HeaderMap::new();

        if let (Some(h), Some(v)) = (&self.test_header, &self.test_header_value) {
            if let (Ok(header), Ok(value)) = (
                HeaderName::from_bytes(h.as_bytes()),
                HeaderValue::from_bytes(v.as_bytes()),
            ) {
                headers.append(header, value);
            };
        }

        let mut crt = None;
        let mut key = None;

        if self.crt.is_some() && self.key.is_some() {
            crt = self.crt.clone();
            key = self.key.clone();
        }

        let mut pfx = None;
        if self.pfx.is_some() {
            pfx = self.pfx.clone();
        }

        RequestOptions {
            lookup,
            headers,
            timeout: Duration::from_millis(5000),
            client_crt: crt,
            client_key: key,
            client_pkcs_12: pfx,
            ..Default::default()
        }
    }

    fn clone_box(&self) -> Box<dyn Interceptor> {
        Box::new(TestInterceptor {
            test_header: self.test_header.clone(),
            test_header_value: self.test_header_value.clone(),
            test_server_port: self.test_server_port.clone(),
            crt: self.crt.clone(),
            key: self.key.clone(),
            pfx: self.pfx.clone(),
        })
    }
}

pub(crate) fn get_default_test_interceptor(port: Option<u16>) -> Option<RequestInterceptor> {
    if let Some(p) = port {
        return Some(Box::new(TestInterceptor {
            test_header: None,
            test_header_value: None,
            test_server_port: Some(p),
            crt: None,
            key: None,
            pfx: None,
        }));
    }

    None
}

pub(crate) fn get_default_test_interceptor_with_crt_key(
    port: Option<u16>,
) -> Option<RequestInterceptor> {
    if let Some(p) = port {
        return Some(Box::new(TestInterceptor {
            test_header: None,
            test_header_value: None,
            test_server_port: Some(p),
            crt: Some(CERT.to_string()),
            key: Some(KEY.to_string()),
            pfx: None,
        }));
    }

    None
}

pub(crate) fn get_default_test_interceptor_with_pfx(
    port: Option<u16>,
) -> Option<RequestInterceptor> {
    if let Some(p) = port {
        let pfx = include_bytes!("testcert.p12");
        return Some(Box::new(TestInterceptor {
            test_header: None,
            test_header_value: None,
            test_server_port: Some(p),
            crt: None,
            key: None,
            pfx: Some(pfx.to_vec()),
        }));
    }

    None
}
