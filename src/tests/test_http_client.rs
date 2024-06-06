use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
};

use josekit::Value;
use url::Url;

use crate::{
    helpers::{decode_jwt, form_url_encoded_to_string_map},
    types::{
        http_client::ClientCertificate, HttpMethod, HttpRequest, HttpResponse, OidcHttpClient,
    },
};

pub struct TestHttpReqRes {
    pub url: Url,
    pub method: HttpMethod,
    pub headers: HashMap<String, Vec<String>>,
    pub dpop: bool,
    pub dpop_ath: bool,
    pub dpop_nonce_not_present: bool,
    pub dpop_nonce: Option<String>,
    pub body: Option<String>,
    pub mtls: bool,

    pub response_body: Option<String>,
    pub response_status_code: u16,
    pub response_content_type: Option<String>,
    pub response_www_authenticate: Option<String>,
    pub response_dpop_nonce: Option<String>,
}

impl TestHttpReqRes {
    pub fn new(url: impl Into<String>) -> Self {
        TestHttpReqRes {
            url: Url::parse(&url.into()).unwrap(),
            method: HttpMethod::GET,
            headers: HashMap::new(),
            dpop: false,
            dpop_ath: false,
            dpop_nonce_not_present: false,
            dpop_nonce: None,
            body: None,
            mtls: false,
            response_body: None,
            response_status_code: 200,
            response_content_type: None,
            response_www_authenticate: None,
            response_dpop_nonce: None,
        }
    }

    pub fn assert_request_method(mut self, method: HttpMethod) -> Self {
        self.method = method;
        self
    }

    pub fn assert_request_header(mut self, key: impl Into<String>, value: Vec<String>) -> Self {
        self.headers.insert(key.into(), value);
        self
    }

    pub fn assert_dpop(mut self) -> Self {
        self.dpop = true;
        self
    }

    pub fn assert_dpop_ath(mut self) -> Self {
        self.dpop_ath = true;
        self
    }

    pub fn assert_dpop_nonce_not_present(mut self) -> Self {
        self.dpop_nonce_not_present = true;
        self
    }

    pub fn assert_dpop_nonce_value(mut self, val: impl Into<String>) -> Self {
        self.dpop_nonce = Some(val.into());
        self
    }

    pub fn assert_request_body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }

    pub fn assert_request_mtls(mut self, mtls: bool) -> Self {
        self.mtls = mtls;
        self
    }

    pub fn set_response_body(mut self, response_body: impl Into<String>) -> Self {
        self.response_body = Some(response_body.into());
        self
    }

    pub fn set_response_status_code(mut self, response_status_code: u16) -> Self {
        self.response_status_code = response_status_code;
        self
    }

    pub fn set_response_content_type_header(mut self, ct: impl Into<String>) -> Self {
        self.response_content_type = Some(ct.into());
        self
    }

    pub fn set_response_www_authenticate_header(mut self, www: impl Into<String>) -> Self {
        self.response_www_authenticate = Some(www.into());
        self
    }

    pub fn set_response_dpop_nonce_header(mut self, nonce: impl Into<String>) -> Self {
        self.response_dpop_nonce = Some(nonce.into());
        self
    }

    pub fn build(self) -> TestHttpClient {
        let http_client = TestHttpClient::new();

        http_client.add(self)
    }
}

pub struct TestHttpClient {
    req_res: RefCell<VecDeque<TestHttpReqRes>>,
    pub return_client_cert: bool,
}

impl TestHttpClient {
    pub fn new() -> Self {
        Self {
            req_res: RefCell::new(VecDeque::with_capacity(5)),
            return_client_cert: false,
        }
    }

    pub fn add(mut self, req_res: TestHttpReqRes) -> Self {
        self.req_res.get_mut().push_back(req_res);

        self
    }

    pub fn return_client_cert(&mut self, v: bool) {
        self.return_client_cert = v;
    }

    pub fn assert(&self) {
        assert!(
            self.req_res.borrow().is_empty(),
            "All requests not fullfilled"
        );
    }
}

unsafe impl Sync for TestHttpClient {}

impl OidcHttpClient for TestHttpClient {
    async fn get_client_certificate(&self, _req: &HttpRequest) -> Option<ClientCertificate> {
        if self.return_client_cert {
            return Some(ClientCertificate {
                cert: "".to_string(),
                key: "".to_string(),
            });
        }
        None
    }

    async fn request(&self, mut req: HttpRequest) -> Result<HttpResponse, String> {
        let mut req_res_list = self.req_res.borrow_mut();

        let req_res = req_res_list.pop_front().unwrap();

        if req_res.dpop
            || req_res.dpop_ath
            || req_res.dpop_nonce.is_some()
            || req_res.dpop_nonce_not_present
        {
            if req_res.dpop && req.headers.get("DPoP").is_none() {
                assert!(false, "Expected DPoP header")
            }

            if let Some(Some(dpop)) = req
                .headers
                .get("DPoP")
                .map(|d| d.first().map(|v| v.to_owned()))
            {
                req.headers.remove("DPoP");

                let decoded = decode_jwt(&dpop).unwrap();

                if req_res.dpop_ath {
                    assert!(decoded.payload.claim("ath").is_some());
                }

                if req_res.dpop_nonce_not_present {
                    assert!(decoded.payload.claim("nonce").is_none())
                }

                if let Some(nonce) = req_res.dpop_nonce {
                    if nonce.is_empty() {
                        assert!(decoded.payload.claim("nonce").is_some());
                    } else {
                        assert_eq!(
                            decoded.payload.claim("nonce").unwrap().as_str().unwrap(),
                            nonce
                        );
                    }
                }
            }
        }

        assert_eq!(req.url, req_res.url);
        assert_eq!(req.method, req_res.method);
        assert_eq!(req.headers, req_res.headers);

        if req_res
            .headers
            .get("content-type")
            .is_some_and(|ct| ct.contains(&"application/json".to_string()))
        {
            assert_eq!(
                req.body.map(|b| serde_json::from_str::<Value>(&b).unwrap()),
                req_res
                    .body
                    .map(|b| serde_json::from_str::<Value>(&b).unwrap()),
            )
        } else if req_res
            .headers
            .get("content-type")
            .is_some_and(|ct| ct.contains(&"application/x-www-form-urlencoded".to_string()))
        {
            assert_eq!(
                req.body.map(|b| form_url_encoded_to_string_map(&b)),
                req_res.body.map(|b| form_url_encoded_to_string_map(&b)),
            )
        } else {
            assert_eq!(req.body, req_res.body);
        }

        assert_eq!(req.mtls, req_res.mtls);

        Ok(HttpResponse {
            body: req_res.response_body,
            status_code: req_res.response_status_code,
            content_type: req_res.response_content_type,
            dpop_nonce: req_res.response_dpop_nonce,
            www_authenticate: req_res.response_www_authenticate,
        })
    }
}
