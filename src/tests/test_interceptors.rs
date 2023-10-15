use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use url::Url;

use crate::types::{Interceptor, Lookup, Request, RequestInterceptor, RequestOptions};

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

        RequestOptions {
            lookup,
            headers,
            timeout: Duration::from_millis(5000),
            ..Default::default()
        }
    }

    fn clone_box(&self) -> Box<dyn Interceptor> {
        Box::new(TestInterceptor {
            test_header: self.test_header.clone(),
            test_header_value: self.test_header_value.clone(),
            test_server_port: self.test_server_port.clone(),
        })
    }
}

pub(crate) fn get_default_test_interceptor(port: Option<u16>) -> Option<RequestInterceptor> {
    if let Some(p) = port {
        return Some(Box::new(TestInterceptor {
            test_header: None,
            test_header_value: None,
            test_server_port: Some(p),
        }));
    }

    None
}
