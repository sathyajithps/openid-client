#![allow(unused)]
//! Default Http Client

use std::collections::HashMap;

use reqwest::Identity;

use crate::types::http_client::{
    ClientCertificate, HttpMethod, HttpRequest, HttpResponse, OidcHttpClient,
};

/// The default HttpClient
pub struct DefaultHttpClient;

impl DefaultHttpClient {
    async fn to_response(response: reqwest::Response) -> HttpResponse {
        let status_code = response.status().as_u16();
        let response_headers = response.headers().clone();

        let mut headers =
            HashMap::<String, Vec<String>>::with_capacity(response_headers.capacity());

        for (k, v) in response_headers {
            if let Some(k) = k {
                if let Ok(v) = v.to_str() {
                    let header_name = k.as_str().to_string();
                    if let Some(entry) = headers.get_mut(&header_name) {
                        entry.push(v.to_string());
                    } else {
                        let values = vec![v.to_string()];
                        headers.insert(header_name, values);
                    }
                }
            }
        }

        let body_result = response.text().await;
        let mut body: Option<String> = None;
        if let Ok(body_string) = body_result {
            if !body_string.is_empty() {
                body = Some(body_string);
            }
        }

        HttpResponse {
            body,
            status_code,
            headers,
        }
    }
}

impl OidcHttpClient for DefaultHttpClient {
    async fn request(&self, req: HttpRequest) -> Result<HttpResponse, String> {
        let mut client =
            reqwest::ClientBuilder::new().connect_timeout(std::time::Duration::from_secs(10));

        if req.mtls {
            if req.client_certificate.is_none() {
                return Err("Request require MTLS. No certificate found".to_owned());
            }

            let ClientCertificate { cert, key } = req.client_certificate.unwrap();

            let identity = Identity::from_pkcs8_pem(cert.as_bytes(), key.as_bytes())
                .map_err(|e| e.to_string())?;

            client = client.use_native_tls().identity(identity);
        }

        let client = client.build().map_err(|e| format!("{e}"))?;

        let method = match req.method {
            HttpMethod::GET => reqwest::Method::GET,
            HttpMethod::POST => reqwest::Method::POST,
            HttpMethod::PUT => reqwest::Method::PUT,
            HttpMethod::PATCH => reqwest::Method::PATCH,
            HttpMethod::DELETE => reqwest::Method::DELETE,
            HttpMethod::HEAD => reqwest::Method::HEAD,
            HttpMethod::OPTIONS => reqwest::Method::OPTIONS,
            HttpMethod::TRACE => reqwest::Method::TRACE,
            HttpMethod::CONNECT => reqwest::Method::CONNECT,
        };

        let mut req_builder = client.request(method, req.url);

        if let Some(body) = req.body.and_then(|b| b.body_string()) {
            req_builder = req_builder.body(body);
        }

        for (name, values) in req.headers {
            for value in values {
                req_builder = req_builder.header(name.clone(), value);
            }
        }

        req_builder = req_builder.header(
            "User-Agent",
            "openid-client (https://github.com/sathyajithps/openid-client)",
        );

        match req_builder.send().await {
            Ok(res) => Ok(Self::to_response(res).await),
            Err(e) => Err(format!("{e}")),
        }
    }
}
