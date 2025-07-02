//! Default Http Client

use std::time::Duration;

use reqwest::{
    header::{CONTENT_TYPE, WWW_AUTHENTICATE},
    ClientBuilder, Method, Response,
};

use crate::types::http_client::{HttpMethod, HttpRequest, HttpResponse, OidcHttpClient};

/// The default HttpClient
pub struct DefaultHttpClient;

impl DefaultHttpClient {
    async fn to_response(response: Response) -> HttpResponse {
        let status_code = response.status().as_u16();
        let response_headers = response.headers().clone();

        let mut content_type = None;

        if let Some(Ok(ct)) = response_headers
            .get(CONTENT_TYPE)
            .map(|ct| ct.to_str().map(|s| s.to_string()))
        {
            content_type = Some(ct);
        };

        let mut www_authenticate = None;

        if let Some(Ok(www)) = response_headers
            .get(WWW_AUTHENTICATE)
            .map(|www| www.to_str().map(|s| s.to_string()))
        {
            www_authenticate = Some(www);
        };

        let mut dpop_nonce = None;

        if let Some(Ok(dn)) = response_headers
            .get("dpop-nonce")
            .map(|dn| dn.to_str().map(|s| s.to_string()))
        {
            dpop_nonce = Some(dn);
        };

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
            content_type,
            www_authenticate,
            dpop_nonce,
        }
    }
}

impl OidcHttpClient for DefaultHttpClient {
    async fn request(&self, req: HttpRequest) -> Result<HttpResponse, String> {
        let client = ClientBuilder::new()
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("{e}"))?;

        let method = match req.method {
            HttpMethod::GET => Method::GET,
            HttpMethod::POST => Method::POST,
            HttpMethod::PUT => Method::PUT,
            HttpMethod::PATCH => Method::PATCH,
            HttpMethod::DELETE => Method::DELETE,
            HttpMethod::HEAD => Method::HEAD,
            HttpMethod::OPTIONS => Method::OPTIONS,
            HttpMethod::TRACE => Method::TRACE,
            HttpMethod::CONNECT => Method::CONNECT,
        };

        let mut req_builder = client.request(method, req.url);

        if let Some(body) = req.body {
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
