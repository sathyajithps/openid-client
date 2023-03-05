# Discovery

## Issuer Discovery

You can pass in a url, `https` or `http` to automatically discover OpenId provider.

```rust
use openid_client::Issuer;

fn main () {
    let issuer = Issuer::discover("https://auth.example.com").unwrap();
}
```

You can also use a full discovery url or a custom path to get the issuer.

```rust
use openid_client::Issuer;

fn main () {
    let issuer_full = Issuer::discover("https://auth.example.com/.well-known/openid-configuration").unwrap();
    let issuer_custom = Issuer::discover("https://auth.example.com/.well-known/openid-configuration").unwrap();
}
```

Discovering an issuer without an absolute url will result in `Err(OidcClientError)`

If you want to add additional request headers or set the timeout for each request, call the `Issuer::discover_with_interceptor` method. It accepts a `mut Box<dyn FnMut(&openid_client::Request) -> openid_client::RequestOptions>` as a second argument.

```rust
use openid_client::Issuer;

fn main () {
    let request_options = |_request: &openid_client::Request| {
        let mut headers = openid_client::HeaderMap::new(); // openid_client::HeaderMap is a re-export from reqwest crate
        headers.append("testHeader", openid_client::HeaderValue::from_static("testHeaderValue")); // openid_client::HeaderValue is a re-export from reqwest crate

        RequestOptions {
            headers,
            timeout: std::time::Duration::from_millis(3500),
        }
    };

    let issuer = Issuer::discover_with_interceptor("https://auth.example.com", Box::new(request_options)).unwrap();
}
```

## Webfinger Discovery

Issuer can be discovered using a webfinger query. You can use an email, a URI [RFC 3986](https://www.ietf.org/rfc/rfc3986.txt) syntax.

```rust
use openid_client::Issuer;

fn main () {
    let issuer_email = Issuer::webfinger("joe@email.example.com").unwrap();
    let issuer_uri = Issuer::webfinger("https://uri.example.com/joe").unwrap();
    let issuer_uri_port = Issuer::webfinger("https://port.example.com:8080").unwrap();
    let issuer_acct_syntax = Issuer::webfinger("acct:juliet%40capulet@example.com").unwrap();
}
```

If you want to add additional request headers or set the timeout for each request, call the `Issuer::webfinger_with_interceptor` method. It accepts a `mut Box<dyn FnMut(&openid_client::Request) -> openid_client::RequestOptions>` as a second argument.

```rust
use openid_client::Issuer;

fn main () {
    let request_options = |_request: &openid_client::Request| {
        let mut headers = openid_client::HeaderMap::new(); // openid_client::HeaderMap is a re-export from reqwest crate
        headers.append("testHeader", openid_client::HeaderValue::from_static("testHeaderValue")); // openid_client::HeaderValue is a re-export from reqwest crate

        RequestOptions {
            headers,
            timeout: std::time::Duration::from_millis(3500),
        }
    };

    let issuer = Issuer::webfinger_with_interceptor("joe@example.com", Box::new(request_options)).unwrap();
}
```
