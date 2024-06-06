use super::RequestResourceOptions;

#[derive(Default)]
/// # RequestResourceParams
pub struct RequestResourceParams<'a> {
    /// Resource server Url
    pub resource_url: &'a str,
    /// Access Token
    pub access_token: &'a str,
    /// Type of the token
    pub token_type: Option<&'a str>,
    /// Specify if the request should be retried once
    pub retry: bool,
    /// [RequestResourceOptions]
    pub options: RequestResourceOptions<'a>,
}

impl<'a> RequestResourceParams<'a> {
    /// Sets resource url
    pub fn resource_url(mut self, resource_url: &'a str) -> Self {
        self.resource_url = resource_url;
        self
    }

    /// Sets access token
    pub fn access_token(mut self, access_token: &'a str) -> Self {
        self.access_token = access_token;
        self
    }

    /// Sets token type
    pub fn token_type(mut self, token_type: &'a str) -> Self {
        self.token_type = Some(token_type);
        self
    }

    /// Sets retry
    pub fn retry(mut self, retry: bool) -> Self {
        self.retry = retry;
        self
    }

    /// Sets options
    pub fn options(mut self, options: RequestResourceOptions<'a>) -> Self {
        self.options = options;
        self
    }
}
