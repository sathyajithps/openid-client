use url::Url;

use crate::client::Client;

pub(crate) struct TestClients {
    pub client: Client,
    pub client_with_meta: Client,
    pub client_with_multiple_metas: Client,
    pub client_with_query: Client,
}

pub(crate) fn get_query(url: &Url, name: &str) -> Option<String> {
    let mut query = url.query_pairs();
    query
        .find(|(q_name, _)| q_name == name)
        .map(|(_, q_value)| q_value.to_string())
}
