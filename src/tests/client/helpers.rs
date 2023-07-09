use url::Url;

pub(crate) fn get_query(url: &Url, name: &str) -> Option<String> {
    let mut query = url.query_pairs();
    query
        .find(|(q_name, _)| q_name == name)
        .map(|(_, q_value)| q_value.to_string())
}
