use std::{collections::HashMap, sync::Mutex};

use lazy_static::lazy_static;

/*
   About this module

   Since tests use real domain, and without modding hosts file or some weird stubs,
   its is impossible to mock a real server.

   What this module does is, it has a global mutex called TEST_URL_MAP that contains
   a hashmap of real domain that is being mocked and the port of the mock server used in that test.
   The real domain is unique for each tests and same for the port of the mock server.

   The test will add its real domain and mocked port. When http::request function get called, it
   calls process_url (that is a function present only for test), which will lookup the real domain
   from the TEST_URL_MAP and make a request to localhost with that port. Only the host gets replaced.

   eg:
   real_domain - example.com
   real_url - https://example.com/path?query=1

   mock_port - 5332
   mock_url - http://127.0.0.1:5332

   let url = process_url(real_url); -> see this in http module.
   url is http://127.0.0.1:5332/path?query=1
*/

lazy_static! {
    pub static ref TEST_URL_MAP: Mutex<HashMap<String, u16>> = Mutex::new(HashMap::new());
    pub static ref COUNTER: Mutex<u64> = Mutex::new(0);
}

#[cfg(test)]
pub fn get_url_with_count(url: &str) -> String {
    let mut c = COUNTER.lock().unwrap();
    *c += 1;
    url.replace("<>", &*c.to_string())
}

#[cfg(not(test))]
pub fn get_url_with_count(url: &str) -> String {
    url.to_owned()
}

#[cfg(test)]
pub fn set_mock_domain(real_domain: &String, mock_port: u16) {
    let mut url_map = TEST_URL_MAP.lock().unwrap();
    let existing_url = url_map.get(real_domain);
    if existing_url.is_none() {
        url_map.insert(real_domain.to_owned(), mock_port.to_owned());
    }
}

#[cfg(not(test))]
pub fn set_mock_domain(_real_domain: &String, _mock_port: u16) {}

#[cfg(test)]
pub fn process_url(url: String) -> String {
    let mut parsed = url::Url::parse(&url).unwrap();
    let mut host = parsed.host_str().unwrap().to_string();
    if let Some(port) = parsed.port() {
        host = host + &format!(":{}", port);
    }
    let url_map = TEST_URL_MAP.lock().unwrap();
    let mocked_port = url_map.get(&host).unwrap();

    parsed.set_host(Some("127.0.0.1:{}")).unwrap();
    parsed.set_port(Some(mocked_port.to_owned())).unwrap();
    parsed.set_scheme("http").unwrap();
    parsed.to_string()
}

#[cfg(not(test))]
pub fn process_url(url: String) -> String {
    url
}
