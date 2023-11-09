use lru_time_cache::LruCache;

#[derive(Clone)]
pub struct DPoPNonceCache {
    pub(crate) cache: LruCache<String, String>,
}

impl DPoPNonceCache {
    pub(crate) fn new() -> Self {
        Self {
            cache: LruCache::<String, String>::with_capacity(100),
        }
    }
}

impl std::fmt::Debug for DPoPNonceCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DPoPNonceCache")
            .field("cache", &"LruCache<String, String>")
            .finish()
    }
}
