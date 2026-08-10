use crate::cache::{Cache, SurrogateKey};
use std::sync::Arc;

/// A shared cache handle used by integration tests.
#[derive(Clone)]
pub struct InMemoryCache(pub(crate) Arc<Cache>);

impl Default for InMemoryCache {
    fn default() -> Self {
        Self(Arc::new(Cache::default()))
    }
}

impl InMemoryCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn purge(&self, surrogates: Vec<String>) {
        for surrogate in surrogates {
            if let Ok(key) = surrogate.parse::<SurrogateKey>() {
                self.0.purge(key, false);
            }
        }
    }
}

impl std::fmt::Display for InMemoryCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InMemoryCache")
    }
}
