use crate::{
    Error,
    cache::{Cache, WriteOptions},
    error::HandleError,
    wiggle_abi::types::{self, CacheWriteOptionsMask},
};
use http::{HeaderMap, request::Parts};
use std::{
    collections::{BTreeMap, HashMap, HashSet, btree_map::Entry},
    fmt::Display,
    sync::{Arc, RwLock},
    time::Instant,
};
use tracing::{Level, event};

/// Handle used for a non-existing cache entry.
pub fn not_found_handle() -> types::CacheHandle {
    types::CacheHandle::from(u32::MAX)
}

type PrimaryCacheKey = Vec<u8>;

/// A shared cache handle used by integration tests.
#[derive(Clone)]
pub struct InMemoryCache(pub(crate) Arc<Cache>, pub(crate) Arc<LegacyCache>);

impl Default for InMemoryCache {
    fn default() -> Self {
        Self(Arc::new(Cache::default()), Arc::new(LegacyCache::default()))
    }
}

impl InMemoryCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn legacy(&self) -> &LegacyCache {
        &self.1
    }

    pub fn purge(&self, surrogates: Vec<String>) {
        self.1.purge(surrogates.clone());
        for surrogate in surrogates {
            if let Ok(key) = surrogate.parse::<crate::cache::SurrogateKey>() {
                self.0.purge(key, false);
            }
        }
    }
}

impl Display for InMemoryCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.1.fmt(f)
    }
}

/// The cache implementation used by the legacy `fastly_cache` ABI.
///
/// The current cache engine is asynchronous and implements request collapsing. The old ABI exposed
/// cache handles directly, so integration tests using that ABI need this handle-indexed store.
#[derive(Clone, Default, Debug)]
pub(crate) struct LegacyCache {
    pub(crate) cache_entries: Arc<RwLock<Vec<Option<CacheEntry>>>>,
    pub(crate) key_candidates: Arc<RwLock<BTreeMap<PrimaryCacheKey, Vec<types::CacheHandle>>>>,
    pub(crate) pending_tx: Arc<RwLock<HashMap<types::CacheHandle, PrimaryCacheKey>>>,
}

impl LegacyCache {
    pub fn purge(&self, surrogates: Vec<String>) {
        let mut cache_entries = self.cache_entries.write().unwrap();
        let surrogates_to_purge: HashSet<String> = surrogates.into_iter().collect();

        for entry in cache_entries.iter_mut() {
            if let Some(cache_entry) = entry {
                if !cache_entry.surrogate_keys.is_disjoint(&surrogates_to_purge) {
                    *entry = None;
                }
            }
        }
    }

    pub fn get_entry(&self, key: &[u8], headers: &HeaderMap) -> Option<types::CacheHandle> {
        let candidates = self.key_candidates.read().unwrap();
        candidates.get(key).and_then(|candidates| {
            let entries = self.cache_entries.read().unwrap();
            candidates.iter().find_map(|handle| {
                get_entry(&entries, *handle).and_then(|entry| {
                    (entry.vary_matches(headers) && entry.is_usable()).then_some(*handle)
                })
            })
        })
    }

    pub fn transaction_lookup(
        &self,
        key: PrimaryCacheKey,
        headers: &HeaderMap,
    ) -> types::CacheHandle {
        if let Some(handle) = self.get_entry(&key, headers) {
            return handle;
        }

        let handle = push_entry(&mut self.cache_entries.write().unwrap(), None);
        self.pending_tx.write().unwrap().insert(handle, key);
        handle
    }

    pub fn pending_key(&self, handle: types::CacheHandle) -> Option<PrimaryCacheKey> {
        self.pending_tx.read().unwrap().get(&handle).cloned()
    }

    pub fn insert(
        &self,
        key: PrimaryCacheKey,
        options_mask: CacheWriteOptionsMask,
        options: &WriteOptions,
        request_parts: Option<&Parts>,
    ) -> Result<types::CacheHandle, Error> {
        let vary = if options_mask.contains(CacheWriteOptionsMask::VARY_RULE) {
            let mut vary = BTreeMap::new();
            if let Some(parts) = request_parts {
                for header in options.vary_rule.headers() {
                    vary.insert(
                        header.as_str().to_owned(),
                        parts
                            .headers
                            .get(header)
                            .map(|value| value.to_str().map(str::to_owned))
                            .transpose()?,
                    );
                }
            }
            vary
        } else {
            BTreeMap::new()
        };

        let surrogate_keys = if options_mask.contains(CacheWriteOptionsMask::SURROGATE_KEYS) {
            options
                .surrogate_keys
                .iter()
                .map(ToString::to_string)
                .collect()
        } else {
            HashSet::new()
        };

        let entry = CacheEntry {
            key: key.clone(),
            body_bytes: vec![],
            vary,
            initial_age_ns: options.initial_age.as_nanos().try_into().ok(),
            max_age_ns: Some(options.max_age.as_nanos().try_into().unwrap_or(u64::MAX)),
            swr_ns: options.stale_while_revalidate.as_nanos().try_into().ok(),
            created_at: Instant::now(),
            user_metadata: options.user_metadata.to_vec(),
            surrogate_keys,
        };

        let empty_headers = HeaderMap::new();
        let headers = request_parts
            .map(|parts| &parts.headers)
            .unwrap_or(&empty_headers);
        let entry_handle = match self.get_entry(&key, headers) {
            Some(handle) => {
                event!(Level::TRACE, "Overwriting cache entry {}", handle);
                get_entry_mut(&mut self.cache_entries.write().unwrap(), handle)
                    .map(|old| *old = entry);
                handle
            }
            None => {
                let handle = push_entry(&mut self.cache_entries.write().unwrap(), Some(entry));
                match self.key_candidates.write().unwrap().entry(key) {
                    Entry::Vacant(vacant) => {
                        vacant.insert(vec![handle]);
                    }
                    Entry::Occupied(mut occupied) => occupied.get_mut().push(handle),
                }
                event!(Level::TRACE, "Wrote new cache entry {}", handle);
                handle
            }
        };

        Ok(entry_handle)
    }

    pub fn append_body(&self, handle: types::CacheHandle, bytes: &[u8]) -> Result<(), Error> {
        get_entry_mut(&mut self.cache_entries.write().unwrap(), handle)
            .map(|entry| entry.body_bytes.extend_from_slice(bytes))
            .ok_or_else(|| HandleError::InvalidCacheHandle(handle).into())
    }

    pub fn body(&self, handle: types::CacheHandle) -> Result<Vec<u8>, Error> {
        get_entry(&self.cache_entries.read().unwrap(), handle)
            .map(|entry| entry.body_bytes.clone())
            .ok_or_else(|| HandleError::InvalidCacheHandle(handle).into())
    }

    pub fn entry(&self, handle: types::CacheHandle) -> Result<CacheEntry, Error> {
        get_entry(&self.cache_entries.read().unwrap(), handle)
            .cloned()
            .ok_or_else(|| HandleError::InvalidCacheHandle(handle).into())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CacheEntry {
    pub key: PrimaryCacheKey,
    pub body_bytes: Vec<u8>,
    pub vary: BTreeMap<String, Option<String>>,
    pub surrogate_keys: HashSet<String>,
    pub initial_age_ns: Option<u64>,
    pub max_age_ns: Option<u64>,
    pub swr_ns: Option<u64>,
    pub created_at: Instant,
    pub user_metadata: Vec<u8>,
}

impl CacheEntry {
    pub fn vary_matches(&self, headers: &HeaderMap) -> bool {
        self.vary.iter().all(|(key, value)| {
            headers.get(key).and_then(|header| header.to_str().ok()) == value.as_deref()
        })
    }

    pub fn age_ns(&self) -> u64 {
        self.created_at
            .elapsed()
            .as_nanos()
            .try_into()
            .ok()
            .and_then(|age: u64| age.checked_add(self.initial_age_ns.unwrap_or(0)))
            .unwrap_or(u64::MAX)
    }

    pub fn is_stale(&self) -> bool {
        let age = self.age_ns();
        match (self.max_age_ns, self.swr_ns) {
            (Some(max_age), Some(swr)) => age > max_age && age < max_age.saturating_add(swr),
            _ => false,
        }
    }

    pub fn is_usable(&self) -> bool {
        self.age_ns() < self.total_ttl_ns()
    }

    fn total_ttl_ns(&self) -> u64 {
        self.max_age_ns
            .unwrap_or_default()
            .saturating_add(self.swr_ns.unwrap_or_default())
    }
}

const NS_TO_S_FACTOR: u64 = 1_000_000_000;

fn handle_index(handle: types::CacheHandle) -> Option<usize> {
    let index: u32 = handle.into();
    (index != u32::MAX).then_some(index as usize)
}

fn push_entry(
    entries: &mut Vec<Option<CacheEntry>>,
    entry: Option<CacheEntry>,
) -> types::CacheHandle {
    let handle = types::CacheHandle::from(entries.len() as u32);
    entries.push(entry);
    handle
}

fn get_entry<'a>(
    entries: &'a [Option<CacheEntry>],
    handle: types::CacheHandle,
) -> Option<&'a CacheEntry> {
    handle_index(handle)
        .and_then(|index| entries.get(index))
        .and_then(Option::as_ref)
}

fn get_entry_mut<'a>(
    entries: &'a mut [Option<CacheEntry>],
    handle: types::CacheHandle,
) -> Option<&'a mut CacheEntry> {
    handle_index(handle)
        .and_then(|index| entries.get_mut(index))
        .and_then(Option::as_mut)
}

impl Display for LegacyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Cache State:")?;
        writeln!(f, "  Entries:")?;
        for (index, entry) in self.cache_entries.read().unwrap().iter().enumerate() {
            let handle = types::CacheHandle::from(index as u32);
            match entry {
                Some(entry) => {
                    let key = entry
                        .key
                        .iter()
                        .map(|byte| format!("{byte:X}"))
                        .collect::<String>();
                    writeln!(f, "    [{}]: {key}", handle)?;
                    writeln!(f, "      Age: {}", entry.age_ns() / NS_TO_S_FACTOR)?;
                    writeln!(
                        f,
                        "      Max-age: {:?}",
                        entry.max_age_ns.map(|x| x / NS_TO_S_FACTOR)
                    )?;
                    writeln!(
                        f,
                        "      Swr: {:?}",
                        entry.swr_ns.map(|x| x / NS_TO_S_FACTOR)
                    )?;
                    writeln!(f, "      Body: {} bytes", entry.body_bytes.len())?;
                }
                None => writeln!(f, "    [{}]: Purged", handle)?,
            }
        }
        Ok(())
    }
}
