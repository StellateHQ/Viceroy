use core::str;
use std::time::Duration;

use bytes::Bytes;
use http::HeaderMap;

use crate::body::Body;
use crate::cache::{CacheKey, SurrogateKeySet, VaryRule, WriteOptions};
use crate::error::HandleError;
use crate::sandbox::Sandbox;
use crate::wiggle_abi::types::CacheWriteOptionsMask;

use super::fastly_cache::FastlyCache;
use super::{Error, types};

fn load_cache_key(
    memory: &wiggle::GuestMemory<'_>,
    cache_key: wiggle::GuestPtr<[u8]>,
) -> Result<CacheKey, Error> {
    let bytes = memory.as_slice(cache_key)?.ok_or(Error::SharedMemory)?;
    let key: CacheKey = bytes.try_into().map_err(|_| Error::InvalidArgument)?;
    Ok(key)
}

fn load_write_options(
    memory: &wiggle::GuestMemory<'_>,
    mut options_mask: types::CacheWriteOptionsMask,
    options: &types::CacheWriteOptions,
) -> Result<WriteOptions, Error> {
    // Headers must be handled before this:
    assert!(
        !options_mask.contains(CacheWriteOptionsMask::REQUEST_HEADERS),
        "Viceroy bug! headers must be handled before load_write_options"
    );

    // Clear each bit of options_mask as we handle it, to make sure we catch any unknown options.
    let max_age = Duration::from_nanos(options.max_age_ns);

    let initial_age = if options_mask.contains(CacheWriteOptionsMask::INITIAL_AGE_NS) {
        Duration::from_nanos(options.initial_age_ns)
    } else {
        Duration::ZERO
    };

    options_mask &= !CacheWriteOptionsMask::INITIAL_AGE_NS;

    let stale_while_revalidate =
        if options_mask.contains(CacheWriteOptionsMask::STALE_WHILE_REVALIDATE_NS) {
            Duration::from_nanos(options.stale_while_revalidate_ns)
        } else {
            Duration::ZERO
        };
    options_mask &= !CacheWriteOptionsMask::STALE_WHILE_REVALIDATE_NS;

    let vary_rule = if options_mask.contains(CacheWriteOptionsMask::VARY_RULE) {
        let slice = options.vary_rule_ptr.as_array(options.vary_rule_len);
        let vary_rule_bytes = memory.as_slice(slice)?.ok_or(Error::SharedMemory)?;
        let vary_rule_str = str::from_utf8(vary_rule_bytes).map_err(Error::Utf8Expected)?;
        vary_rule_str.parse()?
    } else {
        VaryRule::default()
    };
    options_mask &= !CacheWriteOptionsMask::VARY_RULE;

    let user_metadata = if options_mask.contains(CacheWriteOptionsMask::USER_METADATA) {
        let slice = options
            .user_metadata_ptr
            .as_array(options.user_metadata_len);
        let user_metadata_bytes = memory.as_slice(slice)?.ok_or(Error::SharedMemory)?;
        Bytes::copy_from_slice(user_metadata_bytes)
    } else {
        Bytes::new()
    };
    options_mask &= !CacheWriteOptionsMask::USER_METADATA;

    let length = if options_mask.contains(CacheWriteOptionsMask::LENGTH) {
        Some(options.length)
    } else {
        None
    };
    options_mask &= !CacheWriteOptionsMask::LENGTH;

    let sensitive_data = options_mask.contains(CacheWriteOptionsMask::SENSITIVE_DATA);
    options_mask &= !CacheWriteOptionsMask::SENSITIVE_DATA;

    // SERVICE_ID differences are observable- but we don't implement that behavior. Error explicitly.
    if options_mask.contains(CacheWriteOptionsMask::SERVICE_ID) {
        return Err(Error::Unsupported {
            msg: "cache on_behalf_of is not supported in Viceroy",
        });
    }
    options_mask &= !CacheWriteOptionsMask::SERVICE_ID;

    let edge_max_age = if options_mask.contains(CacheWriteOptionsMask::EDGE_MAX_AGE_NS) {
        Duration::from_nanos(options.edge_max_age_ns)
    } else {
        max_age
    };
    if edge_max_age > max_age {
        tracing::error!(
            "deliver node max age {} must be less than TTL {}",
            edge_max_age.as_secs(),
            max_age.as_secs()
        );
        return Err(Error::InvalidArgument);
    }
    options_mask &= !CacheWriteOptionsMask::EDGE_MAX_AGE_NS;

    let surrogate_keys = if options_mask.contains(CacheWriteOptionsMask::SURROGATE_KEYS) {
        let slice = options
            .surrogate_keys_ptr
            .as_array(options.surrogate_keys_len);
        let surrogate_keys_bytes = memory.as_slice(slice)?.ok_or(Error::SharedMemory)?;
        surrogate_keys_bytes.try_into()?
    } else {
        SurrogateKeySet::default()
    };
    options_mask &= !CacheWriteOptionsMask::SURROGATE_KEYS;

    if !options_mask.is_empty() {
        return Err(Error::NotAvailable("unknown cache write option"));
    }

    Ok(WriteOptions {
        max_age,
        initial_age,
        stale_while_revalidate,
        vary_rule,
        user_metadata,
        length,
        sensitive_data,
        edge_max_age,
        surrogate_keys,
    })
}

struct LookupOptions {
    headers: HeaderMap,
    always_use_requested_range: bool,
}

fn load_lookup_options(
    sandbox: &Sandbox,
    memory: &wiggle::GuestMemory<'_>,
    mut options_mask: types::CacheLookupOptionsMask,
    options: wiggle::GuestPtr<types::CacheLookupOptions>,
) -> Result<LookupOptions, Error> {
    let options = memory.read(options)?;
    let headers = if options_mask.contains(types::CacheLookupOptionsMask::REQUEST_HEADERS) {
        let handle = options.request_headers;
        let parts = sandbox.request_parts(handle)?;
        parts.headers.clone()
    } else {
        HeaderMap::default()
    };

    options_mask &= !types::CacheLookupOptionsMask::REQUEST_HEADERS;

    if options_mask.contains(types::CacheLookupOptionsMask::SERVICE_ID) {
        // TODO: Support service-ID-keyed hashes, for testing internal services at Fastly
        return Err(Error::Unsupported {
            msg: "service ID in cache lookup is not supported in Viceroy",
        });
    }

    let always_use_requested_range =
        options_mask.contains(types::CacheLookupOptionsMask::ALWAYS_USE_REQUESTED_RANGE);
    options_mask &= !types::CacheLookupOptionsMask::ALWAYS_USE_REQUESTED_RANGE;

    if !options_mask.is_empty() {
        return Err(Error::NotAvailable("unknown cache lookup option"));
    }

    Ok(LookupOptions {
        headers,
        always_use_requested_range,
    })
}

#[allow(unused_variables)]
impl FastlyCache for Sandbox {
    async fn lookup(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_key: wiggle::GuestPtr<[u8]>,
        options_mask: types::CacheLookupOptionsMask,
        options: wiggle::GuestPtr<types::CacheLookupOptions>,
    ) -> Result<types::CacheHandle, Error> {
        let LookupOptions {
            headers,
            always_use_requested_range,
        } = load_lookup_options(self, memory, options_mask, options)?;
        let key = load_cache_key(memory, cache_key)?;
        let handle = self
            .in_memory_cache()
            .legacy()
            .get_entry(key.as_bytes(), &headers)
            .unwrap_or(crate::in_memory_cache::not_found_handle());
        Ok(handle)
    }

    async fn insert(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_key: wiggle::GuestPtr<[u8]>,
        options_mask: types::CacheWriteOptionsMask,
        options: wiggle::GuestPtr<types::CacheWriteOptions>,
    ) -> Result<types::BodyHandle, Error> {
        let key = load_cache_key(memory, cache_key)?;
        let guest_options = memory.read(options)?;

        let options = load_write_options(
            memory,
            options_mask & !CacheWriteOptionsMask::REQUEST_HEADERS,
            &guest_options,
        )?;
        let handle = self.in_memory_cache().legacy().insert(
            key.as_bytes().to_vec(),
            options_mask,
            &options,
            if options_mask.contains(CacheWriteOptionsMask::REQUEST_HEADERS) {
                Some(self.request_parts(guest_options.request_headers)?)
            } else {
                None
            },
        )?;
        Ok(self.insert_cache_body(handle))
    }

    async fn replace(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_key: wiggle::GuestPtr<[u8]>,
        options_mask: types::CacheReplaceOptionsMask,
        abi_options: wiggle::GuestPtr<types::CacheReplaceOptions>,
    ) -> Result<types::CacheReplaceHandle, Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn replace_get_age_ns(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_handle: types::CacheReplaceHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn replace_get_body(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_handle: types::CacheReplaceHandle,
        options_mask: types::CacheGetBodyOptionsMask,
        options: &types::CacheGetBodyOptions,
    ) -> Result<types::BodyHandle, Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn replace_get_hits(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_handle: types::CacheReplaceHandle,
    ) -> Result<u64, Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn replace_get_length(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_handle: types::CacheReplaceHandle,
    ) -> Result<u64, Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn replace_get_max_age_ns(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_handle: types::CacheReplaceHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn replace_get_stale_while_revalidate_ns(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_handle: types::CacheReplaceHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn replace_get_state(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_handle: types::CacheReplaceHandle,
    ) -> Result<types::CacheLookupState, Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn replace_get_user_metadata(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_handle: types::CacheReplaceHandle,
        out_ptr: wiggle::GuestPtr<u8>,
        out_len: u32,
        nwritten_out: wiggle::GuestPtr<u32>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn replace_insert(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_handle: types::CacheReplaceHandle,
        options_mask: types::CacheWriteOptionsMask,
        abi_options: wiggle::GuestPtr<types::CacheWriteOptions>,
    ) -> Result<types::BodyHandle, Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn transaction_lookup(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_key: wiggle::GuestPtr<[u8]>,
        options_mask: types::CacheLookupOptionsMask,
        options: wiggle::GuestPtr<types::CacheLookupOptions>,
    ) -> Result<types::CacheHandle, Error> {
        let LookupOptions { headers, .. } =
            load_lookup_options(self, memory, options_mask, options)?;
        let key = load_cache_key(memory, cache_key)?;
        Ok(self
            .in_memory_cache()
            .legacy()
            .transaction_lookup(key.as_bytes().to_vec(), &headers))
    }

    async fn transaction_lookup_async(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_key: wiggle::GuestPtr<[u8]>,
        options_mask: types::CacheLookupOptionsMask,
        options: wiggle::GuestPtr<types::CacheLookupOptions>,
    ) -> Result<types::CacheBusyHandle, Error> {
        let LookupOptions { headers, .. } =
            load_lookup_options(self, memory, options_mask, options)?;
        let key = load_cache_key(memory, cache_key)?;
        let handle = self
            .in_memory_cache()
            .legacy()
            .transaction_lookup(key.as_bytes().to_vec(), &headers);
        Ok(types::CacheBusyHandle::from(u32::from(handle)))
    }

    async fn cache_busy_handle_wait(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheBusyHandle,
    ) -> Result<types::CacheHandle, Error> {
        Ok(handle.into())
    }

    async fn transaction_insert(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
        options_mask: types::CacheWriteOptionsMask,
        options: wiggle::GuestPtr<types::CacheWriteOptions>,
    ) -> Result<types::BodyHandle, Error> {
        let (body, cache_handle) = self
            .transaction_insert_and_stream_back(memory, handle, options_mask, options)
            .await?;
        let _ = cache_handle;
        Ok(body)
    }

    async fn transaction_insert_and_stream_back(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
        options_mask: types::CacheWriteOptionsMask,
        options: wiggle::GuestPtr<types::CacheWriteOptions>,
    ) -> Result<(types::BodyHandle, types::CacheHandle), Error> {
        let guest_options = memory.read(options)?;
        let key = self
            .in_memory_cache()
            .legacy()
            .pending_key(handle)
            .ok_or(HandleError::InvalidCacheHandle(handle))?;
        let request_parts = if options_mask.contains(CacheWriteOptionsMask::REQUEST_HEADERS) {
            Some(self.request_parts(guest_options.request_headers)?)
        } else {
            None
        };
        let options = load_write_options(memory, options_mask, &guest_options)?;
        let cache_handle =
            self.in_memory_cache()
                .legacy()
                .insert(key, options_mask, &options, request_parts)?;
        Ok((self.insert_cache_body(cache_handle), cache_handle))
    }

    async fn transaction_update(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
        options_mask: types::CacheWriteOptionsMask,
        options: wiggle::GuestPtr<types::CacheWriteOptions>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("cache transaction update"))
    }

    async fn transaction_cancel(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
    ) -> Result<(), Error> {
        if self
            .in_memory_cache()
            .legacy()
            .pending_key(handle)
            .is_some()
        {
            Ok(())
        } else {
            Err(HandleError::InvalidCacheHandle(handle).into())
        }
    }

    async fn close_busy(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheBusyHandle,
    ) -> Result<(), Error> {
        Ok(())
    }

    async fn close(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
    ) -> Result<(), Error> {
        Ok(())
    }

    async fn get_state(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
    ) -> Result<types::CacheLookupState, Error> {
        let mut state = types::CacheLookupState::empty();
        if let Ok(entry) = self.in_memory_cache().legacy().entry(handle) {
            state |= types::CacheLookupState::FOUND;
            if entry.is_stale() {
                state |= types::CacheLookupState::STALE;
            }
            if entry.is_usable() {
                state |= types::CacheLookupState::USABLE;
            } else {
                state |= types::CacheLookupState::MUST_INSERT_OR_UPDATE;
            }
        } else {
            state |= types::CacheLookupState::MUST_INSERT_OR_UPDATE;
        }

        Ok(state)
    }

    async fn get_user_metadata(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
        user_metadata_out_ptr: wiggle::GuestPtr<u8>,
        user_metadata_out_len: u32,
        nwritten_out: wiggle::GuestPtr<u32>,
    ) -> Result<(), Error> {
        let md_bytes = self.in_memory_cache().legacy().entry(handle)?.user_metadata;
        let len: u32 = md_bytes
            .len()
            .try_into()
            .expect("user metadata must be shorter than u32 can indicate");
        if len > user_metadata_out_len {
            memory.write(nwritten_out, len)?;
            return Err(Error::BufferLengthError {
                buf: "user_metadata_out_ptr",
                len: "user_metadata_out_len",
            });
        }
        let user_metadata = memory
            .as_slice_mut(user_metadata_out_ptr.as_array(user_metadata_out_len))?
            .ok_or(Error::SharedMemory)?;
        user_metadata[..(len as usize)].copy_from_slice(&md_bytes);
        memory.write(nwritten_out, len)?;

        Ok(())
    }

    async fn get_body(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
        mut options_mask: types::CacheGetBodyOptionsMask,
        options: &types::CacheGetBodyOptions,
    ) -> Result<types::BodyHandle, Error> {
        let from = if options_mask.contains(types::CacheGetBodyOptionsMask::FROM) {
            Some(options.from)
        } else {
            None
        };
        options_mask &= !types::CacheGetBodyOptionsMask::FROM;
        let to = if options_mask.contains(types::CacheGetBodyOptionsMask::TO) {
            Some(options.to)
        } else {
            None
        };
        options_mask &= !types::CacheGetBodyOptionsMask::TO;

        if !options_mask.is_empty() {
            return Err(Error::NotAvailable("unknown cache get_body option"));
        }

        // We wind up re-borrowing `found` and `self.sandbox` several times here, to avoid
        // borrowing the both of them at once.
        // (It possible that inserting a body would change the address of Found, by re-shuffling
        // the AsyncItems table; we have to live by borrowck's rules.)
        //
        // We have an exclusive borrow &mut self.sandbox for the lifetime of this call,
        // so even though we're re-borrowing/repeating lookups, we know we won't run into TOCTOU.

        let mut body = self.in_memory_cache().legacy().body(handle)?;
        let from = from.unwrap_or(0) as usize;
        let to = to.map(|to| to as usize).unwrap_or(body.len());
        if from > to || from > body.len() {
            body.clear();
        } else {
            body = body[from..std::cmp::min(to, body.len())].to_vec();
        }
        Ok(self.insert_body(Body::from(body)))
    }

    async fn get_length(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
    ) -> Result<types::CacheObjectLength, Error> {
        Ok(self.in_memory_cache().legacy().body(handle)?.len() as u64)
    }

    async fn get_max_age_ns(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        Ok(self
            .in_memory_cache()
            .legacy()
            .entry(handle)?
            .max_age_ns
            .unwrap_or_default())
    }

    async fn get_stale_while_revalidate_ns(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        Ok(self
            .in_memory_cache()
            .legacy()
            .entry(handle)?
            .swr_ns
            .unwrap_or_default())
    }

    async fn get_age_ns(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        Ok(self.in_memory_cache().legacy().entry(handle)?.age_ns())
    }

    async fn get_hits(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
    ) -> Result<types::CacheHitCount, Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }
}
