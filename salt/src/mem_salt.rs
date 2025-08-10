//! This module provides a simple in-memory implementation of the SALT
//! data structure. Only used in testing.
use crate::{constant::*, traits::*, types::*, StateUpdates, TrieUpdates};
use std::{
    collections::BTreeMap,
    ops::{Bound::Included, Range, RangeInclusive},
    sync::RwLock,
};

/// [`MemSalt`] provides a simple implementation for storing
/// salt in memory. It implements trait [`StateReader`]
/// [`TrieReader`] [`TrieWriter`].
#[derive(Debug, Default)]
pub struct MemSalt {
    /// Stores the state datas that represent the blockchain state.
    pub state: RwLock<StateStorage>,
    /// Stores the node commitments in the trie.
    pub trie: RwLock<BTreeMap<NodeId, CommitmentBytes>>,
}

/// Cache for state datas.
#[derive(Debug, Default, Clone)]
pub struct StateStorage {
    /// Stores the key-value pairs
    pub kvs: BTreeMap<SaltKey, SaltValue>,
    /// Stores the `used` of bucket metadata .
    pub metas_used: BTreeMap<BucketId, u64>,
}

impl Clone for MemSalt {
    fn clone(&self) -> Self {
        Self {
            state: RwLock::new(self.state.read().expect("read lock poisoned").clone()),
            trie: RwLock::new(self.trie.read().expect("read lock poisoned").clone()),
        }
    }
}

impl MemSalt {
    /// Create a new [`MemSalt`] instance, and the initial value of all nonce is 0.
    /// FIXME: what about initial capacity? 0 as well?
    pub fn new() -> Self {
        Self {
            state: RwLock::new(StateStorage::default()),
            trie: RwLock::new(BTreeMap::new()),
        }
    }

    /// Get all key-value pairs in the state.
    pub fn get_all(&self) -> Vec<(SaltKey, SaltValue)> {
        self.state
            .read()
            .unwrap()
            .kvs
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    }

    /// Updates the entire `StateUpdates`.
    pub fn update_state(&self, updates: StateUpdates) {
        let mut state = self.state.write().unwrap();
        for (key, value) in updates.data {
            let bucket_id = key.bucket_id();
            if let Some(new_val) = value.1 {
                state.kvs.insert(key, new_val);
            } else {
                state.kvs.remove(&key);
                *state.metas_used.entry(bucket_id).or_default() -= 1;
            }
            if value.0.is_none() {
                *state.metas_used.entry(bucket_id).or_default() += 1;
            }
        }
    }

    /// Updates the entire `StateUpdates`.
    pub fn update_trie(&self, updates: TrieUpdates) {
        let mut trie = self.trie.write().unwrap();
        for (node_id, (_, new_val)) in updates.data {
            trie.insert(node_id, new_val);
        }
    }

    pub fn put_state(&self, key: SaltKey, val: SaltValue) {
        let mut state = self.state.write().unwrap();
        if !state.kvs.contains_key(&key) {
            *state.metas_used.entry(key.bucket_id()).or_default() += 1;
        }
        state.kvs.insert(key, val);
    }
}

impl StateReader for MemSalt {
    type Error = &'static str;

    /// Get bucket meta by bucket ID.
    fn get_meta(&self, bucket_id: BucketId) -> Result<BucketMeta, Self::Error> {
        let key = bucket_metadata_key(bucket_id);
        let state = self.state.read().unwrap();
        let mut meta = if let Some(v) = state.kvs.get(&key) {
            v.try_into()?
        } else {
            BucketMeta::default()
        };
        // Update the `used` field from metas_used of the state storage.
        meta.used = state
            .metas_used
            .get(&bucket_id)
            .copied()
            .unwrap_or_default();
        Ok(meta)
    }

    fn entry(&self, key: SaltKey) -> Result<Option<SaltValue>, Self::Error> {
        let rs = self.state.read().unwrap().kvs.get(&key).cloned();
        if rs.is_none() && key.is_bucket_meta_slot() {
            return Ok(Some(BucketMeta::default().into()));
        }
        Ok(rs)
    }

    fn range_bucket(
        &self,
        range: RangeInclusive<BucketId>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        Ok(self
            .state
            .read()
            .unwrap()
            .kvs
            .range((
                Included(SaltKey::from((*range.start(), 0))),
                Included(SaltKey::from((*range.end(), BUCKET_SLOT_ID_MASK))),
            ))
            .map(|(k, v)| (*k, v.clone()))
            .collect())
    }

    fn range_slot(
        &self,
        bucket_id: BucketId,
        range: RangeInclusive<u64>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        let data = if bucket_id < NUM_META_BUCKETS as BucketId {
            let start = std::cmp::min(*range.start(), MIN_BUCKET_SIZE as u64 - 1);
            let end = std::cmp::min(*range.end(), MIN_BUCKET_SIZE as u64 - 1);
            (start..=end)
                .map(|slot_id| {
                    let key = SaltKey::from((bucket_id, slot_id));
                    (
                        key,
                        self.entry(key)
                            .expect("slot should exist")
                            .expect("metadata should exist"),
                    )
                })
                .collect()
        } else {
            self.state
                .read()
                .unwrap()
                .kvs
                .range(
                    SaltKey::from((bucket_id, *range.start()))
                        ..=SaltKey::from((bucket_id, *range.end())),
                )
                .map(|(k, v)| (*k, v.clone()))
                .collect()
        };
        Ok(data)
    }
}

impl TrieReader for MemSalt {
    type Error = &'static str;

    fn get_commitment(&self, node_id: NodeId) -> Result<CommitmentBytes, Self::Error> {
        Ok(self
            .trie
            .read()
            .unwrap()
            .get(&node_id)
            .copied()
            .unwrap_or_else(|| default_commitment(node_id)))
    }

    fn get_range(
        &self,
        range: Range<NodeId>,
    ) -> Result<Vec<(NodeId, CommitmentBytes)>, Self::Error> {
        let map = self.trie.read().unwrap();
        Ok(map.range(range).map(|(k, v)| (*k, *v)).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_meta() {
        let store = MemSalt::new();
        let bucket_id = (NUM_META_BUCKETS + 400) as BucketId;
        let salt_key: SaltKey = (
            (bucket_id >> MIN_BUCKET_SIZE_BITS),
            (bucket_id % MIN_BUCKET_SIZE as BucketId) as SlotId,
        )
            .into();
        let mut meta = store.get_meta(bucket_id).unwrap();
        assert_eq!(meta, BucketMeta::default());
        let v = store.entry(salt_key).unwrap().unwrap();
        assert_eq!(meta, BucketMeta::try_from(&v).unwrap());
        meta.capacity = 1024;
        meta.used = 100;
        store
            .state
            .write()
            .unwrap()
            .metas_used
            .insert(bucket_id, meta.used);
        store.put_state(salt_key, SaltValue::from(meta));
        assert_eq!(store.get_meta(bucket_id).unwrap(), meta);
        store
            .state
            .write()
            .unwrap()
            .metas_used
            .insert(bucket_id, meta.used + 1);
        assert_eq!(
            store.get_meta(bucket_id).unwrap(),
            BucketMeta {
                used: meta.used + 1,
                ..meta
            }
        );
    }

    #[test]
    fn test_insert_new_key_value() {
        let store = MemSalt::new();

        let mut updates = StateUpdates::default();
        let bucket_id = 65537;
        let k = SaltKey::from((bucket_id, 1));
        let v = SaltValue::new(&b"accout1".to_vec(), &b"balance1".to_vec());
        updates.data.insert(k, (None, Some(v.clone())));
        store.update_state(updates.clone());

        let state = store.state.read().unwrap();
        assert_eq!(state.kvs.get(&k), Some(&v));
        assert_eq!(state.metas_used.get(&bucket_id), Some(&1));
        drop(state);

        updates.data.insert(k, (Some(v.clone()), None));
        store.update_state(updates.clone());

        let state = store.state.read().unwrap();
        assert_eq!(state.kvs.get(&k), None);
        assert_eq!(state.metas_used.get(&bucket_id), Some(&0));
    }
}
