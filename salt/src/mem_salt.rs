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
    /// Stores the key-value pairs that represent the blockchain state.
    pub state: RwLock<BTreeMap<SaltKey, SaltValue>>,
    /// Stores the node commitments in the trie.
    pub trie: RwLock<BTreeMap<NodeId, CommitmentBytes>>,
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
    pub fn new() -> Self {
        Self {
            state: RwLock::new(BTreeMap::new()),
            trie: RwLock::new(BTreeMap::new()),
        }
    }

    /// Get all key-value pairs in the state.
    pub fn get_all(&self) -> Vec<(SaltKey, SaltValue)> {
        self.state
            .read()
            .unwrap()
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    }

    /// Updates the entire `StateUpdates`.
    pub fn update_state(&self, updates: StateUpdates) {
        let mut state = self.state.write().unwrap();
        for (key, value) in updates.data {
            if let Some(new_val) = value.1 {
                state.insert(key, new_val);
            } else {
                state.remove(&key);
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
        self.state.write().unwrap().insert(key, val);
    }
}

impl StateReader for MemSalt {
    type Error = &'static str;

    fn entry(&self, key: SaltKey) -> Result<Option<SaltValue>, Self::Error> {
        let rs = self.state.read().unwrap().get(&key).cloned();
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
        range: Range<u64>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        let data = if bucket_id < NUM_META_BUCKETS as BucketId {
            assert!(range.end <= MIN_BUCKET_SIZE as NodeId);
            range
                .into_iter()
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
                .range(
                    SaltKey::from((bucket_id, range.start))..SaltKey::from((bucket_id, range.end)),
                )
                .map(|(k, v)| (*k, v.clone()))
                .collect()
        };
        Ok(data)
    }

    fn get_meta(&self, bucket_id: BucketId) -> Result<BucketMeta, Self::Error> {
        let key = meta_position(bucket_id);
        match self.entry(key)? {
            Some(ref v) => v.try_into(),
            None => Ok(BucketMeta::default()),
        }
    }
}

impl TrieReader for MemSalt {
    type Error = &'static str;

    fn bucket_capacity(&self, bucket_id: BucketId) -> Result<u64, Self::Error> {
        let meta = self.get_meta(bucket_id)?;
        Ok(meta.capacity)
    }

    fn get_commitment(&self, node_id: NodeId) -> Result<CommitmentBytes, Self::Error> {
        Ok(self
            .trie
            .read()
            .unwrap()
            .get(&node_id)
            .copied()
            .unwrap_or_else(|| {
                let level = get_node_level(node_id);
                if is_extension_node(node_id)
                    || node_id >= DEFAULT_COMMITMENT_AT_LEVEL[level].0 as NodeId
                {
                    zero_commitment()
                } else {
                    DEFAULT_COMMITMENT_AT_LEVEL[level].1
                }
            }))
    }
}
/*
impl TrieWriter for MemSalt {
    type Error = &'static str;
    fn put(&self, node_id: NodeId, commitment: CommitmentBytes) -> Result<(), Self::Error> {
        self.trie.write().unwrap().insert(node_id, commitment);
        Ok(())
    }

    fn clear(&self) -> Result<(), Self::Error> {
        self.trie.write().unwrap().clear();
        Ok(())
    }
}*/

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_meta() {
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
        store.put_state(salt_key, SaltValue::from(meta));
        assert_eq!(store.get_meta(bucket_id).unwrap(), meta);
    }
}
