//! In-memory storage backend for the SALT data structure.
//!
//! This module provides [`MemStore`], a simple in-memory storage backend that implements
//! the [`StateReader`] and [`TrieReader`] traits. It stores blockchain state data and
//! trie node commitments in memory using [`BTreeMap`] collections.
//!
//! # Note
//!
//! `MemStore` is **not** an implementation of the SALT data structure itself. It is merely
//! a storage backend that provides the underlying key-value storage required by SALT. The
//! actual SALT logic and algorithms are implemented in the `state` and `trie` modules.
//!
//! # Usage
//!
//! `MemStore` is primarily intended for:
//! - Unit testing and integration testing
//! - Development and debugging
//! - Serving as a reference implementation of the storage traits
//!
//! For production use cases requiring persistence, use a database-backed storage
//! implementation instead of this in-memory version.
//!
//! # Thread Safety
//!
//! All operations are thread-safe through the use of [`RwLock`] for interior mutability.
use crate::{constant::*, traits::*, types::*, StateUpdates, TrieUpdates};
use std::{
    collections::BTreeMap,
    ops::{Range, RangeInclusive},
    sync::RwLock,
};

/// Groups blockchain state storage and bucket usage cache together to ensure
/// atomic consistency between the two related data structures.
#[derive(Debug, Default, Clone)]
struct StateStore {
    /// The actual key-value state storage.
    ///
    /// Maps [`SaltKey`] to [`SaltValue`] pairs representing the current state
    /// of the blockchain. Keys encode bucket and slot information, while values
    /// contain the actual state data including account information, storage, etc.
    ///
    /// **Note**: Default bucket metadata entries are not stored in this map. When
    /// [`StateReader::metadata`] is called for a bucket whose metadata key is not
    /// present, it returns [`BucketMeta::default()`] values automatically.
    kvs: BTreeMap<SaltKey, SaltValue>,

    /// Cache for bucket used slot counts.
    ///
    /// Maps [`BucketId`] to the number of occupied slots in that bucket.
    /// This cache improves performance by avoiding repeated scans of bucket entries.
    ///
    /// **Interpretation**: If a bucket ID is not present in this map, it means
    /// the bucket has not been updated since the creation of this `MemStore`.
    /// For such buckets, the number of used slots is guaranteed to be zero.
    used_slots: BTreeMap<BucketId, u64>,
}

/// In-memory storage backend for SALT.
///
/// `MemStore` provides a simple, thread-safe storage backend that stores
/// state and trie data entirely in memory. It maintains two primary data stores:
///
/// 1. **State storage**: Key-value pairs representing blockchain state
/// 2. **Trie storage**: Node commitments for the Merkle trie structure
///
/// # Implemented Traits
///
/// - [`StateReader`]: Read operations on blockchain state data
/// - [`TrieReader`]: Read operations on trie node commitments
///
/// # Thread Safety
///
/// All data access is protected by [`RwLock`], allowing multiple concurrent readers
/// or a single writer per data store.
#[derive(Debug, Default)]
pub struct MemStore {
    /// Blockchain state storage.
    state: RwLock<StateStore>,

    /// Trie node commitment storage.
    ///
    /// Maps [`NodeId`] to [`CommitmentBytes`] representing cryptographic commitments
    /// for nodes in the SALT trie. These commitments are used for state proofs
    /// and verification.
    trie: RwLock<BTreeMap<NodeId, CommitmentBytes>>,
}

impl Clone for MemStore {
    fn clone(&self) -> Self {
        Self {
            state: RwLock::new(self.state.read().expect("state lock poisoned").clone()),
            trie: RwLock::new(self.trie.read().expect("trie lock poisoned").clone()),
        }
    }
}

impl MemStore {
    /// Creates a new empty `MemStore` instance.
    ///
    /// Both the state and trie stores are initialized as empty [`BTreeMap`]s.
    ///
    /// # Lazy Initialization Optimization
    ///
    /// This implementation uses lazy initialization for bucket metadata to avoid
    /// pre-populating tens of millions of metadata entries during unit testing.
    /// When [`StateReader::get_meta`] is called for a bucket whose metadata entry
    /// doesn't exist, it returns [`BucketMeta::default()`] instead of an empty value.
    ///
    /// This optimization reduces memory usage and initialization time for this
    /// in-memory implementation, but adds code complexity. Production disk-based
    /// implementations shall choose explicit initialization instead because the
    /// storage savings don't justify the added complexity.
    pub fn new() -> Self {
        Self {
            state: RwLock::new(StateStore::default()),
            trie: RwLock::new(BTreeMap::new()),
        }
    }

    /// Applies a batch of state updates.
    ///
    /// Processes all state changes in the provided [`StateUpdates`]. For each
    /// update entry:
    /// - If the new value is `Some`, the key-value pair is inserted/updated
    /// - If the new value is `None`, the key is removed from the state
    ///
    /// This method also updates the bucket used slots cache to reflect changes
    /// in bucket occupancy.
    ///
    /// # Arguments
    ///
    /// * `updates` - Batch of state changes to apply
    pub fn update_state(&self, updates: StateUpdates) {
        let mut state = self.state.write().unwrap();

        for (key, (old_value, new_value)) in updates.data {
            // Update used_slot information for data buckets only
            if !key.is_in_meta_bucket() {
                let bucket_id = key.bucket_id();
                match (old_value.is_some(), new_value.is_some()) {
                    (false, true) => *state.used_slots.entry(bucket_id).or_insert(0) += 1,
                    (true, false) => {
                        if let Some(count) = state.used_slots.get_mut(&bucket_id) {
                            *count = count.saturating_sub(1);
                        }
                    }
                    _ => {} // No change in count (update or no-op)
                }
            }

            // Apply the state change
            match new_value {
                Some(new_val) => state.kvs.insert(key, new_val),
                None => state.kvs.remove(&key),
            };
        }
    }

    /// Applies a batch of trie updates.
    ///
    /// Processes all trie node commitment changes in the provided [`TrieUpdates`].
    /// Each update contains a node ID and its new commitment value, which replaces
    /// any existing commitment for that node.
    ///
    /// # Arguments
    ///
    /// * `updates` - Batch of trie node commitment changes to apply
    pub fn update_trie(&self, updates: TrieUpdates) {
        let mut trie = self.trie.write().unwrap();
        for (node_id, (_, new_val)) in updates.data {
            trie.insert(node_id, new_val);
        }
    }
}

impl StateReader for MemStore {
    /// Error type for state read operations.
    ///
    /// Uses static string references for simplicity in this in-memory implementation.
    type Error = &'static str;

    fn value(&self, key: SaltKey) -> Result<Option<SaltValue>, Self::Error> {
        let val = self.state.read().unwrap().kvs.get(&key).cloned();
        Ok(val)
    }

    fn entries(
        &self,
        range: RangeInclusive<SaltKey>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        Ok(self
            .state
            .read()
            .unwrap()
            .kvs
            .range(range)
            .map(|(k, v)| (*k, v.clone()))
            .collect())
    }

    fn bucket_used_slots(&self, bucket_id: BucketId) -> Result<u64, Self::Error> {
        // Return the cached count, defaulting to 0 for buckets that haven't been accessed
        Ok(*self
            .state
            .read()
            .unwrap()
            .used_slots
            .get(&bucket_id)
            .unwrap_or(&0))
    }
}

impl TrieReader for MemStore {
    /// Error type for trie read operations.
    ///
    /// Uses static string references for simplicity in this in-memory implementation.
    type Error = &'static str;

    fn commitment(&self, node_id: NodeId) -> Result<CommitmentBytes, Self::Error> {
        Ok(self
            .trie
            .read()
            .unwrap()
            .get(&node_id)
            .copied()
            .unwrap_or_else(|| default_commitment(node_id)))
    }

    fn node_entries(
        &self,
        range: Range<NodeId>,
    ) -> Result<Vec<(NodeId, CommitmentBytes)>, Self::Error> {
        Ok(self
            .trie
            .read()
            .unwrap()
            .range(range)
            .map(|(k, v)| (*k, *v))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests bucket metadata retrieval and storage.
    ///
    /// Verifies that:
    /// - Default metadata is returned for unset buckets
    /// - Metadata can be stored and retrieved correctly
    /// - The metadata slot key mapping works as expected
    #[test]
    fn get_meta() {
        let store = MemStore::new();
        let bucket_id = (NUM_META_BUCKETS + 400) as BucketId;
        let salt_key: SaltKey = (
            (bucket_id >> MIN_BUCKET_SIZE_BITS),
            (bucket_id % MIN_BUCKET_SIZE as BucketId) as SlotId,
        )
            .into();
        let mut meta = store.metadata(bucket_id).unwrap();
        // The metadata() method now populates the used field
        let expected_meta = BucketMeta {
            used: Some(0), // populated by metadata()
            ..BucketMeta::default()
        };
        assert_eq!(meta, expected_meta);
        assert!(store.value(salt_key).unwrap().is_none());
        meta.capacity = 1024;
        let updates = StateUpdates {
            data: [(salt_key, (None, Some(SaltValue::from(meta))))].into(),
        };
        store.update_state(updates);
        // After update, used field should still be populated correctly
        let updated_meta = store.metadata(bucket_id).unwrap();
        assert_eq!(updated_meta.nonce, meta.nonce);
        assert_eq!(updated_meta.capacity, meta.capacity);
        assert_eq!(updated_meta.used, Some(0)); // Still 0 since we didn't add any entries
    }

    // FIXME: no tests for bucket expansion??
}
