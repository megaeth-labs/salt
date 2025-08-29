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
/// 2. **Trie storage**: Node commitments for the SALT trie structure
///
/// # Canonical State Structure
///
/// `MemStore` uses lazy initialization for bucket metadata, which defines the
/// canonical structure of the SALT state. Only buckets with explicitly modified
/// metadata store actual entries; all others are treated as having default metadata
/// values when accessed through [`StateReader::metadata`].
///
/// This approach ensures:
/// - **Deterministic state representation**: State roots are computed over this
///   canonical minimal representation
/// - **Consistent behavior**: Empty state always produces the same state root
/// - **Storage efficiency**: Only non-default metadata consumes storage space
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
        for (node_id, (_, new_val)) in updates {
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

    fn metadata(&self, bucket_id: BucketId) -> Result<BucketMeta, Self::Error> {
        let key = bucket_metadata_key(bucket_id);
        let state = self.state.read().unwrap();

        let mut meta = match state.kvs.get(&key) {
            Some(v) => v.try_into()?,
            None => BucketMeta::default(),
        };
        meta.used = Some(*state.used_slots.get(&bucket_id).unwrap_or(&0));
        Ok(meta)
    }

    fn bucket_used_slots(&self, bucket_id: BucketId) -> Result<u64, Self::Error> {
        if !is_valid_data_bucket(bucket_id) {
            return Ok(0);
        }

        let state = self.state.read().unwrap();
        Ok(*state.used_slots.get(&bucket_id).unwrap_or(&0))
    }

    fn plain_value_fast(&self, _plain_key: &[u8]) -> Result<SaltKey, Self::Error> {
        Err("plain_value_fast not supported for MemStore")
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

    /// Tests the lazy metadata initialization optimization.
    ///
    /// Verifies that:
    /// - Metadata entries are not pre-populated in storage
    /// - metadata() returns default values for unset buckets
    /// - The used field is always computed and populated correctly
    /// - No actual storage entry is created for default metadata
    #[test]
    fn test_lazy_metadata_initialization() {
        let store = MemStore::new();
        let bucket_id = NUM_META_BUCKETS as BucketId + 100;

        // Verify metadata is not pre-populated
        assert!(store.entries(METADATA_KEYS_RANGE).unwrap().is_empty());

        // metadata() should return default values with used field populated
        let meta = store.metadata(bucket_id).unwrap();
        assert_eq!(meta.nonce, 0);
        assert_eq!(meta.capacity, MIN_BUCKET_SIZE as u64);
        assert_eq!(meta.used, Some(0));

        // Still no actual metadata entry stored
        assert!(store.entries(METADATA_KEYS_RANGE).unwrap().is_empty());
    }

    /// Tests the used_slots cache consistency across all state operations.
    ///
    /// Verifies that:
    /// - Insert operations increment the count: (false, true) -> +1
    /// - Update operations don't change the count: (true, true) -> no change
    /// - Delete operations decrement the count: (true, false) -> -1
    /// - Meta bucket operations don't affect the cache
    /// - Cache correctly handles buckets that haven't been accessed (returns 0)
    #[test]
    fn test_used_slots_cache_consistency() {
        let store = MemStore::new();
        let bucket_id = NUM_META_BUCKETS as BucketId + 42;
        let key1 = SaltKey::from((bucket_id, 10));
        let key2 = SaltKey::from((bucket_id, 20));
        let val = SaltValue::new(&[1; 32], &[2; 32]);

        // Initially, bucket should have 0 used slots
        assert_eq!(store.bucket_used_slots(bucket_id).unwrap(), 0);

        // Insert: (false, true) -> count should increase
        let updates = StateUpdates {
            data: [(key1, (None, Some(val.clone())))].into(),
        };
        store.update_state(updates);
        assert_eq!(store.bucket_used_slots(bucket_id).unwrap(), 1);

        // Insert another: count should increase again
        let updates = StateUpdates {
            data: [(key2, (None, Some(val.clone())))].into(),
        };
        store.update_state(updates);
        assert_eq!(store.bucket_used_slots(bucket_id).unwrap(), 2);

        // Update existing: (true, true) -> count should not change
        let updates = StateUpdates {
            data: [(key1, (Some(val.clone()), Some(val.clone())))].into(),
        };
        store.update_state(updates);
        assert_eq!(store.bucket_used_slots(bucket_id).unwrap(), 2);

        // Delete: (true, false) -> count should decrease
        let updates = StateUpdates {
            data: [(key1, (Some(val.clone()), None))].into(),
        };
        store.update_state(updates);
        assert_eq!(store.bucket_used_slots(bucket_id).unwrap(), 1);

        // Meta bucket keys should not affect used_slots
        let meta_key = SaltKey::from((1000, 0)); // Meta bucket 1000
        let updates = StateUpdates {
            data: [(meta_key, (None, Some(val.clone())))].into(),
        };
        store.update_state(updates);
        // Should not have created entry for bucket 1000 in used_slots
        assert_eq!(store.entries(METADATA_KEYS_RANGE).unwrap().len(), 1);
        assert_eq!(store.bucket_used_slots(1000).unwrap(), 0);
    }

    /// Tests metadata storage and retrieval with key mapping.
    ///
    /// Verifies that:
    /// - Custom metadata can be stored and retrieved correctly
    /// - The bucket_metadata_key mapping works (bucket_id / 256, bucket_id % 256)
    /// - The used field is always computed from actual data, not stored value
    /// - Metadata storage uses the standard SaltValue serialization
    #[test]
    fn test_metadata_storage_and_retrieval() {
        let store = MemStore::new();
        let bucket_id = NUM_META_BUCKETS as BucketId + 256; // Maps to meta bucket 257, slot 0

        // Store custom metadata
        let custom_meta = BucketMeta {
            nonce: 42,
            capacity: 1024,
            used: None, // Should be ignored when storing
        };
        let metadata_key = bucket_metadata_key(bucket_id);
        let updates = StateUpdates {
            data: [(metadata_key, (None, Some(SaltValue::from(custom_meta))))].into(),
        };
        store.update_state(updates);

        // Add some actual data to the bucket
        let data_key = SaltKey::from((bucket_id, 0));
        let val = SaltValue::new(&[1; 32], &[2; 32]);
        let updates = StateUpdates {
            data: [(data_key, (None, Some(val)))].into(),
        };
        store.update_state(updates);

        // Retrieve metadata - should have custom values with computed used field
        let retrieved = store.metadata(bucket_id).unwrap();
        assert_eq!(retrieved.nonce, 42);
        assert_eq!(retrieved.capacity, 1024);
        assert_eq!(retrieved.used, Some(1)); // Computed from actual data

        // Verify the key mapping
        assert_eq!(metadata_key.bucket_id(), 257);
        assert_eq!(metadata_key.slot_id(), 0);
    }

    /// Tests the different behavior between meta buckets and data buckets.
    ///
    /// Verifies that:
    /// - Meta buckets always return 0 for bucket_used_slots
    /// - Data buckets return actual slot counts
    /// - Boundary cases around NUM_META_BUCKETS work correctly
    /// - Invalid bucket IDs (>= NUM_BUCKETS) return 0
    #[test]
    fn test_meta_vs_data_bucket_behavior() {
        let store = MemStore::new();

        // Test boundary case: last meta bucket
        let last_meta = NUM_META_BUCKETS as BucketId - 1;
        assert_eq!(store.bucket_used_slots(last_meta).unwrap(), 0);

        // Test boundary case: first data bucket
        let first_data = NUM_META_BUCKETS as BucketId;
        assert_eq!(store.bucket_used_slots(first_data).unwrap(), 0);

        // Add data to first data bucket
        let key = SaltKey::from((first_data, 0));
        let val = SaltValue::new(&[1; 32], &[2; 32]);
        let updates = StateUpdates {
            data: [(key, (None, Some(val)))].into(),
        };
        store.update_state(updates);

        // Data bucket should show count
        assert_eq!(store.bucket_used_slots(first_data).unwrap(), 1);
        // Meta bucket should still return 0
        assert_eq!(store.bucket_used_slots(last_meta).unwrap(), 0);

        // Test invalid bucket (>= NUM_BUCKETS)
        assert_eq!(store.bucket_used_slots(NUM_BUCKETS as BucketId).unwrap(), 0);
    }

    /// Tests atomic consistency of batch state updates.
    ///
    /// Verifies that:
    /// - Batch updates maintain consistency between kvs and used_slots
    /// - Complex multi-operation batches work correctly
    /// - All state change types work in combination: insert, update, delete, no-op
    #[test]
    fn test_state_updates_atomicity() {
        let store = MemStore::new();
        let bucket_id = NUM_META_BUCKETS as BucketId + 500;
        let key1 = SaltKey::from((bucket_id, 1));
        let key2 = SaltKey::from((bucket_id, 2));
        let key3 = SaltKey::from((bucket_id, 3));
        let val = SaltValue::new(&[1; 32], &[2; 32]);

        // Batch update with multiple operations
        let updates = StateUpdates {
            data: [
                (key1, (None, Some(val.clone()))), // Insert
                (key2, (None, Some(val.clone()))), // Insert
                (key3, (None, None)),              // No-op (delete non-existent)
            ]
            .into(),
        };
        store.update_state(updates);

        // Check state consistency
        assert!(store.value(key1).unwrap().is_some());
        assert!(store.value(key2).unwrap().is_some());
        assert!(store.value(key3).unwrap().is_none());
        assert_eq!(store.bucket_used_slots(bucket_id).unwrap(), 2);

        // Complex batch with all operation types
        let updates = StateUpdates {
            data: [
                (key1, (Some(val.clone()), Some(val.clone()))), // Update
                (key2, (Some(val.clone()), None)),              // Delete
                (key3, (None, Some(val.clone()))),              // Insert
            ]
            .into(),
        };
        store.update_state(updates);

        // Final state check
        assert!(store.value(key1).unwrap().is_some());
        assert!(store.value(key2).unwrap().is_none());
        assert!(store.value(key3).unwrap().is_some());
        assert_eq!(store.bucket_used_slots(bucket_id).unwrap(), 2);
    }

    /// Tests trie storage operations.
    ///
    /// Verifies that:
    /// - Default commitments are returned for unset nodes
    /// - Custom commitments can be stored and retrieved
    /// - node_entries returns correct ranges of stored commitments
    /// - Empty ranges return empty results
    /// - TrieUpdates batch operations work correctly
    #[test]
    fn test_trie_operations() {
        let store = MemStore::new();

        // Test default commitment
        let node_id = 42;
        assert_eq!(
            store.commitment(node_id).unwrap(),
            default_commitment(node_id)
        );

        // Store custom commitment
        let custom_commitment = [3u8; 64];
        let updates = vec![(node_id, ([0u8; 64], custom_commitment))];
        store.update_trie(updates);

        // Retrieve custom commitment
        assert_eq!(store.commitment(node_id).unwrap(), custom_commitment);

        // Test node_entries
        let entries = store.node_entries(40..45).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], (node_id, custom_commitment));

        // Empty range should return empty vec
        assert!(store.node_entries(100..200).unwrap().is_empty());
    }
}
