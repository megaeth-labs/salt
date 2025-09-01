//! Core traits for SALT state and trie storage.
use crate::trie::node_utils::subtree_root_level;
use crate::{
    constant::{BUCKET_SLOT_ID_MASK, MAX_SUBTREE_LEVELS, NUM_META_BUCKETS},
    types::{is_valid_data_bucket, BucketMeta, CommitmentBytes, NodeId, SaltKey, SaltValue},
    BucketId,
};
use core::error::Error;
use std::ops::{Range, RangeInclusive};

/// Provides read-only access to SALT state storage.
///
/// SALT organizes state data into buckets (0..16M), where the first 65K are metadata
/// buckets storing configuration for data buckets. Each bucket contains slots addressed
/// by [`SaltKey`] (bucket_id, slot_id) pairs.
///
/// This trait defines a consistent interface for reading state data. Low-level methods
/// like `value()` returns `None` for missing keys without interpretation. Higher-level
/// methods like `metadata()` provide semantic meaning - returning default values where
/// appropriate (e.g., default bucket metadata for buckets that haven't been resized or
/// rehashed).
///
/// See [`MemStore`](crate::MemStore) for a reference in-memory implementation.
#[auto_impl::auto_impl(&, Arc)]
pub trait StateReader: Send + Sync {
    /// Custom trait's error type.
    type Error: Error + Send + Sync + 'static;

    /// Retrieves a state value by key.
    ///
    /// Returns the state value associated with the given key, or `None` if the key
    /// doesn't exist. This method does not return default values for missing keys;
    /// it's the responsibility of higher-level methods (e.g., [`metadata`]) to
    /// interpret the meaning of missing keys.
    ///
    /// # Arguments
    ///
    /// * `key` - The state key to look up
    ///
    /// # Returns
    ///
    /// - `Ok(Some(value))` if the key exists
    /// - `Ok(None)` if the key doesn't exist
    /// - `Err(_)` on storage errors
    fn value(&self, key: SaltKey) -> Result<Option<SaltValue>, Self::Error>;

    /// Retrieves all non-empty entries within the specified range of SaltKeys.
    ///
    /// # Arguments
    ///
    /// * `range` - Inclusive range of SaltKeys to query
    ///
    /// # Returns
    ///
    /// Vector of all matching key-value pairs, ordered by key.
    fn entries(
        &self,
        range: RangeInclusive<SaltKey>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error>;

    /// Retrieves metadata for a specific data bucket.
    ///
    /// Bucket metadata contains essential information about a bucket's configuration
    /// and usage, including:
    /// - `nonce`: Used for SHI hash table operations
    /// - `capacity`: Total number of slots in the bucket
    /// - `used`: Number of occupied slots
    ///
    /// # Behavior
    ///
    /// This method looks up the bucket's metadata using the bucket ID. If no metadata
    /// entry exists, it uses default values for `nonce` (0) and `capacity` (MIN_BUCKET_SIZE).
    /// Regardless of whether metadata is stored or default, the `used` field is **always**
    /// populated with the actual number of occupied slots.
    ///
    /// # Arguments
    ///
    /// * `bucket_id` - The ID of the data bucket whose metadata to retrieve. Must be
    ///   a valid data bucket ID (NUM_META_BUCKETS <= bucket_id < NUM_BUCKETS).
    ///
    /// # Returns
    ///
    /// - `Ok(BucketMeta)` - The bucket's metadata with computed `used` field
    /// - `Err(_)` - If there's an error reading from storage
    ///
    /// # Panics
    ///
    /// - Panics if `bucket_id` refers to a meta bucket or is invalid (>= NUM_BUCKETS)
    /// - Panics if the stored metadata value cannot be decoded into a valid
    ///   [`BucketMeta`] structure (indicates data corruption)
    fn metadata(&self, bucket_id: BucketId) -> Result<BucketMeta, Self::Error>;

    /// Returns the number of occupied slots in a data bucket.
    ///
    /// This method is intended for data buckets only. While meta bucket IDs are
    /// accepted for completeness, they will always return 0 since meta buckets
    /// don't store regular key-value data that would be counted as "used slots".
    ///
    /// # Default Implementation
    ///
    /// The default implementation scans all entries in the bucket and counts
    /// non-empty slots. Implementations should override this with a more
    /// efficient approach (e.g., caching the count in memory).
    ///
    /// # Arguments
    ///
    /// * `bucket_id` - The ID of the bucket whose occupied slots to count
    ///
    /// # Returns
    ///
    /// - `Ok(count)` - The number of occupied slots in the bucket (0 for meta buckets)
    /// - `Err(_)` - If there's an error reading from storage
    fn bucket_used_slots(&self, bucket_id: BucketId) -> Result<u64, Self::Error> {
        if !is_valid_data_bucket(bucket_id) {
            return Ok(0);
        }

        let start_key = SaltKey::from((bucket_id, 0u64));
        let end_key = SaltKey::from((bucket_id, BUCKET_SLOT_ID_MASK));
        let entries = self.entries(start_key..=end_key)?;
        Ok(entries.len() as u64)
    }

    /// Provides a fast path lookup from plain keys to salt keys.
    ///
    /// This method is essential for enabling [`EphemeralSaltState`] to work with
    /// storage backends that only have partial state information, such as block
    /// witnesses or proofs. While these backends may not have access to the complete
    /// state, they can maintain explicit mappings between plain keys and their
    /// corresponding salt keys to facilitate the SHI hash table lookup algorithm.
    ///
    /// **Important**: This method cannot be used to conclude that a key doesn't exist.
    /// Partial state storage only knows about a specific subset of keys, so returning
    /// an error simply means "this key is not in my known mappings", not "this key
    /// doesn't exist globally".
    ///
    /// # Arguments
    /// * `plain_key` - The plain key to look up
    ///
    /// # Returns
    /// - `Ok(salt_key)` - The plain key exists and maps to this salt key
    /// - `Err(_)` - The key is not in the partial state's known mappings, or the
    ///   operation is not supported. This does NOT mean the key doesn't exist globally.
    ///
    /// # Implementation Notes
    /// - Partial state backends MUST implement this to provide known mappings.
    /// - Full state backends MAY return an error, or optionally implement this
    ///   as a performance optimization.
    fn plain_value_fast(&self, plain_key: &[u8]) -> Result<SaltKey, Self::Error>;

    /// Computes the number of levels in a bucket's subtree.
    ///
    /// For SALT's two-tier architecture, each bucket can expand into a dynamic subtree
    /// when its capacity exceeds the minimum bucket size. This method returns the number
    /// of levels in the subtree based on the bucket's current capacity.
    ///
    /// # Subtree Level Calculation
    ///
    /// - **Meta buckets** (0-65535): Always return 1 level (no expansion)
    /// - **Data buckets**: Number of levels depends on capacity:
    ///   - Capacity ≤ 256: 1 level (no internal nodes)
    ///   - Capacity ≤ 65,536: 2 levels (1 internal + 1 leaf)
    ///   - Capacity ≤ 16,777,216: 3 levels (2 internal + 1 leaf)
    ///   - And so on, up to 5 levels maximum
    ///
    /// # Arguments
    ///
    /// * `bucket_id` - The ID of the bucket whose subtree levels to compute
    ///
    /// # Returns
    ///
    /// - `Ok(levels)` - Number of levels in the subtree (1-5)
    /// - `Err(_)` - If there's an error reading bucket metadata
    ///
    /// # Default Implementation
    ///
    /// The default implementation reads bucket metadata to get capacity and uses
    /// the `subtree_root_level` helper to calculate the number of levels.
    fn get_subtree_levels(&self, bucket_id: BucketId) -> Result<usize, Self::Error> {
        // Meta buckets always have 1 level (no expansion)
        if bucket_id < NUM_META_BUCKETS as u32 {
            return Ok(1);
        }

        // Get bucket capacity from metadata
        let meta = self.metadata(bucket_id)?;
        let capacity = meta.capacity;

        // Calculate subtree levels based on capacity
        // subtree_root_level returns which level is the root (0-4)
        // We need to return the number of levels (1-5)
        let root_level = subtree_root_level(capacity);
        Ok(MAX_SUBTREE_LEVELS - root_level)
    }
}

/// Provides read-only access to SALT trie commitments.
///
/// SALT uses a two-tier architecture to authenticate state data:
/// - **Main trie**: A static 4-level, 256-ary complete trie where each leaf represents
///   a bucket (first 65K are metadata buckets, remainder are data buckets)
/// - **Bucket subtrees**: Dynamic 256-ary complete trees that extend from data bucket
///   leaves, growing as buckets expand beyond their initial capacity
///
/// This trait provides a uniform interface for reading commitments from both tiers.
/// Methods return deterministic default commitments for nodes that haven't been
/// explicitly stored, ensuring the trie behaves as if fully materialized.
///
/// See [`MemStore`](crate::MemStore) for a reference in-memory implementation.
#[auto_impl::auto_impl(&, Arc)]
pub trait TrieReader: Sync {
    /// Custom trait's error type.
    type Error: Error + Send + Sync + 'static;

    /// Retrieves the commitment for a specific trie node.
    ///
    /// **Note**: This method assumes the NodeId is valid and does no error checking.
    /// Invalid NodeIds will return a default commitment rather than an error.
    ///
    /// If no commitment has been explicitly stored, returns a default commitment
    /// pre-computed from the node ID.
    ///
    /// # Arguments
    /// * `node_id` - The unique identifier for the trie node
    ///
    /// # Returns
    /// The 64-byte cryptographic commitment for the node
    fn commitment(&self, node_id: NodeId) -> Result<CommitmentBytes, Self::Error>;

    /// Retrieves commitments for a range of trie nodes.
    ///
    /// Returns only explicitly stored commitments within the range. Nodes with
    /// default commitments are not included in the results.
    ///
    /// # Arguments
    /// * `range` - Half-open range [start, end) of node IDs to query
    ///
    /// # Returns
    /// Vector of (node_id, commitment) pairs ordered by node ID
    fn node_entries(
        &self,
        range: Range<NodeId>,
    ) -> Result<Vec<(NodeId, CommitmentBytes)>, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{constant::NUM_META_BUCKETS, mem_store::MemStore, types::BucketMeta};

    #[test]
    fn test_get_subtree_levels_meta_buckets() {
        let store = MemStore::new();

        // Test meta buckets always return 1 level
        for bucket_id in [0u32, 1000u32, (NUM_META_BUCKETS - 1) as u32] {
            let levels = store.get_subtree_levels(bucket_id).unwrap();
            assert_eq!(levels, 1, "Meta bucket {} should have 1 level", bucket_id);
        }
    }

    #[test]
    fn test_get_subtree_levels_data_buckets() {
        use crate::{bucket_metadata_key, state::updates::StateUpdates, types::SaltValue};

        let store = MemStore::new();

        // Test cases: (capacity, expected_levels)
        let cases = [
            (1, 1),          // Single slot → 1 level
            (256, 1),        // Exactly MIN_BUCKET_SIZE → 1 level
            (257, 2),        // Just over MIN_BUCKET_SIZE → 2 levels
            (65536, 2),      // 256^2 slots → 2 levels
            (65537, 3),      // Just over 256^2 → 3 levels
            (16777216, 3),   // 256^3 slots → 3 levels
            (16777217, 4),   // Just over 256^3 → 4 levels
            (4294967296, 4), // 256^4 slots → 4 levels
            (4294967297, 5), // Just over 256^4 → 5 levels (max)
        ];

        for (capacity, expected_levels) in cases {
            // Create a data bucket with specific capacity
            let bucket_id = NUM_META_BUCKETS as u32;

            // Set up bucket metadata with the desired capacity
            let meta = BucketMeta {
                nonce: 0,
                capacity,
                used: Some(0),
            };

            // Create state updates to store the metadata
            let mut updates = StateUpdates::default();
            let meta_key = bucket_metadata_key(bucket_id);
            let meta_value = SaltValue::try_from(meta).unwrap();
            updates.add(meta_key, None, Some(meta_value));

            // Update the store with this metadata
            store.update_state(updates);

            // Test the get_subtree_levels method
            let levels = store.get_subtree_levels(bucket_id).unwrap();
            assert_eq!(
                levels, expected_levels,
                "Bucket with capacity={} should have {} levels",
                capacity, expected_levels
            );
        }
    }

    #[test]
    fn test_get_subtree_levels_default_capacity() {
        let store = MemStore::new();
        let bucket_id = (NUM_META_BUCKETS + 1000) as u32;

        // For buckets without explicit metadata, should use default capacity (MIN_BUCKET_SIZE)
        let levels = store.get_subtree_levels(bucket_id).unwrap();
        assert_eq!(
            levels, 1,
            "Bucket with default capacity should have 1 level"
        );
    }
}
