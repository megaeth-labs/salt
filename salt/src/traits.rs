//! Core traits for SALT state and trie storage.
use crate::{
    constant::BUCKET_SLOT_ID_MASK,
    types::{is_valid_data_bucket, BucketMeta, CommitmentBytes, NodeId, SaltKey, SaltValue},
    BucketId,
};
use std::{
    fmt::Debug,
    ops::{Range, RangeInclusive},
};

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
pub trait StateReader: Debug + Send + Sync {
    /// Custom trait's error type.
    type Error: Debug + Send;

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
pub trait TrieReader: Sync {
    /// Custom trait's error type.
    type Error: Debug + Send;

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
