//! Define traits for storing salt state and salt trie.
use crate::{
    constant::{default_commitment, zero_commitment, STARTING_NODE_ID, TRIE_LEVELS, TRIE_WIDTH},
    trie::trie::get_child_node,
    types::{
        bucket_metadata_key, get_bfs_level, is_subtree_node, BucketMeta, CommitmentBytes, NodeId,
        SaltKey, SaltValue,
    },
    BucketId,
};
use std::{
    fmt::Debug,
    ops::{Range, RangeInclusive},
};

/// This trait provides functionality for reading the entries of SALT buckets.
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
    fn entry(&self, key: SaltKey) -> Result<Option<SaltValue>, Self::Error>;

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

    /// Retrieves metadata for a specific bucket.
    ///
    /// Bucket metadata contains essential information about a bucket's configuration
    /// and usage, including:
    /// - `nonce`: Used for SHI hash table operations
    /// - `capacity`: Total number of slots in the bucket
    /// - `used`: Number of occupied slots
    ///
    /// # Behavior
    ///
    /// This method looks up the bucket's metadata using a special metadata key
    /// derived from the bucket ID. If no metadata entry exists (common for
    /// uninitialized buckets), it returns a default [`BucketMeta`] with:
    /// - `nonce`: 0
    /// - `capacity`: MIN_BUCKET_SIZE (256)
    /// - `used`: 0
    ///
    /// # Arguments
    ///
    /// * `bucket_id` - The ID of the bucket whose metadata to retrieve
    ///
    /// # Returns
    ///
    /// - `Ok(BucketMeta)` - The bucket's metadata or default values if not found
    /// - `Err(_)` - If there's an error reading from storage
    ///
    /// # Panics
    ///
    /// Panics if the stored metadata value cannot be decoded into a valid
    /// [`BucketMeta`] structure. This indicates data corruption.
    fn metadata(&self, bucket_id: BucketId) -> Result<BucketMeta, Self::Error> {
        let key = bucket_metadata_key(bucket_id);
        Ok(match self.entry(key)? {
            Some(ref v) => v
                .try_into()
                .expect("Failed to decode bucket metadata: stored value is corrupted"),
            // Return default metadata for uninitialized buckets
            None => BucketMeta::default(),
        })
    }
}

/// This trait provides functionality for reading commitments from trie nodes.
pub trait TrieReader: Sync {
    /// Custom trait's error type.
    type Error: Debug + Send;

    /// Get node commitment by `node_id` from store.
    fn commitment(&self, node_id: NodeId) -> Result<CommitmentBytes, Self::Error>;

    /// Get node commitments by `range` from store.
    fn commitments(
        &self,
        range: Range<NodeId>,
    ) -> Result<Vec<(NodeId, CommitmentBytes)>, Self::Error>;

    /// Retrieves child nodes based on the node ID
    fn children(&self, node_id: NodeId) -> Result<Vec<CommitmentBytes>, Self::Error> {
        let zero = zero_commitment();
        let child_start = get_child_node(&node_id, 0);
        let mut children = vec![zero; TRIE_WIDTH];
        let cache = self.commitments(child_start as NodeId..child_start + TRIE_WIDTH as NodeId)?;
        // Fill in actual values where they exist
        for (k, v) in cache {
            children[k as usize - child_start as usize] = v;
        }

        // Because the trie did not store the default value when init,
        // so meta nodes needs to update the default commitment.
        let child_level = get_bfs_level(node_id) + 1;
        if !is_subtree_node(node_id)
            && child_level < TRIE_LEVELS
            && node_id < STARTING_NODE_ID[child_level] as NodeId
        {
            for i in child_start..child_start + TRIE_WIDTH as NodeId {
                let j = (i - child_start) as usize;
                if children[j] == zero {
                    children[j] = default_commitment(i);
                }
            }
        }

        Ok(children)
    }
}
