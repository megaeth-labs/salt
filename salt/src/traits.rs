//! Define traits for storing salt state and salt trie.

use crate::{
    state::updates::SaltDeltas,
    types::{BucketMeta, CommitmentBytes, NodeId, SaltKey, SaltValue},
    BucketId, StateUpdates, TrieUpdates,
};
use alloy_primitives::BlockNumber;
use std::{
    fmt::Debug,
    ops::{Range, RangeInclusive},
};

/// This trait provides functionality for reading the nonces and sizes of SALT buckets.
pub trait BucketMetadataReader {
    /// Custom trait's error type.
    type Error: Send + Debug;
    /// Get bucket meta by bucket ID.
    fn get_meta(&self, bucket_id: BucketId) -> Result<BucketMeta, Self::Error>;
}

/// This trait provides functionality for reading the entries of SALT buckets.
pub trait StateReader: BucketMetadataReader + Send + Sync {
    /// Get slot value by bucket_id and slot_id. Includes SaltValue that stores bucket metas or
    /// plain value.
    fn entry(
        &self,
        key: SaltKey,
    ) -> Result<Option<SaltValue>, <Self as BucketMetadataReader>::Error>;

    /// Retrieves all non-empty entries within the specified range of buckets.
    /// Only includes SaltValue that stores plain value.
    fn range_bucket(
        &self,
        range: RangeInclusive<BucketId>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error>;

    /// Retrieves all non-empty entries within the specified range of slots.
    /// Includes SaltValue that stores bucket metas or plain value.
    fn range_slot(
        &self,
        _bucket_id: BucketId,
        _range: Range<u64>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        Ok(vec![])
    }
}

/// This trait provides functionality for writing the entries of SALT buckets.
pub trait StateWriter: BucketMetadataReader {
    /// Update the bucket entry specified by the given SALT key.
    fn put(
        &self,
        key: SaltKey,
        value: SaltValue,
    ) -> Result<(), <Self as BucketMetadataReader>::Error>;
    /// Update the metadata of the specified bucket.
    fn put_meta(
        &self,
        id: BucketId,
        meta: BucketMeta,
    ) -> Result<(), <Self as BucketMetadataReader>::Error>;
    /// Delete the bucket entry specified by the given SALT key.
    fn delete(&self, key: SaltKey) -> Result<bool, <Self as BucketMetadataReader>::Error>;
    /// Updates the entire `StateUpdates`.
    fn update(&self, updates: StateUpdates) -> Result<(), <Self as BucketMetadataReader>::Error> {
        for (key, value) in updates.data {
            if let Some(new_val) = value.1 {
                self.put(key, new_val)?;
            } else {
                self.delete(key)?;
            }
        }
        Ok(())
    }

    /// Clear all entries.
    fn clear(&self) -> Result<(), <Self as BucketMetadataReader>::Error>;

    /// Applies a given set of SALT value deltas to the current state.
    /// This batch interface allows more optimized implementations than
    /// `put` and `delete`.
    fn apply_changesets(
        &self,
        salt_deltas: SaltDeltas,
    ) -> Result<(), <Self as BucketMetadataReader>::Error>;
}

/// This trait provides functionality for reading commitments from trie nodes.
pub trait TrieReader: Sync {
    /// Custom trait's error type.
    type Error: Send + Debug;
    /// Get Bucket Capacity from store.
    fn bucket_capacity(&self, bucket_id: BucketId) -> Result<u64, Self::Error>;
    /// Get node by node_id from store.
    fn get(&self, node_id: NodeId) -> Result<CommitmentBytes, Self::Error>;
    /// Retrieves child nodes based on the node ID
    fn children(&self, node_id: NodeId) -> Result<Vec<CommitmentBytes>, Self::Error>;
}

/// This trait provides functionality for updating the trie nodes.
pub trait TrieWriter {
    /// Custom trait's error type.
    type Error: Debug;
    /// Set the commitment of the given trie node.
    fn put(&self, node_id: NodeId, commitment: CommitmentBytes) -> Result<(), Self::Error>;
    /// Remove all commitment data.
    fn clear(&self) -> Result<(), Self::Error>;
    /// Updates the entire `TrieUpdates`.
    fn update(&self, updates: TrieUpdates) -> Result<(), Self::Error> {
        updates.data.into_iter().try_for_each(|(node_id, (_old, new))| self.put(node_id, new))
    }
}

/// This trait provides the functionality for reading the
/// [`SaltChangeSets`] table.
pub trait SaltChangeReader {
    /// Custom trait's error type.
    type Error: Debug;
    /// Read the change sets of the given block.
    fn read_changesets(&self, block_number: BlockNumber) -> Result<SaltDeltas, Self::Error>;
    /// Get the latest change sets.
    fn latest_changesets(&self) -> Result<Option<(BlockNumber, SaltDeltas)>, Self::Error>;
    /// Get change sets by block range.
    fn read_changesets_by_block_range(
        &self,
        range: RangeInclusive<BlockNumber>,
    ) -> Result<Vec<SaltDeltas>, Self::Error>;
}

/// This trait provides the functionality for writing the
/// [`SaltChangeSets`] table.
pub trait SaltChangeWriter {
    /// Custom trait's error type.
    type Error: Debug;

    /// Write the change sets of the given block.
    fn write_changesets(
        &self,
        block_number: BlockNumber,
        salt_deltas: SaltDeltas,
    ) -> Result<(), Self::Error>;
}

/// This trait provides the functionality for reading and writing the `BucketVersion` table.
pub trait BucketVersionProvider {
    /// Custom trait's error type.
    type Error: Debug;

    /// Mark the bootstrap is started.
    fn start_bootstrap(&self) -> Result<(), Self::Error>;

    /// Check whether the bootstrap is finished.
    fn bootstrap_flag(&self) -> Result<Option<BlockNumber>, Self::Error>;

    /// Load all existing buckets and their versions.
    fn existing_buckets(&self) -> Result<Vec<(BucketId, BlockNumber)>, Self::Error>;

    /// Set some bucket's version.
    fn set_bucket_version(
        &self,
        bucket_id: BucketId,
        version: BlockNumber,
    ) -> Result<(), Self::Error>;

    /// Mark the bootstrap is finished.
    fn finish_bootstrap(&self, block_number: BlockNumber) -> Result<(), Self::Error>;
}
