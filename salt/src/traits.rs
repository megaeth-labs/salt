//! Define traits for storing salt state and salt trie.
use crate::{
    types::{meta_position, BucketMeta, CommitmentBytes, NodeId, SaltKey, SaltValue},
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

    /// Get slot value by `bucket_id` and `slot_id`.
    fn entry(&self, key: SaltKey) -> Result<Option<SaltValue>, Self::Error>;

    /// Retrieves all non-empty entries within the specified range of buckets.
    fn range_bucket(
        &self,
        range: RangeInclusive<BucketId>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error>;

    /// Retrieves all non-empty entries within the specified range of slots.
    fn range_slot(
        &self,
        _bucket_id: BucketId,
        _range: Range<u64>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        unimplemented!("range_slot is not implemented for this reader")
    }

    /// Get bucket meta by bucket ID.
    fn get_meta(&self, bucket_id: BucketId) -> Result<BucketMeta, Self::Error> {
        let key = meta_position(bucket_id);
        Ok(match self.entry(key)? {
            Some(ref v) => v.try_into().expect("meta value error"),
            None => BucketMeta::default(),
        })
    }
}

/// This trait provides functionality for reading commitments from trie nodes.
pub trait TrieReader: Sync {
    /// Custom trait's error type.
    type Error: Debug + Send;
    /// Get Bucket Capacity from store.
    fn bucket_capacity(&self, _bucket_id: BucketId) -> Result<u64, Self::Error> {
        unimplemented!("bucket_capacity is not implemented for this reader")
    }
    /// Get node commitment by `node_id` from store.
    fn get_commitment(&self, node_id: NodeId) -> Result<CommitmentBytes, Self::Error>;

    /// Retrieves child nodes based on the node ID
    fn children(&self, node_id: NodeId) -> Result<Vec<CommitmentBytes>, Self::Error>;
}
