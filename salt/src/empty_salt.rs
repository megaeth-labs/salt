//! This module provides a standalone method for computing the
//! SALT state root for the genesis block with minimal dependency.

use crate::{
    constant::*,
    traits::{StateReader, TrieReader},
    types::*,
};
use std::ops::{Range, RangeInclusive};

/// An empty SALT structure that contains no account or storage.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct EmptySalt;

impl StateReader for EmptySalt {
    type Error = &'static str;

    fn entry(&self, key: SaltKey) -> Result<Option<SaltValue>, Self::Error> {
        let value = key
            .is_bucket_meta_slot()
            .then(|| BucketMeta::default().into());
        Ok(value)
    }

    fn entries(
        &self,
        range: RangeInclusive<SaltKey>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        let mut result = Vec::new();

        // Find the last metadata key
        let last_metadata_key = bucket_metadata_key(NUM_KV_BUCKETS as BucketId - 1);

        // Only handle metadata keys in the range
        if *range.start() <= last_metadata_key {
            let split_point = std::cmp::min(*range.end(), last_metadata_key);
            let start_bucket = range.start().bucket_id();
            let end_bucket = split_point.bucket_id();

            for bucket_id in start_bucket..=end_bucket {
                for slot_id in 0..=(MIN_BUCKET_SIZE - 1) as SlotId {
                    let meta_key = SaltKey::from((bucket_id, slot_id));
                    if meta_key >= *range.start() && meta_key <= split_point {
                        result.push((meta_key, BucketMeta::default().into()));
                    }
                }
            }
        }

        Ok(result)
    }

    fn meta(&self, _bucket_id: BucketId) -> Result<BucketMeta, Self::Error> {
        Ok(BucketMeta::default())
    }
}

impl TrieReader for EmptySalt {
    type Error = &'static str;

    fn commitment(&self, node_id: NodeId) -> Result<CommitmentBytes, Self::Error> {
        Ok(default_commitment(node_id))
    }

    fn commitments(
        &self,
        _range: Range<NodeId>,
    ) -> Result<Vec<(NodeId, CommitmentBytes)>, Self::Error> {
        Ok(vec![])
    }
}
