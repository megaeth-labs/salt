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

    fn range_bucket(
        &self,
        _range: RangeInclusive<BucketId>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        Ok(Vec::new())
    }

    fn range_slot(
        &self,
        bucket_id: BucketId,
        range: RangeInclusive<u64>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        Ok(if bucket_id < NUM_META_BUCKETS as BucketId {
            assert!(*range.end() <= MIN_BUCKET_SIZE as NodeId);
            range
                .into_iter()
                .map(|slot_id| {
                    // Return a default value for the bucket meta
                    (
                        SaltKey::from((bucket_id, slot_id)),
                        BucketMeta::default().into(),
                    )
                })
                .collect()
        } else {
            Vec::new()
        })
    }

    fn get_meta(&self, _bucket_id: BucketId) -> Result<BucketMeta, Self::Error> {
        Ok(BucketMeta::default())
    }
}

impl TrieReader for EmptySalt {
    type Error = &'static str;

    fn get_commitment(&self, node_id: NodeId) -> Result<CommitmentBytes, Self::Error> {
        let level = get_node_level(node_id);
        Ok(
            if is_extension_node(node_id)
                || node_id >= DEFAULT_COMMITMENT_AT_LEVEL[level].0 as NodeId
            {
                zero_commitment()
            } else {
                DEFAULT_COMMITMENT_AT_LEVEL[level].1
            },
        )
    }

    fn get_range(
        &self,
        _range: Range<NodeId>,
    ) -> Result<Vec<(NodeId, CommitmentBytes)>, Self::Error> {
        Ok(vec![])
    }
}
