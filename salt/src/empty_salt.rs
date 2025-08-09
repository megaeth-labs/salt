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
        bucket_id: BucketId,
        range: RangeInclusive<u64>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        Ok(if bucket_id < NUM_META_BUCKETS as BucketId {
            let clamped_range = *range.start()..=(*range.end()).min((MIN_BUCKET_SIZE - 1) as u64);
            clamped_range
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
