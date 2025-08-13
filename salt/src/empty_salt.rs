//! Empty storage backend for SALT.
//!
//! This module provides [`EmptySalt`], a minimal and immutable storage backend
//! that returns default values for all queries. Useful for computing the initial
//! state root of an empty SALT trie and testing scenarios.

use crate::{
    constant::*,
    traits::{StateReader, TrieReader},
    types::*,
};
use std::ops::{Range, RangeInclusive};

/// Represents an empty SALT structure that contains no account or storage.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct EmptySalt;

impl StateReader for EmptySalt {
    type Error = &'static str;

    fn value(&self, key: SaltKey) -> Result<Option<SaltValue>, Self::Error> {
        let value = key
            .is_in_meta_bucket()
            .then(|| BucketMeta::default().into());
        Ok(value)
    }

    fn entries(
        &self,
        _range: RangeInclusive<SaltKey>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        Ok(Vec::new())
    }

    fn metadata(&self, _bucket_id: BucketId) -> Result<BucketMeta, Self::Error> {
        Ok(BucketMeta::default())
    }

    fn bucket_used_slots(&self, _bucket_id: BucketId) -> Result<u64, Self::Error> {
        Ok(0) // Empty SALT has no occupied slots
    }
}

impl TrieReader for EmptySalt {
    type Error = &'static str;

    fn commitment(&self, node_id: NodeId) -> Result<CommitmentBytes, Self::Error> {
        Ok(default_commitment(node_id))
    }

    fn node_entries(
        &self,
        _range: Range<NodeId>,
    ) -> Result<Vec<(NodeId, CommitmentBytes)>, Self::Error> {
        Ok(vec![])
    }
}
