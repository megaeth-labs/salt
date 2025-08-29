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

    fn value(&self, _key: SaltKey) -> Result<Option<SaltValue>, Self::Error> {
        Ok(None)
    }

    fn entries(
        &self,
        _range: RangeInclusive<SaltKey>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        Ok(Vec::new())
    }

    fn metadata(&self, _bucket_id: BucketId) -> Result<BucketMeta, Self::Error> {
        Ok(BucketMeta {
            used: Some(0),
            ..BucketMeta::default()
        })
    }

    fn plain_value_fast(&self, _plain_key: &[u8]) -> Result<SaltKey, Self::Error> {
        Err("Empty salt has no keys")
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constant::NUM_META_BUCKETS;

    #[test]
    fn test_state_reader() {
        let empty_salt = EmptySalt;

        // Test value() returns None
        assert_eq!(empty_salt.value(SaltKey::from((1000, 0))).unwrap(), None);

        // Test entries() returns empty Vec
        assert!(empty_salt
            .entries(SaltKey(0)..=SaltKey(u64::MAX))
            .unwrap()
            .is_empty());

        // Test bucket_used_slots() returns 0
        let bucket_id = NUM_META_BUCKETS as u32;
        assert_eq!(empty_salt.bucket_used_slots(bucket_id).unwrap(), 0);

        // Test metadata() returns default with used: Some(0)
        let meta = empty_salt.metadata(bucket_id).unwrap();
        let expected_meta = BucketMeta {
            used: Some(0),
            ..BucketMeta::default()
        };
        assert_eq!(meta, expected_meta);
    }

    #[test]
    fn test_trie_reader() {
        let empty_salt = EmptySalt;

        // Test commitment() returns default commitment
        let node_id = 0;
        let result = empty_salt.commitment(node_id).unwrap();
        assert_eq!(result, default_commitment(node_id));

        // Test node_entries() returns empty Vec
        assert!(empty_salt.node_entries(0..10).unwrap().is_empty());
    }
}
