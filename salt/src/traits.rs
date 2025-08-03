//! Define traits for storing salt state and salt trie.
use crate::{
    constant::{default_commitment, zero_commitment, STARTING_NODE_ID, TRIE_LEVELS, TRIE_WIDTH},
    trie::trie::get_child_node,
    types::{
        bucket_metadata_key, get_node_level, is_subtree_node, BucketMeta, CommitmentBytes, NodeId,
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
        _range: RangeInclusive<u64>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        unimplemented!("range_slot is not implemented for this reader")
    }

    /// Get bucket meta by bucket ID.
    fn get_meta(&self, bucket_id: BucketId) -> Result<BucketMeta, Self::Error> {
        let key = bucket_metadata_key(bucket_id);
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

    /// Get node commitment by `node_id` from store.
    fn get_commitment(&self, node_id: NodeId) -> Result<CommitmentBytes, Self::Error>;

    /// Get node commitments by `range` from store.
    /// This is an inefficient implementation that
    /// needs to be re implemented in your Reader
    fn get_range(
        &self,
        range: Range<NodeId>,
    ) -> Result<Vec<(NodeId, CommitmentBytes)>, Self::Error> {
        range
            .map(|node_id| {
                let commitment = self.get_commitment(node_id)?;
                Ok((node_id, commitment))
            })
            .collect()
    }

    /// Retrieves child nodes based on the node ID
    fn children(&self, node_id: NodeId) -> Result<Vec<CommitmentBytes>, Self::Error> {
        let zero = zero_commitment();
        let child_start = get_child_node(&node_id, 0);
        let mut children = vec![zero; TRIE_WIDTH];
        let cache = self.get_range(child_start as NodeId..child_start + TRIE_WIDTH as NodeId)?;
        // Fill in actual values where they exist
        for (k, v) in cache {
            children[k as usize - child_start as usize] = v;
        }

        // Because the trie did not store the default value when init,
        // so meta nodes needs to update the default commitment.
        let child_level = get_node_level(node_id) + 1;
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
