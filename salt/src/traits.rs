//! Define traits for storing salt state and salt trie.
use crate::{
    constant::{default_commitment, zero_commitment, STARTING_NODE_ID, TRIE_LEVELS, TRIE_WIDTH},
    trie::trie::get_child_node,
    types::{
        bucket_metadata_key, get_bfs_level, is_subtree_node, BucketId, BucketMeta, CommitmentBytes,
        NodeId, SaltKey, SaltValue, SlotId,
    },
};
use std::{
    cmp::Ordering,
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
        _range: RangeInclusive<u64>, // FIXME: u64 => SaltKey
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        // FIXME: don't provide a bogus implementation here
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

    /// Return the plain value associated with the given plain key.
    fn get(&self, plain_key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        // Computes the `bucket_id` based on the `key`.
        let bucket_id = pk_hasher::bucket_id(plain_key);
        let metadata = self.get_meta(bucket_id)?;
        // Calculates the `hashed_id`(the initial slot position) based on the `key` and `nonce`.
        let hashed_id = pk_hasher::hashed_key(plain_key, metadata.nonce);

        // FIXME: it's a bit awkward that the SHI hash table logic is mingled here
        // can we have a shi-hashtable.rs file that separates the shi logic? easier
        // testing too!

        // Starts from the initial slot position and searches for the slot corresponding to the
        // `key`.
        for step in 0..metadata.capacity {
            let slot_id = probe(hashed_id, step, metadata.capacity);
            if let Some(slot_val) = self.entry((bucket_id, slot_id).into())? {
                match slot_val.key().cmp(plain_key) {
                    Ordering::Less => return Ok(None),
                    // FIXME: no need to copy out the value using "to_vec()"; leave that decision to the caller!
                    Ordering::Equal => return Ok(Some(slot_val.value().to_vec())),
                    Ordering::Greater => (),
                }
            } else {
                return Ok(None);
            }
        }
        Ok(None)
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

/// Returns the i-th slot in the probe sequence of `hashed_key`. Our SHI hash table
/// uses linear probing to address key collisions, so `i` is used as an offset. Since
/// the first slot of each bucket is reserved for metadata (i.e., nonce & capacity),
/// the returned value must be in the range of [1, bucket size).
#[inline(always)]
pub fn probe(hashed_key: u64, i: u64, capacity: u64) -> SlotId {
    ((hashed_key + i) & (capacity - 1)) as SlotId
}

/// Provides utility functions to convert plain keys to hashed keys (and eventually SALT keys).
pub mod pk_hasher {
    use crate::constant::{NUM_KV_BUCKETS, NUM_META_BUCKETS};
    use megaeth_ahash::RandomState;
    use std::hash::{BuildHasher, Hasher};

    use super::BucketId;

    /// Use the lower 32 bytes of keccak256("Make Ethereum Great Again") as the seed values.
    const HASHER_SEED_0: u64 = 0x921321f4;
    const HASHER_SEED_1: u64 = 0x2ccb667e;
    const HASHER_SEED_2: u64 = 0x60d68842;
    const HASHER_SEED_3: u64 = 0x077ada9d;

    /// Hash the given byte string.
    #[inline(always)]
    pub(crate) fn hash(bytes: &[u8]) -> u64 {
        static HASH_BUILDER: RandomState =
            RandomState::with_seeds(HASHER_SEED_0, HASHER_SEED_1, HASHER_SEED_2, HASHER_SEED_3);

        let mut hasher = HASH_BUILDER.build_hasher();
        hasher.write(bytes);
        hasher.finish()
    }

    /// Convert the plain key to a hashed key using the given bucket nonce.
    /// The resulting hashed key will be used to search for the final bucket
    /// location (i.e., the SALT key) where the plain key will be placed.
    #[inline(always)]
    pub(crate) fn hashed_key(plain_key: &[u8], nonce: u32) -> u64 {
        let mut data = plain_key.to_vec();
        data.extend_from_slice(&nonce.to_le_bytes());

        hash(&data)
    }

    /// Locate the bucket where the given plain key resides.
    #[inline(always)]
    pub fn bucket_id(key: &[u8]) -> BucketId {
        (hash(key) % NUM_KV_BUCKETS as u64 + NUM_META_BUCKETS as u64) as BucketId
    }
}
