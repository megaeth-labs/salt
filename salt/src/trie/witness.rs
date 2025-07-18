//! This module export block witness's interfaces.
use crate::{
    constant::{
        get_node_level, is_extension_node, zero_commitment, BUCKET_SLOT_BITS,
        DEFAULT_COMMITMENT_AT_LEVEL, MIN_BUCKET_SIZE, MIN_BUCKET_SIZE_BITS, NUM_META_BUCKETS,
        STARTING_NODE_ID, TRIE_LEVELS, TRIE_WIDTH,
    },
    proof::{prover, CommitmentBytesW, ProofError, SaltProof},
    traits::{BucketMetadataReader, StateReader, TrieReader},
    trie::trie::get_child_node,
    types::*,
};
use alloy_primitives::{b256, Address, B256};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ops::{Bound::Included, Range, RangeInclusive},
};

pub const KECCAK_EMPTY: B256 =
    b256!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

/// create a block witness from the trie
pub fn get_block_witness<'a, S, T>(
    min_sub_tree: &[SaltKey],
    state_reader: &S,
    trie_reader: &T,
) -> Result<BlockWitness, ProofError<S, T>>
where
    S: StateReader,
    T: TrieReader,
{
    let mut keys = min_sub_tree.to_vec();

    // Check if the array is already sorted - returns true if sorted, false otherwise
    // Using any() to find the first out-of-order pair for efficiency
    let needs_sorting = keys.windows(2).any(|w| w[0] > w[1]);
    if needs_sorting {
        keys.par_sort_unstable();
    }
    keys.dedup();

    // Split the sorted keys into two vectors based on threshold
    let threshold = SaltKey::from((NUM_META_BUCKETS as u32, 0));
    // Since keys is already sorted, we can use binary search to find the split point
    let split_index = match keys.binary_search(&threshold) {
        Ok(index) => index,  // Exact match found
        Err(index) => index, // Would be inserted at this index
    };
    let (meta_keys, data_keys) = keys.split_at(split_index);

    let metas = meta_keys
        .iter()
        .map(|salt_key| {
            let bucket_id =
                (salt_key.bucket_id() << MIN_BUCKET_SIZE_BITS) | (salt_key.slot_id() as u32);
            let entry = state_reader.entry(*salt_key).map_err(ProofError::ReadStateFailed)?;

            let bucket_meta = match entry {
                Some(v) => BucketMeta::from(&v),
                None => BucketMeta::default(),
            };

            Ok((bucket_id, bucket_meta))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;

    let kvs = data_keys
        .iter()
        .map(|salt_key| {
            let entry = state_reader.entry(*salt_key).map_err(ProofError::ReadStateFailed)?;
            Ok((*salt_key, entry))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;

    let proof = prover::create_salt_proof(&keys, state_reader, trie_reader)?;

    Ok(BlockWitness { metas, kvs, proof })
}

/// Data structure used to re-execute the block in prover client
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockWitness {
    /// bucket meta in sub state
    pub metas: BTreeMap<BucketId, BucketMeta>,
    /// kvs in sub state
    pub kvs: BTreeMap<SaltKey, Option<SaltValue>>,
    /// salt proof to prove the metas + kvs
    pub proof: SaltProof,
}

impl TrieReader for BlockWitness {
    type Error = &'static str;

    fn bucket_capacity(&self, bucket_id: BucketId) -> Result<u64, Self::Error> {
        Ok(match self.metas.get(&bucket_id) {
            Some(meta) => meta.capacity,
            None => MIN_BUCKET_SIZE as u64,
        })
    }

    fn get(&self, node_id: NodeId) -> Result<CommitmentBytes, Self::Error> {
        Ok(self
            .proof
            .parents_commitments
            .get(&node_id)
            .cloned()
            .unwrap_or_else(|| {
                let level = get_node_level(node_id);
                if is_extension_node(node_id) ||
                    node_id >= DEFAULT_COMMITMENT_AT_LEVEL[level].0 as NodeId
                {
                    CommitmentBytesW(zero_commitment())
                } else {
                    CommitmentBytesW(DEFAULT_COMMITMENT_AT_LEVEL[level].1)
                }
            })
            .0)
    }

    fn children(&self, node_id: NodeId) -> Result<Vec<CommitmentBytes>, Self::Error> {
        let zero = zero_commitment();
        let child_start = get_child_node(&node_id, 0);
        let mut children = vec![zero; TRIE_WIDTH];
        let map = &self.proof.parents_commitments;
        // Fill in actual values where they exist
        for (k, v) in map.range(child_start as NodeId..child_start + TRIE_WIDTH as NodeId) {
            children[*k as usize - child_start as usize] = v.0;
        }

        // Because the trie did not store the default value when init,
        // so meta nodes needs to update the default commitment.
        if node_id < (NUM_META_BUCKETS + STARTING_NODE_ID[TRIE_LEVELS - 1]) as NodeId {
            let child_level = get_node_level(node_id) + 1;
            assert!(child_level < TRIE_LEVELS);
            for i in child_start..
                std::cmp::min(
                    DEFAULT_COMMITMENT_AT_LEVEL[child_level].0,
                    child_start as usize + TRIE_WIDTH,
                ) as NodeId
            {
                let j = (i - child_start) as usize;
                if children[j] == zero {
                    children[j] = DEFAULT_COMMITMENT_AT_LEVEL[child_level].1;
                }
            }
        }

        Ok(children)
    }
}

impl BlockWitness {
    /// Verify the block witness
    pub fn verify_proof<B, T>(&self, root: B256) -> Result<(), ProofError<B, T>>
    where
        B: BucketMetadataReader,
        T: TrieReader,
    {
        let mut keys = self
            .metas
            .keys()
            .map(|bucket_id| {
                SaltKey::from((
                    (bucket_id >> MIN_BUCKET_SIZE_BITS),
                    (bucket_id % MIN_BUCKET_SIZE as BucketId) as SlotId,
                ))
            })
            .collect::<Vec<_>>();

        keys.extend(self.kvs.keys().cloned());

        let mut vals =
            self.metas.values().cloned().map(|v| Some(SaltValue::from(v))).collect::<Vec<_>>();

        vals.extend(self.kvs.values().cloned());

        self.proof.check(keys, vals, root)?;
        Ok(())
    }

    /// Get the address that code hash is not empty
    pub fn get_code_hash_not_empty_addresses(&self) -> Vec<(Address, B256)> {
        self.kvs
            .values()
            .filter_map(|v| v.as_ref())
            .filter_map(|val| {
                let (plain_key, plain_value) = val.into();
                match (plain_key, plain_value) {
                    (PlainKey::Account(address), PlainValue::Account(account)) => account
                        .bytecode_hash
                        .filter(|&code_hash| code_hash != KECCAK_EMPTY)
                        .map(|code_hash| (address, code_hash)),
                    _ => None,
                }
            })
            .collect()
    }
}

impl BucketMetadataReader for BlockWitness {
    type Error = &'static str;
    fn get_meta(&self, bucket_id: BucketId) -> Result<BucketMeta, Self::Error> {
        Ok(self.metas.get(&bucket_id).map_or(BucketMeta::default(), |v| *v))
    }
}

impl StateReader for BlockWitness {
    fn entry(
        &self,
        key: SaltKey,
    ) -> Result<Option<SaltValue>, <Self as BucketMetadataReader>::Error> {
        if key.bucket_id() < NUM_META_BUCKETS as BucketId {
            let data_bucket_id =
                (key.bucket_id() << MIN_BUCKET_SIZE_BITS) + key.slot_id() as BucketId;
            return Ok(Some(self.get_meta(data_bucket_id)?.into()));
        } else {
            let result = self.kvs.get(&key).cloned().flatten();
            Ok(result)
        }
    }

    fn range_bucket(
        &self,
        range: RangeInclusive<BucketId>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        Ok(self
            .kvs
            .range((
                Included(SaltKey::from((*range.start(), 0))),
                Included(SaltKey::from((*range.end(), (1 << BUCKET_SLOT_BITS) - 1))),
            ))
            .filter(|(_, v)| v.is_some())
            .map(|(k, v)| (*k, v.clone().unwrap())) // v is checked to be Some in the filter
            .collect())
    }

    fn range_slot(
        &self,
        bucket_id: BucketId,
        range: Range<u64>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        let data = if bucket_id < NUM_META_BUCKETS as BucketId {
            assert!(range.end <= MIN_BUCKET_SIZE as NodeId);
            range
                .into_iter()
                .map(|slot_id| {
                    let data_bucket_id = (bucket_id << MIN_BUCKET_SIZE_BITS) + slot_id as BucketId;
                    let value =
                        self.get_meta(data_bucket_id).expect("metadata should always exist").into();
                    (SaltKey::from((bucket_id, slot_id)), value)
                })
                .collect()
        } else {
            self.kvs
                .range(
                    SaltKey::from((bucket_id, range.start))..SaltKey::from((bucket_id, range.end)),
                )
                .map(|(k, v)| (k.clone(), v.clone().expect("existing key")))
                .collect()
        };
        Ok(data)
    }
}
/* 
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        compat::Account, constant::MIN_BUCKET_SIZE_BITS, mem_salt::MemSalt,
        state::state::EphemeralSaltState, trie::trie::StateRoot,
    };
    use alloy_primitives::{Address, B256, U256};
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use std::collections::HashMap;

    #[test]
    fn get_mini_trie() {
        let kvs = create_random_kv_pairs(1000);

        let mem_salt = MemSalt::new();

        // 1. Initialize the state & trie to represent the origin state.
        let initial_updates = EphemeralSaltState::new(&mem_salt).update(&kvs).unwrap();
        initial_updates.clone().write_to_store(&mem_salt).unwrap();

        let mut trie = StateRoot::new();
        let (old_trie_root, initial_trie_updates) =
            trie.update(&mem_salt, &initial_updates).unwrap();

        initial_trie_updates.write_to_store(&mem_salt).unwrap();

        // 2. Suppose that 100 new kv pairs need to be inserted
        // after the execution of the block.
        let new_kvs = create_random_kv_pairs(100);

        let mut state = EphemeralSaltState::new(&mem_salt);
        let state_updates = state.update(&new_kvs).unwrap();

        // Update the trie with the new inserts
        let (new_trie_root, mut trie_updates) = trie.update(&mem_salt, &state_updates).unwrap();

        let mut min_sub_tree_keys = state.kv_cache.keys().map(|k| *k).collect::<Vec<_>>();
        min_sub_tree_keys.extend(
            state
                .meta_cache
                .keys()
                .map(|bucket_id| {
                    (
                        (bucket_id >> MIN_BUCKET_SIZE_BITS),
                        (bucket_id % MIN_BUCKET_SIZE as BucketId) as SlotId,
                    )
                        .into()
                })
                .collect::<Vec<SaltKey>>(),
        );
        let block_witness = get_block_witness(&min_sub_tree_keys, &mem_salt, &mem_salt).unwrap();

        // 3.options in prover node
        // 3.1 verify the block witness
        let res = block_witness.verify_proof::<MemSalt, MemSalt>(old_trie_root);
        assert!(res.is_ok());

        // 3.2 create EphemeralSaltState from block witness
        let mut prover_state = EphemeralSaltState::new(&block_witness);

        // 3.3 prover client execute the same blocks, and get the same new_kvs
        let prover_updates = prover_state.update(&new_kvs).unwrap();

        assert_eq!(state_updates, prover_updates);

        let mut prover_trie = StateRoot::new();
        let (prover_trie_root, mut prover_trie_updates) =
            prover_trie.update(&block_witness, &prover_updates).unwrap();

        trie_updates.data.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        prover_trie_updates.data.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));

        assert_eq!(trie_updates, prover_trie_updates);

        assert_eq!(new_trie_root, prover_trie_root);
    }

    #[test]
    fn test_block_witness_serialization() {
        let kvs = create_random_kv_pairs(1000);

        // 1. Initialize the state & trie to represent the origin state.
        let mem_salt = MemSalt::new();

        let initial_updates = EphemeralSaltState::new(&mem_salt).update(&kvs).unwrap();
        initial_updates.clone().write_to_store(&mem_salt).unwrap();

        let mut trie = StateRoot::new();
        let (_, initial_trie_updates) = trie.update(&mem_salt, &initial_updates).unwrap();

        initial_trie_updates.write_to_store(&mem_salt).unwrap();

        // 2. Suppose that 100 new kv pairs need to be inserted
        // after the execution of the block.
        let new_kvs = create_random_kv_pairs(10);
        let mut state = EphemeralSaltState::new(&mem_salt);
        state.update(&new_kvs).unwrap();

        let mut min_sub_tree_keys = state.kv_cache.keys().map(|k| *k).collect::<Vec<_>>();
        min_sub_tree_keys.extend(
            state
                .meta_cache
                .keys()
                .map(|bucket_id| {
                    (
                        (bucket_id >> MIN_BUCKET_SIZE_BITS),
                        (bucket_id % MIN_BUCKET_SIZE as BucketId) as SlotId,
                    )
                        .into()
                })
                .collect::<Vec<SaltKey>>(),
        );
        let block_witness = get_block_witness(&min_sub_tree_keys, &mem_salt, &mem_salt).unwrap();

        let serialized =
            bincode::serde::encode_to_vec(&block_witness, bincode::config::legacy()).unwrap();

        let deserialized: (BlockWitness, usize) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::legacy()).unwrap();

        assert_eq!(block_witness, deserialized.0);
    }

    #[test]
    fn test_error() {
        let kvs = create_random_kv_pairs(100);

        // 1. Initialize the state & trie to represent the origin state.
        let mem_salt = MemSalt::new();

        let initial_updates = EphemeralSaltState::new(&mem_salt).update(&kvs).unwrap();
        initial_updates.clone().write_to_store(&mem_salt).unwrap();

        let mut trie = StateRoot::new();
        let (root, initial_trie_updates) = trie.update(&mem_salt, &initial_updates).unwrap();

        initial_trie_updates.write_to_store(&mem_salt).unwrap();

        // 2. Suppose that 100 new kv pairs need to be inserted
        // after the execution of the block.

        let pk = PlainKey::Storage(Address::ZERO, B256::ZERO);

        let pv = Some(PlainValue::Storage(B256::ZERO.into()));

        let mut state = EphemeralSaltState::new(&mem_salt);
        state.update(vec![(&pk, &pv)]).unwrap();

        let mut min_sub_tree_keys = state.kv_cache.keys().map(|k| *k).collect::<Vec<_>>();
        min_sub_tree_keys.extend(
            state
                .meta_cache
                .keys()
                .map(|bucket_id| {
                    (
                        (bucket_id >> MIN_BUCKET_SIZE_BITS),
                        (bucket_id % MIN_BUCKET_SIZE as BucketId) as SlotId,
                    )
                        .into()
                })
                .collect::<Vec<SaltKey>>(),
        );
        let block_witness_res =
            get_block_witness(&min_sub_tree_keys, &mem_salt, &mem_salt).unwrap();

        let res = block_witness_res.verify_proof::<MemSalt, MemSalt>(root);
        assert!(res.is_ok());
    }

    #[test]
    fn test_state_reader_for_witness() {
        let kvs = create_random_kv_pairs(1000);

        // 1. Initialize the state & trie to represent the origin state.
        let mem_salt = MemSalt::new();

        let initial_updates = EphemeralSaltState::new(&mem_salt).update(&kvs).unwrap();
        initial_updates.clone().write_to_store(&mem_salt).unwrap();

        let mut trie = StateRoot::new();
        let (_, initial_trie_updates) = trie.update(&mem_salt, &initial_updates).unwrap();

        initial_trie_updates.write_to_store(&mem_salt).unwrap();

        // 2. Suppose that 100 new kv pairs need to be inserted
        // after the execution of the block.
        let new_kvs = create_random_kv_pairs(10);
        let mut state = EphemeralSaltState::new(&mem_salt);
        state.update(&new_kvs).unwrap();

        let min_sub_tree_data_keys = state.kv_cache.keys().map(|k| *k).collect::<Vec<_>>();
        let min_sub_tree_meta_keys = state
            .meta_cache
            .keys()
            .map(|bucket_id| {
                (
                    (bucket_id >> MIN_BUCKET_SIZE_BITS),
                    (bucket_id % MIN_BUCKET_SIZE as BucketId) as SlotId,
                )
                    .into()
            })
            .collect::<Vec<SaltKey>>();

        let min_sub_tree_keys = vec![min_sub_tree_data_keys, min_sub_tree_meta_keys].concat();

        let block_witness = get_block_witness(&min_sub_tree_keys, &mem_salt, &mem_salt).unwrap();

        // use the old state
        let state = EphemeralSaltState::new(&mem_salt);

        for key in min_sub_tree_keys {
            let witness_value = block_witness.entry(key).unwrap();
            let state_value = state.entry(key).unwrap();
            assert_eq!(witness_value, state_value);
        }
    }

    fn create_random_kv_pairs(l: usize) -> HashMap<PlainKey, Option<PlainValue>> {
        let mut rng = StdRng::seed_from_u64(42);
        let mut res = HashMap::new();

        (0..l / 2).for_each(|_| {
            let pk = PlainKey::Account(Address::random_with(&mut rng));
            let pv = Some(PlainValue::Account(Account {
                balance: U256::from(rng.gen_range(0..1000)),
                nonce: rng.gen_range(0..100),
                bytecode_hash: None,
            }));
            res.insert(pk, pv);
        });
        (l / 2..l).for_each(|_| {
            let pk = PlainKey::Storage(Address::random_with(&mut rng), B256::random_with(&mut rng));
            let pv = Some(PlainValue::Storage(B256::random_with(&mut rng).into()));
            res.insert(pk, pv);
        });
        res
    }
}
*/