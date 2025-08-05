//! This module export block witness's interfaces.
use crate::{
    constant::{default_commitment, BUCKET_SLOT_BITS, MIN_BUCKET_SIZE, NUM_META_BUCKETS},
    proof::{prover, CommitmentBytesW, ProofError, SaltProof},
    traits::{StateReader, TrieReader},
    types::*,
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ops::{Bound::Included, Range, RangeInclusive},
};

/// create a block witness from the trie
pub fn get_block_witness<S, T>(
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
        .par_iter()
        .map(|&salt_key| {
            let bucket_id = bucket_id_from_metadata_key(salt_key);
            let meta = state_reader
                .get_meta(bucket_id)
                .map_err(ProofError::ReadStateFailed)?;

            Ok((bucket_id, meta))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;

    let kvs = data_keys
        .par_iter()
        .map(|&salt_key| {
            let entry = state_reader
                .entry(salt_key)
                .map_err(ProofError::ReadStateFailed)?;
            Ok((salt_key, entry))
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

    fn get_commitment(&self, node_id: NodeId) -> Result<CommitmentBytes, Self::Error> {
        Ok(self
            .proof
            .parents_commitments
            .get(&node_id)
            .cloned()
            .unwrap_or_else(|| CommitmentBytesW(default_commitment(node_id)))
            .0)
    }

    fn get_range(
        &self,
        range: Range<NodeId>,
    ) -> Result<Vec<(NodeId, CommitmentBytes)>, Self::Error> {
        let map = &self.proof.parents_commitments;
        Ok(map.range(range).map(|(k, v)| (*k, v.0)).collect())
    }
}

impl BlockWitness {
    /// Verify the block witness
    pub fn verify_proof<B, T>(&self, root: [u8; 32]) -> Result<(), ProofError<B, T>>
    where
        B: StateReader,
        T: TrieReader,
    {
        let mut keys = self
            .metas
            .keys()
            .map(|&bucket_id| bucket_metadata_key(bucket_id))
            .collect::<Vec<_>>();
        keys.extend(self.kvs.keys().copied());

        let mut vals = self
            .metas
            .values()
            .cloned()
            .map(|v| Some(SaltValue::from(v)))
            .collect::<Vec<_>>();
        vals.extend(self.kvs.values().cloned());

        self.proof.check(keys, vals, root)?;
        Ok(())
    }
}

impl StateReader for BlockWitness {
    type Error = &'static str;

    fn entry(&self, key: SaltKey) -> Result<Option<SaltValue>, Self::Error> {
        if key.is_bucket_meta_slot() {
            let bucket_id = bucket_id_from_metadata_key(key);
            Ok(Some(self.get_meta(bucket_id)?.into()))
        } else {
            Ok(self.kvs.get(&key).cloned().flatten())
        }
    }

    // only handle data bucket
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
        range: RangeInclusive<u64>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        let data = if bucket_id < NUM_META_BUCKETS as BucketId {
            assert!(*range.end() <= MIN_BUCKET_SIZE as NodeId);
            range
                .into_iter()
                .map(|slot_id| {
                    let salt_key = SaltKey::from((bucket_id, slot_id));

                    let value = self
                        .metas
                        .get(&bucket_id_from_metadata_key(salt_key))
                        .copied()
                        .unwrap_or_default()
                        .into();

                    (salt_key, value)
                })
                .collect()
        } else {
            self.kvs
                .range((
                    Included(SaltKey::from((bucket_id, *range.start()))),
                    Included(SaltKey::from((bucket_id, *range.end()))),
                ))
                .filter(|(_, v)| v.is_some())
                .map(|(&k, v)| (k, v.clone().unwrap())) // v is checked to be Some in the filter
                .collect()
        };
        Ok(data)
    }

    fn get_meta(&self, bucket_id: BucketId) -> Result<BucketMeta, Self::Error> {
        Ok(self.metas.get(&bucket_id).copied().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        formate::*, mem_salt::MemSalt, state::state::EphemeralSaltState, trie::trie::StateRoot,
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
        mem_salt.update_state(initial_updates.clone());

        let mut trie = StateRoot::new();
        let (old_trie_root, initial_trie_updates) =
            trie.update(&mem_salt, &mem_salt, &initial_updates).unwrap();

        mem_salt.update_trie(initial_trie_updates);

        // 2. Suppose that 100 new kv pairs need to be inserted
        // after the execution of the block.
        let new_kvs = create_random_kv_pairs(100);

        let mut state = EphemeralSaltState::new(&mem_salt);
        let state_updates = state.update(&new_kvs).unwrap();

        // Update the trie with the new inserts
        let (new_trie_root, mut trie_updates) =
            trie.update(&mem_salt, &mem_salt, &state_updates).unwrap();

        let min_sub_tree_keys = state.cache.keys().copied().collect::<Vec<_>>();
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
        let (prover_trie_root, mut prover_trie_updates) = prover_trie
            .update(&block_witness, &block_witness, &prover_updates)
            .unwrap();

        trie_updates
            .data
            .sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        prover_trie_updates
            .data
            .sort_unstable_by(|(a, _), (b, _)| a.cmp(b));

        assert_eq!(trie_updates, prover_trie_updates);

        assert_eq!(new_trie_root, prover_trie_root);
    }

    #[test]
    fn test_error() {
        let kvs = create_random_kv_pairs(100);

        // 1. Initialize the state & trie to represent the origin state.
        let mem_salt = MemSalt::new();

        let initial_updates = EphemeralSaltState::new(&mem_salt).update(&kvs).unwrap();
        mem_salt.update_state(initial_updates.clone());

        let mut trie = StateRoot::new();
        let (root, initial_trie_updates) =
            trie.update(&mem_salt, &mem_salt, &initial_updates).unwrap();

        mem_salt.update_trie(initial_trie_updates);

        // 2. Suppose that 100 new kv pairs need to be inserted
        // after the execution of the block.

        let pk = PlainKey::Storage(Address::ZERO, B256::ZERO).encode();

        let pv = Some(PlainValue::Storage(B256::ZERO.into()).encode());

        let mut state = EphemeralSaltState::new(&mem_salt);
        state.update(vec![(&pk, &pv)]).unwrap();

        let min_sub_tree_keys = state.cache.keys().copied().collect::<Vec<_>>();
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
        mem_salt.update_state(initial_updates.clone());

        let mut trie = StateRoot::new();
        let (_, initial_trie_updates) =
            trie.update(&mem_salt, &mem_salt, &initial_updates).unwrap();

        mem_salt.update_trie(initial_trie_updates);

        // 2. Suppose that 100 new kv pairs need to be inserted
        // after the execution of the block.
        let new_kvs = create_random_kv_pairs(10);
        let mut state = EphemeralSaltState::new(&mem_salt);
        state.update(&new_kvs).unwrap();

        let min_sub_tree_keys = state.cache.keys().copied().collect::<Vec<_>>();

        let block_witness = get_block_witness(&min_sub_tree_keys, &mem_salt, &mem_salt).unwrap();

        // use the old state
        for key in min_sub_tree_keys {
            let witness_value = block_witness.entry(key).unwrap();
            let state_value = mem_salt.entry(key).unwrap();
            assert_eq!(witness_value, state_value);
        }
    }

    fn create_random_kv_pairs(l: usize) -> HashMap<Vec<u8>, Option<Vec<u8>>> {
        let mut rng = StdRng::seed_from_u64(42);
        let mut res = HashMap::new();

        (0..l / 2).for_each(|_| {
            let pk = PlainKey::Account(Address::from(rng.gen::<[u8; 20]>())).encode();
            let pv = Some(
                PlainValue::Account(Account {
                    balance: U256::from(rng.gen_range(0..1000)),
                    nonce: rng.gen_range(0..100),
                    bytecode_hash: None,
                })
                .encode(),
            );
            res.insert(pk, pv);
        });
        (l / 2..l).for_each(|_| {
            let pk = PlainKey::Storage(
                Address::from(rng.gen::<[u8; 20]>()),
                B256::from(rng.gen::<[u8; 32]>()),
            );
            let pv = Some(PlainValue::Storage(B256::from(rng.gen::<[u8; 32]>()).into()).encode());
            res.insert(pk.encode(), pv);
        });
        res
    }
}
