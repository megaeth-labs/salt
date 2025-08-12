//! This module export block witness's interfaces.
use crate::{
    constant::{default_commitment, NUM_META_BUCKETS},
    proof::{prover, ProofError, SaltProof},
    traits::{StateReader, TrieReader},
    types::*,
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ops::{Range, RangeInclusive},
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

    // Sort only if needed
    if keys.windows(2).any(|w| w[0] > w[1]) {
        keys.par_sort_unstable();
    }
    keys.dedup();

    // Separate meta keys from data keys
    let threshold = SaltKey::from((NUM_META_BUCKETS as u32, 0));
    let split_index = keys.partition_point(|&k| k < threshold);
    let (meta_keys, data_keys) = keys.split_at(split_index);

    let metadata = meta_keys
        .par_iter()
        .filter_map(|&salt_key| {
            let bucket_id = bucket_id_from_metadata_key(salt_key);
            state_reader
                .metadata(bucket_id)
                .ok()
                .map(|meta| (bucket_id, (meta != BucketMeta::default()).then_some(meta)))
        })
        .collect();

    let kvs = data_keys
        .par_iter()
        .map(|&salt_key| {
            state_reader
                .value(salt_key)
                .map_err(ProofError::ReadStateFailed)
                .map(|entry| (salt_key, entry))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;

    let proof = prover::create_salt_proof(&keys, state_reader, trie_reader)?;

    Ok(BlockWitness {
        metadata,
        kvs,
        proof,
    })
}

/// Data structure used to re-execute the block in prover client
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockWitness {
    /// bucket metadata in sub state
    pub metadata: BTreeMap<BucketId, Option<BucketMeta>>,
    /// kvs in sub state
    pub kvs: BTreeMap<SaltKey, Option<SaltValue>>,
    /// salt proof to prove the metadata + kvs
    pub proof: SaltProof,
}

impl TrieReader for BlockWitness {
    type Error = &'static str;

    fn commitment(&self, node_id: NodeId) -> Result<CommitmentBytes, Self::Error> {
        Ok(self
            .proof
            .parents_commitments
            .get(&node_id)
            .map(|c| c.0)
            .unwrap_or_else(|| default_commitment(node_id)))
    }

    fn node_entries(
        &self,
        range: Range<NodeId>,
    ) -> Result<Vec<(NodeId, CommitmentBytes)>, Self::Error> {
        Ok(self
            .proof
            .parents_commitments
            .range(range)
            .map(|(&k, v)| (k, v.0))
            .collect())
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
            .metadata
            .keys()
            .map(|&bucket_id| bucket_metadata_key(bucket_id))
            .collect::<Vec<_>>();
        keys.extend(self.kvs.keys().copied());

        let mut vals = self
            .metadata
            .values()
            .map(|&meta_opt| Some(meta_opt.unwrap_or_default().into()))
            .collect::<Vec<_>>();
        vals.extend(self.kvs.values().cloned());

        self.proof.check(keys, vals, root)?;
        Ok(())
    }
}

impl StateReader for BlockWitness {
    type Error = &'static str;

    fn value(&self, key: SaltKey) -> Result<Option<SaltValue>, Self::Error> {
        if key.is_in_meta_bucket() {
            let bucket_id = bucket_id_from_metadata_key(key);
            Ok(self
                .metadata
                .get(&bucket_id)
                .and_then(|&opt| opt)
                .map(Into::into))
        } else {
            Ok(self.kvs.get(&key).cloned().flatten())
        }
    }

    fn entries(
        &self,
        range: RangeInclusive<SaltKey>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        let mut result: Vec<_> = self
            .metadata
            .range(
                bucket_id_from_metadata_key(*range.start())
                    ..=bucket_id_from_metadata_key(*range.end()),
            )
            .filter_map(|(bucket_id, meta)| {
                meta.as_ref()
                    .map(|m| (bucket_metadata_key(*bucket_id), (*m).into()))
            })
            .collect();
        result.extend(
            self.kvs
                .range(*range.start()..=*range.end())
                .filter_map(|(k, v)| v.as_ref().map(|val| (*k, val.clone()))),
        );
        Ok(result)
    }

    fn metadata(&self, bucket_id: BucketId) -> Result<BucketMeta, Self::Error> {
        Ok(self
            .metadata
            .get(&bucket_id)
            .and_then(|&opt| opt)
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        formate::*, mem_store::MemStore, state::state::EphemeralSaltState, trie::trie::StateRoot,
    };
    use alloy_primitives::{Address, B256, U256};
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use std::collections::HashMap;

    #[test]
    fn get_mini_trie() {
        let kvs = create_random_kv_pairs(1000);

        let mem_store = MemStore::new();

        // 1. Initialize the state & trie to represent the origin state.
        let initial_updates = EphemeralSaltState::new(&mem_store).update(&kvs).unwrap();
        mem_store.update_state(initial_updates.clone());

        let mut trie = StateRoot::new();
        let (old_trie_root, initial_trie_updates) = trie
            .update(&mem_store, &mem_store, &initial_updates)
            .unwrap();

        mem_store.update_trie(initial_trie_updates);

        // 2. Suppose that 100 new kv pairs need to be inserted
        // after the execution of the block.
        let new_kvs = create_random_kv_pairs(100);

        let mut state = EphemeralSaltState::new(&mem_store);
        let state_updates = state.update(&new_kvs).unwrap();

        // Update the trie with the new inserts
        let (new_trie_root, mut trie_updates) =
            trie.update(&mem_store, &mem_store, &state_updates).unwrap();

        let min_sub_tree_keys = state.cache.keys().copied().collect::<Vec<_>>();
        let block_witness = get_block_witness(&min_sub_tree_keys, &mem_store, &mem_store).unwrap();

        // 3.options in prover node
        // 3.1 verify the block witness
        let res = block_witness.verify_proof::<MemStore, MemStore>(old_trie_root);
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
        let mem_store = MemStore::new();

        let initial_updates = EphemeralSaltState::new(&mem_store).update(&kvs).unwrap();
        mem_store.update_state(initial_updates.clone());

        let mut trie = StateRoot::new();
        let (root, initial_trie_updates) = trie
            .update(&mem_store, &mem_store, &initial_updates)
            .unwrap();

        mem_store.update_trie(initial_trie_updates);

        // 2. Suppose that 100 new kv pairs need to be inserted
        // after the execution of the block.

        let pk = PlainKey::Storage(Address::ZERO, B256::ZERO).encode();

        let pv = Some(PlainValue::Storage(B256::ZERO.into()).encode());

        let mut state = EphemeralSaltState::new(&mem_store);
        state.update(vec![(&pk, &pv)]).unwrap();

        let min_sub_tree_keys = state.cache.keys().copied().collect::<Vec<_>>();
        let block_witness_res =
            get_block_witness(&min_sub_tree_keys, &mem_store, &mem_store).unwrap();

        let res = block_witness_res.verify_proof::<MemStore, MemStore>(root);
        assert!(res.is_ok());
    }

    #[test]
    fn test_state_reader_for_witness() {
        let kvs = create_random_kv_pairs(1000);

        // 1. Initialize the state & trie to represent the origin state.
        let mem_store = MemStore::new();

        let initial_updates = EphemeralSaltState::new(&mem_store).update(&kvs).unwrap();
        mem_store.update_state(initial_updates.clone());

        let mut trie = StateRoot::new();
        let (_, initial_trie_updates) = trie
            .update(&mem_store, &mem_store, &initial_updates)
            .unwrap();

        mem_store.update_trie(initial_trie_updates);

        // 2. Suppose that 100 new kv pairs need to be inserted
        // after the execution of the block.
        let new_kvs = create_random_kv_pairs(100);
        let mut state = EphemeralSaltState::new(&mem_store);
        state.update(&new_kvs).unwrap();

        let min_sub_tree_keys = state.cache.keys().copied().collect::<Vec<_>>();

        let block_witness = get_block_witness(&min_sub_tree_keys, &mem_store, &mem_store).unwrap();

        // use the old state
        for key in min_sub_tree_keys {
            let witness_value = block_witness.value(key).unwrap();
            let state_value = mem_store.value(key).unwrap();
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
