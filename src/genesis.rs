//! This module provides a standalone method for computing the
//! SALT state root for the genesis block with minimal dependency.

use crate::{
    constant::{
        get_node_level, is_extension_node, zero_commitment, DEFAULT_COMMITMENT_AT_LEVEL,
        MIN_BUCKET_SIZE, NUM_META_BUCKETS, TRIE_LEVELS, TRIE_WIDTH,
    },
    traits::{BucketMetadataReader, StateReader, TrieReader},
    types::*,
    EphemeralSaltState, StateRoot,
};
use alloy_genesis::GenesisAccount;
use alloy_primitives::{keccak256, Address, B256};
use reth_primitives_traits::Account;
use std::{
    collections::HashMap,
    ops::{Range, RangeInclusive},
};

/// Compute the state root at genesis from scratch.
pub fn genesis_state_root<'a>(
    state: impl IntoIterator<Item = (&'a Address, &'a GenesisAccount)>,
) -> B256 {
    // Convert PlainAccount|StorageState to PlainKey|Value.
    let mut storages = HashMap::new();
    let mut accounts = HashMap::new();
    for (key, acc) in state {
        let storage = acc
            .storage
            .as_ref()
            .map(|storage| {
                storage
                    .iter()
                    .filter(|(_, value)| **value != B256::ZERO)
                    .map(|(slot, value)| {
                        (PlainKey::Storage(*key, *slot), Some(PlainValue::Storage((*value).into())))
                    })
                    .collect::<HashMap<_, _>>()
            })
            .unwrap_or_default();
        storages.extend(storage);
        accounts.insert(
            PlainKey::Account(*key),
            Some(PlainValue::Account(Account {
                nonce: acc.nonce.unwrap_or_default(),
                balance: acc.balance,
                bytecode_hash: acc.clone().code.map(keccak256),
            })),
        );
    }
    accounts.extend(storages);

    // Calculate salt state root.
    let state_updates = EphemeralSaltState::new(&EmptySalt)
        .update(&accounts)
        .expect("GenesisReader calculate_kvs_state error");
    StateRoot::new()
        .update(&EmptySalt, &state_updates)
        .expect("EmptySalt calculate_state_root error")
        .0
}

/// An empty SALT structure that contains no account or storage.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct EmptySalt;

impl BucketMetadataReader for EmptySalt {
    type Error = &'static str;
    fn get_meta(&self, _bucket_id: BucketId) -> Result<BucketMeta, Self::Error> {
        Ok(BucketMeta::default())
    }
}

impl StateReader for EmptySalt {
    fn entry(
        &self,
        key: SaltKey,
    ) -> Result<Option<SaltValue>, <Self as BucketMetadataReader>::Error> {
        Ok(if key.bucket_id() < NUM_META_BUCKETS as BucketId {
            Some(BucketMeta::default().into())
        } else {
            None
        })
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
        range: Range<u64>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        if bucket_id < NUM_META_BUCKETS as BucketId {
            assert!(range.end <= MIN_BUCKET_SIZE as NodeId);
            let data = range
                .into_iter()
                .map(|slot_id| {
                    // Return a default value for the bucket meta
                    (SaltKey::from((bucket_id, slot_id)), BucketMeta::default().into())
                })
                .collect();
            return Ok(data);
        }
        Ok(Vec::new())
    }
}

impl TrieReader for EmptySalt {
    type Error = &'static str;

    fn bucket_capacity(&self, _bucket_id: BucketId) -> Result<u64, Self::Error> {
        Ok(MIN_BUCKET_SIZE as u64)
    }

    fn get(&self, node_id: NodeId) -> Result<CommitmentBytes, Self::Error> {
        let level = get_node_level(node_id);
        Ok(
            if is_extension_node(node_id) ||
                node_id >= DEFAULT_COMMITMENT_AT_LEVEL[level].0 as NodeId
            {
                zero_commitment()
            } else {
                DEFAULT_COMMITMENT_AT_LEVEL[level].1
            },
        )
    }

    fn children(&self, node_id: NodeId) -> Result<Vec<CommitmentBytes>, Self::Error> {
        let level = get_node_level(node_id);

        if level >= TRIE_LEVELS - 1 {
            return Err("Cannot get children: node is at the bottom level");
        }

        let next_level_default = DEFAULT_COMMITMENT_AT_LEVEL[level + 1].1;
        let zero = zero_commitment();

        let mut children = Vec::with_capacity(TRIE_WIDTH);

        if node_id < DEFAULT_COMMITMENT_AT_LEVEL[level].0 as NodeId {
            if node_id == 0 {
                children.push(next_level_default);
                children.extend(std::iter::repeat(zero).take(TRIE_WIDTH - 1));
            } else {
                children.extend(std::iter::repeat(next_level_default).take(TRIE_WIDTH));
            }
        } else {
            children.extend(std::iter::repeat(zero).take(TRIE_WIDTH));
        }

        Ok(children)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_genesis::GenesisAccount;
    use alloy_primitives::{b256, Address, B256, U256};
    use std::collections::BTreeMap;

    #[test]
    fn genesis_state_root_work() {
        let storages_map: BTreeMap<B256, B256> = vec![(
            b256!("0101010101010101010101010101010101010101010101010101010101010101"),
            b256!("0101010101010101010101010101010101010101010101010101010101010101"),
        )]
        .into_iter()
        .collect();

        let accounts_map: BTreeMap<Address, GenesisAccount> = vec![
            (
                Address::from([1u8; 20]),
                GenesisAccount { balance: U256::from(100), ..Default::default() },
            ),
            (
                Address::from([2u8; 20]),
                GenesisAccount {
                    storage: Some(storages_map),
                    balance: U256::from(200),
                    ..Default::default()
                },
            ),
        ]
        .into_iter()
        .collect();

        assert_eq!(
            genesis_state_root(&accounts_map),
            b256!("dbefb2e79cb31d6200befcea5416cf73c8ed420b2017499c46a1c6314839eb0b")
        );
    }
}
