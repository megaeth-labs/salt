//! This module implements plain key proof, account proof.
use crate::{
    constant::{
        BUCKET_SLOT_BITS, MIN_BUCKET_SIZE, MIN_BUCKET_SIZE_BITS, NUM_META_BUCKETS, TRIE_WIDTH_BITS,
    },
    proof::{prover, ProofError, SaltProof},
    state::state::{pk_hasher, probe, EphemeralSaltState},
    traits::{BucketMetadataReader, StateReader, TrieReader},
    types::*,
};
use alloy_primitives::{Address, B256, U256};
use reth_codecs::Compact;
use reth_primitives_traits::Account;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ops::{Bound::Included, Range, RangeInclusive},
};

// Create a proof for the given `PlainKey`s.
// Salt's storage structure is (salt_key => salt_value(plain_key, plain_value)),
// If you need to insert a PlainKey, its corresponding salt_key = function(plain_key, tree.state)
// will be calculated.
//
// Therefore, there are two states of these to be inserted plain_keys in Salt,
// - plain_key is stored in a salt's slot
// - plain_key does not exist in all salt's slots
//
// When plain_key exists, just get the SaltProof of the corresponding (salt_key, salt_value), and
// then verify the plain_key contained in salt_value.

// When plain_key does not exist, when we try to insert plain_key, Salt will first calculate the
// optimal slot of plain_key, and according to the find algorithm, it will automatically find the
// final slot where plain_key will be stored.
// - The final slot may be the optimal slot directly. The optimal slot in salt is empty, or the
//   optimal slot in salt is not empty, but the priority of the plainkey stored in it is lower than
//   the priority of the plain_key to be inserted
// - The final slot may be one or n slots after the optimal slot. At this time, the priority of the
//   plainkey stored in the optimal slot is higher than the plain_key to be inserted. This process
//   will generate traversal until None or a slot with a lower priority of the stored plainkey is
//   found.
// The salt key and salt value accessed during the traversal process and the bucket meta will be
// saved and proved, which is used to reconstruct the process on the verifier side.
fn create_proof<S, T>(
    keys: &Vec<PlainKey>,
    state_reader: &S,
    trie_reader: &T,
) -> Result<PlainKeysProof, ProofError<S, T>>
where
    S: StateReader,
    T: TrieReader,
{
    let mut status = Vec::with_capacity(keys.len());
    let mut metas = BTreeMap::new();
    let mut sub_state = BTreeMap::new();

    for key in keys.iter() {
        // Create a temporary state so that find operations with different keys will not interfere
        // with state.cache
        let mut state = EphemeralSaltState::new(state_reader);

        let key_buf = key.encode();
        let bucket_id = pk_hasher::bucket_id(&key_buf);

        let meta = state_reader.get_meta(bucket_id).map_err(ProofError::ReadStateFailed)?;

        let slot_id =
            state.find(bucket_id, &meta, &key_buf).map_err(ProofError::ReadStateFailed)?;

        match slot_id {
            Some((slot_id, salt_value)) => {
                let salt_key = SaltKey::from((bucket_id, slot_id));

                status.push(PlainKeysStatus::Existed(salt_key));
                sub_state.insert(salt_key, Some(salt_value));
            }

            None => {
                let cache = &state.kv_cache;
                if cache.is_empty() {
                    return Err(ProofError::ProveFailed(
                        "EphemeralSaltState cache is empty".to_string(),
                    ));
                }

                let optimal_slot_id =
                    probe(pk_hasher::hashed_key(&key_buf, meta.nonce), 0, meta.capacity);

                let final_slot_id_salt_key = if optimal_slot_id + cache.len() as u64 > meta.capacity
                {
                    (bucket_id, (optimal_slot_id + cache.len() as u64 - 1) & (meta.capacity - 1))
                        .into()
                } else {
                    cache
                        .keys()
                        .max()
                        .cloned()
                        .ok_or(ProofError::ProveFailed("cache is empty".to_string()))?
                };

                status.push(PlainKeysStatus::NotExisted(final_slot_id_salt_key));
                metas.insert(bucket_id, meta);
                sub_state.extend(cache.iter().map(|(k, v)| (*k, v.clone())));
            }
        };
    }

    let mut salt_keys = Vec::with_capacity(metas.len() + sub_state.len());

    salt_keys
        .extend(metas.keys().map(|&k| SaltKey::from((k >> TRIE_WIDTH_BITS, (k & 0xFF) as u64))));
    salt_keys.extend(sub_state.keys().map(|k| *k));

    let proof = prover::create_salt_proof(&salt_keys, state_reader, trie_reader)?;

    Ok(PlainKeysProof { keys: keys.clone(), status, metas, sub_state, proof })
}

/// get account proof
pub fn get_proof<S, T>(
    address: Address,
    slots: &[B256],
    state_reader: &S,
    trie_reader: &T,
) -> Result<AccountProof, ProofError<S, T>>
where
    S: StateReader,
    T: TrieReader,
{
    let account_proof = create_proof(&vec![PlainKey::Account(address)], state_reader, trie_reader)?;

    let storage_proof = if slots.is_empty() {
        None
    } else {
        let storage_keys = slots.iter().map(|slot| PlainKey::Storage(address, *slot)).collect();
        Some(create_proof(&storage_keys, state_reader, trie_reader)?)
    };

    Ok(AccountProof { account_proof, storage_proof })
}

/// plain key status
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlainKeysStatus {
    /// existed
    Existed(SaltKey),
    /// not existed
    NotExisted(SaltKey),
}

/// A set of plain keys' proof
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlainKeysProof {
    /// The plain keys to be proved
    pub(crate) keys: Vec<PlainKey>,
    /// The status of each plain key
    pub(crate) status: Vec<PlainKeysStatus>,
    /// Data used to help with verify, used to implement BucketMetadataReader
    pub(crate) metas: BTreeMap<BucketId, BucketMeta>,
    /// Data used to help with verify, used to implement StateReader, and get the PlainValue if
    /// PlainKey exists
    pub(crate) sub_state: BTreeMap<SaltKey, Option<SaltValue>>,
    /// The proof of the sub_state and metas
    pub(crate) proof: SaltProof,
}

impl PlainKeysProof {
    /// Verify the account proof and storage proof.
    pub(crate) fn verify<B, T>(&self, root: B256) -> Result<(), ProofError<B, T>>
    where
        B: BucketMetadataReader,
        T: TrieReader,
    {
        if self.keys.len() != self.status.len() {
            return Err(ProofError::VerifyFailed("keys and status length mismatch".to_string()));
        }

        let mut salt_keys = Vec::with_capacity(self.sub_state.len() + self.metas.len());
        salt_keys.extend(
            self.metas.keys().map(|k| SaltKey::from((*k >> TRIE_WIDTH_BITS, (*k & 0xFF) as u64))),
        );
        salt_keys.extend(self.sub_state.keys().map(|k| *k));

        let mut salt_values: Vec<Option<SaltValue>> =
            Vec::with_capacity(self.sub_state.len() + self.metas.len());
        salt_values.extend(self.metas.values().map(|&v| Some(SaltValue::from(v))));
        salt_values.extend(self.sub_state.values().map(|v| v.clone()));

        self.proof.check(salt_keys, salt_values, root)?;

        for (pkey, status) in self.keys.iter().zip(self.status.iter()) {
            match status {
                PlainKeysStatus::Existed(salt_key) => {
                    let salt_value = self
                        .entry(*salt_key)
                        .map_err(|e| ProofError::VerifyFailed(format!(
                            "verify plain key: {:?} failed: salt key {:?}'s salt value not found: {}",
                            pkey, salt_key, e
                        )))?
                        .ok_or(ProofError::VerifyFailed(format!(
                            "verify plain key: {:?} failed: salt key {:?}'s salt value not found",
                            pkey, salt_key
                        )))?;

                    let key = salt_value.key();
                    let address = Address::from_slice(&key[..20]);

                    let plain_key = if key.len() == 20 {
                        PlainKey::Account(address)
                    } else {
                        PlainKey::Storage(address, B256::from_slice(&key[20..52]))
                    };

                    if plain_key != *pkey {
                        return Err(ProofError::VerifyFailed(format!(
                            "expected plain key {:?}, but got {:?}, salt key {:?}",
                            pkey, plain_key, salt_key
                        )));
                    }
                }
                PlainKeysStatus::NotExisted(salt_key) => {
                    let mut state = EphemeralSaltState::new(self);

                    let key_buf = pkey.encode();
                    let bucket_id = pk_hasher::bucket_id(&key_buf);

                    let meta = self.get_meta(bucket_id).map_err(|e| {
                        ProofError::VerifyFailed(format!(
                            "bucket id {:?} not found, detail: {}",
                            bucket_id, e
                        ))
                    })?;

                    let slot_id = state.find(bucket_id, &meta, &key_buf).map_err(|e| {
                        ProofError::VerifyFailed(format!("slot id not found, detail: {}", e))
                    })?;

                    if slot_id.is_some() {
                        return Err(ProofError::VerifyFailed(format!(
                            "slot_id found, so plain_key {:?} should be existed, but the proof is about not existed, salt key {:?}",
                            pkey, salt_key
                        )));
                    }

                    let cache = &state.kv_cache;
                    if cache.is_empty() {
                        return Err(ProofError::VerifyFailed("cache is empty".to_string()));
                    }

                    let optimal_slot_id =
                        probe(pk_hasher::hashed_key(&pkey.encode(), meta.nonce), 0, meta.capacity);

                    let target_salt_key = if optimal_slot_id + cache.len() as u64 > meta.capacity {
                        (
                            bucket_id,
                            (optimal_slot_id + cache.len() as u64 - 1) & (meta.capacity - 1),
                        )
                            .into()
                    } else {
                        cache
                            .keys()
                            .max()
                            .cloned()
                            .ok_or(ProofError::VerifyFailed("cache is empty".to_string()))?
                    };

                    let target_salt_value =
                        cache.get(&target_salt_key).cloned().ok_or(ProofError::VerifyFailed(
                            format!("salt key {:?} not found in cache", target_salt_key),
                        ))?;

                    if target_salt_key != *salt_key {
                        return Err(ProofError::VerifyFailed(format!(
                            "salt key {:?} expected, but got {:?}",
                            salt_key, target_salt_key
                        )));
                    } else {
                        if let Some(salt_value) = target_salt_value {
                            let key = salt_value.key();
                            let address = Address::from_slice(&key[..20]);

                            let plain_key = if key.len() == 20 {
                                PlainKey::Account(address)
                            } else {
                                PlainKey::Storage(address, B256::from_slice(&key[20..52]))
                            };

                            if plain_key == *pkey {
                                return Err(ProofError::VerifyFailed(format!(
                                    "plain_key {:?} existed, but the proof is about not existed, salt key {:?}",
                                    pkey, salt_key
                                )));
                            } else if plain_key > *pkey {
                                return Err(ProofError::VerifyFailed(format!(
                                    "plain_key {:?} may be existed, as it's smaller than {:?}",
                                    pkey, plain_key
                                )));
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

impl BucketMetadataReader for PlainKeysProof {
    type Error = &'static str;
    fn get_meta(&self, bucket_id: BucketId) -> Result<BucketMeta, Self::Error> {
        Ok(self.metas.get(&bucket_id).map_or(BucketMeta::default(), |v| *v))
    }
}

impl StateReader for PlainKeysProof {
    fn entry(
        &self,
        key: SaltKey,
    ) -> Result<Option<SaltValue>, <Self as BucketMetadataReader>::Error> {
        if key.bucket_id() < NUM_META_BUCKETS as BucketId {
            let data_bucket_id =
                (key.bucket_id() << MIN_BUCKET_SIZE_BITS) + key.slot_id() as BucketId;
            return Ok(Some(self.get_meta(data_bucket_id)?.into()))
        } else {
            let result = self.sub_state.get(&key).cloned().flatten();
            Ok(result)
        }
    }

    fn range_bucket(
        &self,
        range: RangeInclusive<BucketId>,
    ) -> Result<Vec<(SaltKey, SaltValue)>, Self::Error> {
        Ok(self
            .sub_state
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
            self.sub_state
                .range(
                    SaltKey::from((bucket_id, range.start))..SaltKey::from((bucket_id, range.end)),
                )
                .map(|(k, v)| (k.clone(), v.clone().expect("existing key")))
                .collect()
        };
        Ok(data)
    }
}

/// Trie layer's Response for EIP-1186 account proof `eth_getProof`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountProof {
    /// The account proof.
    pub account_proof: PlainKeysProof,
    /// The storage proof.
    pub storage_proof: Option<PlainKeysProof>,
}

impl AccountProof {
    /// Verify the account proof and storage proof.
    pub fn verify<B, T>(&self, root: B256) -> Result<(), ProofError<B, T>>
    where
        B: BucketMetadataReader,
        T: TrieReader,
    {
        self.account_proof.verify(root)?;

        if let Some(storage_proof) = &self.storage_proof {
            storage_proof.verify(root)?;
        }

        Ok(())
    }

    /// Get the Account
    pub fn account(&self) -> Result<(Address, Account), String> {
        let address = match self.account_proof.keys[0] {
            PlainKey::Account(address) => address,
            _ => return Err("plain key should be Account type in the account proof".to_string()),
        };

        let salt_key = match self.account_proof.status[0] {
            PlainKeysStatus::Existed(salt_key) => salt_key,
            PlainKeysStatus::NotExisted(_) => {
                return Ok((address, Account::default()));
            }
        };

        let salt_val = self.account_proof.entry(salt_key)?.ok_or("account not found")?;

        let account = if salt_val.value().len() == 0 {
            Account::default()
        } else {
            let plain_val = PlainValue::decode(salt_val.value());
            plain_val.into()
        };
        Ok((address, account))
    }

    /// Get the storage slots and values
    pub fn storages(&self) -> Result<Vec<(B256, U256)>, String> {
        let address = match self.account_proof.keys[0] {
            PlainKey::Account(address) => address,
            _ => return Err("plain key should be Account type in the account proof".to_string()),
        };

        let slots_vals = if let Some(storage_proof) = &self.storage_proof {
            storage_proof
                    .keys
                    .iter()
                    .zip(storage_proof.status.iter())
                    .map(|(key, status)| {
                        let slot = match key {
                            PlainKey::Storage(addr, slot) => {
                                if *addr != address {
                                    return Err("address mismatch".to_string());
                                }
                                slot
                            }
                            _ => {
                                return Err(
                                    "key should be Storage type in the storage proof".to_string()
                                )
                            }
                        };

                        let storage_val = match status {
                            PlainKeysStatus::Existed(salt_key) => {
                                let salt_val = storage_proof
                                    .entry(*salt_key)?
                                    .ok_or("slot's salt value not found")?;
                                U256::from_compact(salt_val.value(), salt_val.value().len()).0
                            }
                            PlainKeysStatus::NotExisted(_) => U256::ZERO,
                        };

                        Ok((*slot, storage_val))
                    })
                .collect::<Result<Vec<_>, _>>()?
        } else {
            vec![]
        };

        Ok(slots_vals)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{mem_salt::MemSalt, state::state::EphemeralSaltState, trie::trie::StateRoot};
    use alloy_primitives::{B256, U256};
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use reth_primitives_traits::Account;
    use std::collections::HashMap;

    /// Checks if the account proof is correct
    #[test]
    fn test_account_proof() {
        let mut rng = StdRng::seed_from_u64(42);

        let addresses: Vec<Address> = (0..4).map(|_| Address::random_with(&mut rng)).collect();

        let account1 = Account { balance: U256::from(10), nonce: 10, bytecode_hash: None };
        let account2 =
            Account { balance: U256::from(100), nonce: 0, bytecode_hash: Some(B256::random()) };

        let mut slot1 = B256::random();
        let mut slot2 = B256::random();
        if slot1 > slot2 {
            std::mem::swap(&mut slot1, &mut slot2);
        }
        let storage_value1 = B256::random();
        let storage_value2 = B256::random();

        let kvs1 = HashMap::from([
            (PlainKey::Account(addresses[0]), Some(PlainValue::Account(account1))),
            (PlainKey::Account(addresses[1]), Some(PlainValue::Account(account1))),
        ]);

        let kvs2 = HashMap::from([
            (PlainKey::Account(addresses[2]), Some(PlainValue::Account(account2))),
            (
                PlainKey::Storage(addresses[2], slot1),
                Some(PlainValue::Storage(storage_value1.into())),
            ),
            (
                PlainKey::Storage(addresses[2], slot2),
                Some(PlainValue::Storage(storage_value2.into())),
            ),
        ]);

        let mut kvs = kvs1;
        kvs.extend(kvs2);

        let mem_salt = MemSalt::new();

        let state_updates = EphemeralSaltState::new(&mem_salt).update(&kvs).unwrap();
        state_updates.clone().write_to_store(&mem_salt).unwrap();

        let mut trie = StateRoot::new();
        let (root, trie_updates) = trie.update(&mem_salt, &state_updates).unwrap();
        trie_updates.write_to_store(&mem_salt).unwrap();

        let account_proof0 = get_proof(addresses[0], &[], &mem_salt, &mem_salt).unwrap();
        let account_proof1 = get_proof(addresses[1], &[], &mem_salt, &mem_salt).unwrap();
        let account_proof2 =
            get_proof(addresses[2], &[slot1, slot2], &mem_salt, &mem_salt).unwrap();
        let account_proof3 = get_proof(addresses[3], &[], &mem_salt, &mem_salt).unwrap();

        account_proof0.verify::<MemSalt, MemSalt>(root).unwrap();
        account_proof1.verify::<MemSalt, MemSalt>(root).unwrap();
        account_proof2.verify::<MemSalt, MemSalt>(root).unwrap();
        account_proof3.verify::<MemSalt, MemSalt>(root).unwrap();

        let account0_get = account_proof0.account().unwrap();
        let account1_get = account_proof1.account().unwrap();
        let account2_get = account_proof2.account().unwrap();
        let account3_get = account_proof3.account().unwrap();

        assert_eq!(account0_get.0, addresses[0]);
        assert_eq!(account1_get.0, addresses[1]);
        assert_eq!(account2_get.0, addresses[2]);

        assert_eq!(account0_get.1, account1);
        assert_eq!(account1_get.1, account1);
        assert_eq!(account2_get.1, account2);
        assert_eq!(account3_get.1, Account::default());

        let account2_storages = account_proof2.storages().unwrap();

        assert_eq!(account2_storages[0].0, slot1);
        assert_eq!(account2_storages[0].1, storage_value1.into());

        assert_eq!(account2_storages[1].0, slot2);
        assert_eq!(account2_storages[1].1, storage_value2.into());

        let serialized =
            bincode::serde::encode_to_vec(&account_proof2, bincode::config::legacy()).unwrap();
        let deserialized: (AccountProof, usize) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::legacy()).unwrap();

        assert_eq!(account_proof2, deserialized.0);

        let serialized = serde_json::to_string(&account_proof2).unwrap();
        let deserialized: AccountProof = serde_json::from_str(&serialized).unwrap();

        assert_eq!(account_proof2, deserialized);
    }

    #[test]
    fn test_plain_keys_proof_serialize() {
        let account1 = Account { balance: U256::from(10), nonce: 10, bytecode_hash: None };

        let kvs = HashMap::from([(
            PlainKey::Account(Address::random()),
            Some(PlainValue::Account(account1)),
        )]);

        let mem_salt = MemSalt::new();

        let state_updates = EphemeralSaltState::new(&mem_salt).update(&kvs).unwrap();
        state_updates.clone().write_to_store(&mem_salt).unwrap();

        let mut trie = StateRoot::new();
        let (_root, trie_updates) = trie.update(&mem_salt, &state_updates).unwrap();
        trie_updates.write_to_store(&mem_salt).unwrap();

        let plain_keys_proof =
            create_proof(&vec![*kvs.keys().next().unwrap()], &mem_salt, &mem_salt).unwrap();

        let serialized =
            bincode::serde::encode_to_vec(&plain_keys_proof, bincode::config::legacy()).unwrap();
        let deserialized: (PlainKeysProof, usize) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::legacy()).unwrap();

        assert_eq!(plain_keys_proof, deserialized.0);
    }

    #[test]
    fn test_plain_key_proof_exist_or_not_exist() {
        // The result of find is some
        // ===================
        // Case 1, the result of find is some, and PlainKey is equal (found)
        // Insert 6, find 6
        // Case 2, the result of find is None, there are 1 or more values ​​in the state cache, and
        // all v are some. PlainKey Not equal (not found, and the PlainKey to be found has a
        // high priority) case 2.1
        // Insert 6, find 0
        // case 2.2
        // Insert 6, 0, find 1
        // case 2.3
        // Insert 6, 0, 2, find 1
        // The result of find is None
        // ==================
        // Case 3,
        // the result of find is None, there is only 1 value in the state cache, and its v
        // is None. The best slot is None. No insertion, directly find 0
        // Case 4, the find result is None, there are 2 or more values ​​in the state cache, the best
        // slot is Some, but the one to be found PlainKey has the lowest priority and
        // finally falls to None Insert 0-5, find 6

        // case 1
        let mem_salt = MemSalt::new();
        let root = insert_kvs(get_kvs(vec![6]), &mem_salt);

        let proof =
            create_proof(&vec![*get_kvs(vec![6]).keys().next().unwrap()], &mem_salt, &mem_salt)
                .unwrap();

        assert!(proof.verify::<MemSalt, MemSalt>(root).is_ok());

        let salt_key = match proof.status.first().unwrap() {
            PlainKeysStatus::Existed(key) => key,
            PlainKeysStatus::NotExisted(key) => key,
        };

        let salt_value = proof.entry(*salt_key).unwrap().unwrap();
        let plain_value = if salt_value.value().len() == 20 {
            Some(PlainValue::Account(Account::default()))
        } else {
            Some(PlainValue::Storage(B256::from_slice(&salt_value.value()).into()))
        };

        assert_eq!(plain_value, *get_kvs(vec![6]).values().next().unwrap());

        // case 2.1
        let mem_salt = MemSalt::new();
        let root = insert_kvs(get_kvs(vec![6]), &mem_salt);

        let salt_val = SaltValue { data: SALT_VALUE_BYTES[0] };
        let key = salt_val.key();

        let plain_key = if key.len() == 20 {
            PlainKey::Account(Address::from_slice(&key[..20]))
        } else {
            PlainKey::Storage(Address::from_slice(&key[..20]), B256::from_slice(&key[20..52]))
        };

        let proof = create_proof(&vec![plain_key], &mem_salt, &mem_salt).unwrap();

        assert!(proof.verify::<MemSalt, MemSalt>(root).is_ok());

        let salt_key = match proof.status.first().unwrap() {
            PlainKeysStatus::Existed(key) => key,
            PlainKeysStatus::NotExisted(key) => key,
        };

        let salt_value = proof.entry(*salt_key).unwrap();
        assert!(salt_value.is_some());

        let bucket_id = 2448221;
        let meta = mem_salt.get_meta(bucket_id).unwrap();

        let mut state = EphemeralSaltState::new(&mem_salt);
        state.find(bucket_id, &meta, plain_key.encode().as_slice()).unwrap();

        let existed_key = state.kv_cache.values().next().unwrap().clone().unwrap();

        assert!(*plain_key.encode() > *existed_key.key());

        // case 2.2
        let mem_salt = MemSalt::new();
        let root = insert_kvs(get_kvs(vec![6, 0]), &mem_salt);

        let salt_val = SaltValue { data: SALT_VALUE_BYTES[1] };
        let key = salt_val.key();

        let plain_key = if key.len() == 20 {
            PlainKey::Account(Address::from_slice(&key[..20]))
        } else {
            PlainKey::Storage(Address::from_slice(&key[..20]), B256::from_slice(&key[20..52]))
        };

        let proof = create_proof(&vec![plain_key], &mem_salt, &mem_salt).unwrap();

        let res = proof.verify::<MemSalt, MemSalt>(root);
        assert!(res.is_ok());

        let salt_key = match proof.status.first().unwrap() {
            PlainKeysStatus::Existed(key) => key,
            PlainKeysStatus::NotExisted(key) => key,
        };

        let salt_value = proof.entry(*salt_key).unwrap();
        assert!(salt_value.is_some());

        let bucket_id = 2448221;
        let meta = mem_salt.get_meta(bucket_id).unwrap();

        let mut state = EphemeralSaltState::new(&mem_salt);
        state.find(bucket_id, &meta, plain_key.encode().as_slice()).unwrap();

        let existed_key = state.kv_cache.values().next().unwrap().clone().unwrap();

        assert!(*plain_key.encode() > *existed_key.key());

        // case 2.3
        let mem_salt = MemSalt::new();
        let root = insert_kvs(get_kvs(vec![6, 0, 2]), &mem_salt);

        let salt_val = SaltValue { data: SALT_VALUE_BYTES[1] };
        let key = salt_val.key();

        let plain_key = if key.len() == 20 {
            PlainKey::Account(Address::from_slice(&key[..20]))
        } else {
            PlainKey::Storage(Address::from_slice(&key[..20]), B256::from_slice(&key[20..52]))
        };

        let proof = create_proof(&vec![plain_key], &mem_salt, &mem_salt).unwrap();

        assert!(proof.verify::<MemSalt, MemSalt>(root).is_ok());

        let salt_key = match proof.status.first().unwrap() {
            PlainKeysStatus::Existed(key) => key,
            PlainKeysStatus::NotExisted(key) => key,
        };

        let salt_value = proof.entry(*salt_key).unwrap();
        assert!(salt_value.is_some());

        let bucket_id = 2448221;
        let meta = mem_salt.get_meta(bucket_id).unwrap();

        let mut state = EphemeralSaltState::new(&mem_salt);
        state.find(bucket_id, &meta, plain_key.encode().as_slice()).unwrap();

        let existed_key = state.kv_cache.values().next().unwrap().clone().unwrap();

        assert!(*plain_key.encode() > *existed_key.key());

        // case 3
        let mem_salt = MemSalt::new();
        let root = B256::from_slice(&ffi_interface::hash_commitment(mem_salt.get(0).unwrap()));

        let salt_val = SaltValue { data: SALT_VALUE_BYTES[1] };
        let key = salt_val.key();

        let plain_key = if key.len() == 20 {
            PlainKey::Account(Address::from_slice(&key[..20]))
        } else {
            PlainKey::Storage(Address::from_slice(&key[..20]), B256::from_slice(&key[20..52]))
        };

        let proof = create_proof(&vec![plain_key], &mem_salt, &mem_salt).unwrap();

        assert!(proof.verify::<MemSalt, MemSalt>(root).is_ok());

        let salt_key = match proof.status.first().unwrap() {
            PlainKeysStatus::Existed(key) => key,
            PlainKeysStatus::NotExisted(key) => key,
        };

        let salt_value = proof.entry(*salt_key).unwrap();
        assert!(salt_value.is_none());

        let bucket_id = 2448221;
        let meta = mem_salt.get_meta(bucket_id).unwrap();

        let mut state = EphemeralSaltState::new(&mem_salt);
        state.find(bucket_id, &meta, plain_key.encode().as_slice()).unwrap();

        assert!(state.kv_cache.values().next().unwrap().is_none());

        // case 4
        let mem_salt = MemSalt::new();
        let root = insert_kvs(get_kvs(vec![0, 1, 2, 3, 4, 5]), &mem_salt);

        let salt_val = SaltValue { data: SALT_VALUE_BYTES[6] };
        let key = salt_val.key();

        let plain_key = if key.len() == 20 {
            PlainKey::Account(Address::from_slice(&key[..20]))
        } else {
            PlainKey::Storage(Address::from_slice(&key[..20]), B256::from_slice(&key[20..52]))
        };

        let proof = create_proof(&vec![plain_key], &mem_salt, &mem_salt).unwrap();

        assert!(proof.verify::<MemSalt, MemSalt>(root).is_ok());

        let salt_key = match proof.status.first().unwrap() {
            PlainKeysStatus::Existed(key) => key,
            PlainKeysStatus::NotExisted(key) => key,
        };

        let salt_value = proof.entry(*salt_key).unwrap();
        assert!(salt_value.is_none());

        let bucket_id = 2448221;
        let meta = mem_salt.get_meta(bucket_id).unwrap();

        let mut state = EphemeralSaltState::new(&mem_salt);
        state.find(bucket_id, &meta, plain_key.encode().as_slice()).unwrap();

        let salt_val = state.kv_cache.iter().max_by_key(|a| a.0).unwrap().1.clone();

        assert!(salt_val.is_none());
    }

    #[test]
    fn test_plain_key_proof_in_loop_slot_id() {
        let mem_salt = MemSalt::new();
        let root = insert_kvs(get_kvs(vec![9]), &mem_salt);

        let salt_val = SaltValue { data: SALT_VALUE_BYTES[7] };
        let key = salt_val.key();

        let plain_key = if key.len() == 20 {
            PlainKey::Account(Address::from_slice(&key[..20]))
        } else {
            PlainKey::Storage(Address::from_slice(&key[..20]), B256::from_slice(&key[20..52]))
        };

        let proof = create_proof(&vec![plain_key], &mem_salt, &mem_salt).unwrap();

        assert!(proof.verify::<MemSalt, MemSalt>(root).is_ok());

        let salt_key = match proof.status.first().unwrap() {
            PlainKeysStatus::Existed(key) => key,
            PlainKeysStatus::NotExisted(key) => key,
        };

        assert_eq!(salt_key.slot_id(), 0);
        let salt_value = proof.entry(*salt_key).unwrap();
        assert!(salt_value.is_none());

        // another case
        let mem_salt = MemSalt::new();
        let root = insert_kvs(get_kvs(vec![7, 8, 9]), &mem_salt);

        let salt_val = SaltValue { data: SALT_VALUE_BYTES[8] };
        let key = salt_val.key();

        let plain_key = if key.len() == 20 {
            PlainKey::Account(Address::from_slice(&key[..20]))
        } else {
            PlainKey::Storage(Address::from_slice(&key[..20]), B256::from_slice(&key[20..52]))
        };

        let proof = create_proof(&vec![plain_key], &mem_salt, &mem_salt).unwrap();

        assert!(proof.verify::<MemSalt, MemSalt>(root).is_ok());

        assert_eq!(proof.keys.first().unwrap(), &plain_key);

        let salt_key = match proof.status.first().unwrap() {
            PlainKeysStatus::Existed(key) => key,
            PlainKeysStatus::NotExisted(key) => key,
        };

        assert_eq!(salt_key.slot_id(), 1);
        let salt_value = proof.entry(*salt_key).unwrap().unwrap();

        assert_eq!(salt_value, salt_val);
    }

    #[test]
    fn test_state_reader_for_plain_keys_proof() {
        let l = 100;
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

        let mem_salt = MemSalt::new();
        let mut state = EphemeralSaltState::new(&mem_salt);
        let updates = state.update(&res).unwrap();
        updates.clone().write_to_store(&mem_salt).unwrap();

        let (_, trie_updates) = StateRoot::new().update(&mem_salt, &updates).unwrap();

        trie_updates.write_to_store(&mem_salt).unwrap();

        let keys = state.kv_cache.keys().map(|k| *k).collect::<Vec<_>>();

        let plain_keys_proof =
            create_proof(&res.keys().map(|k| *k).collect::<Vec<_>>(), &mem_salt, &mem_salt)
                .unwrap();

        for key in keys {
            let proof_value = plain_keys_proof.entry(key).unwrap();
            let state_value = state.entry(key).unwrap();
            assert_eq!(proof_value, state_value);
        }
    }

    fn get_kvs(index: Vec<usize>) -> HashMap<PlainKey, Option<PlainValue>> {
        index
            .into_iter()
            .map(|v| {
                let salt_val = SaltValue { data: SALT_VALUE_BYTES[v] };
                let key = salt_val.key();
                let value = salt_val.value();
                let address = Address::from_slice(&key[..20]);

                let (plain_key, plain_value) = if key.len() == 20 {
                    (PlainKey::Account(address), Some(PlainValue::Account(Account::default())))
                } else {
                    (
                        PlainKey::Storage(address, B256::from_slice(&key[20..52])),
                        Some(PlainValue::Storage(B256::from_slice(&value).into())),
                    )
                };

                (plain_key, plain_value)
            })
            .collect::<HashMap<_, _>>()
    }

    fn insert_kvs(kvs: HashMap<PlainKey, Option<PlainValue>>, mem_salt: &MemSalt) -> B256 {
        let state_updates = EphemeralSaltState::new(mem_salt).update(&kvs).unwrap();
        state_updates.clone().write_to_store(mem_salt).unwrap();

        let mut trie = StateRoot::new();
        let (root, trie_updates) = trie.update(mem_salt, &state_updates).unwrap();

        trie_updates.write_to_store(mem_salt).unwrap();

        root
    }

    // Array index       [0,1,2,3,4,5,6], [7,8,9]
    // SaltValue in slot [1,2,3,4,5,6,7], [0,1,255] in different bucket
    // to find plain key in SALT_VALUE_BYTES[2], find slot 2, 3
    // to find plain key in SALT_VALUE_BYTES[4], find slot 4, 5
    // to find plain key in SALT_VALUE_BYTES[6], find slot 1,2,3,4,5,6,7
    // to find plain key in SALT_VALUE_BYTES[7], find slot 255,0
    // to find plain key in SALT_VALUE_BYTES[8], find slot 255,0,1
    const SALT_VALUE_BYTES: [[u8; 94]; 10] = [
        [
            52, 32, 48, 1, 62, 32, 116, 157, 191, 48, 139, 176, 173, 251, 201, 192, 82, 146, 212,
            212, 72, 62, 42, 70, 230, 98, 153, 254, 5, 225, 54, 96, 119, 133, 13, 215, 150, 9, 239,
            78, 219, 57, 82, 47, 114, 62, 236, 212, 57, 81, 129, 32, 94, 28, 42, 70, 230, 98, 153,
            254, 5, 225, 54, 96, 119, 133, 13, 215, 150, 9, 239, 78, 219, 57, 82, 47, 114, 62, 236,
            212, 57, 81, 129, 32, 94, 28, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        [
            52, 32, 154, 221, 159, 18, 92, 229, 18, 12, 78, 44, 173, 46, 157, 25, 86, 74, 216, 124,
            123, 179, 73, 164, 70, 136, 156, 92, 251, 144, 116, 127, 24, 118, 238, 22, 158, 125,
            220, 88, 65, 208, 178, 202, 229, 44, 56, 87, 12, 136, 239, 134, 175, 120, 73, 164, 70,
            136, 156, 92, 251, 144, 116, 127, 24, 118, 238, 22, 158, 125, 220, 88, 65, 208, 178,
            202, 229, 44, 56, 87, 12, 136, 239, 134, 175, 120, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        [
            20, 2, 52, 220, 58, 90, 110, 77, 173, 74, 122, 102, 155, 171, 25, 2, 104, 65, 76, 187,
            122, 62, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        [
            52, 32, 164, 97, 20, 34, 94, 46, 59, 72, 254, 212, 177, 227, 38, 87, 20, 201, 80, 119,
            63, 148, 109, 7, 147, 15, 168, 242, 212, 100, 160, 114, 171, 80, 130, 82, 98, 215, 183,
            116, 78, 225, 48, 74, 210, 145, 191, 5, 202, 254, 206, 141, 251, 140, 109, 7, 147, 15,
            168, 242, 212, 100, 160, 114, 171, 80, 130, 82, 98, 215, 183, 116, 78, 225, 48, 74,
            210, 145, 191, 5, 202, 254, 206, 141, 251, 140, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        [
            52, 32, 37, 229, 167, 117, 247, 21, 40, 63, 212, 58, 225, 130, 62, 135, 163, 144, 210,
            234, 213, 243, 231, 221, 164, 152, 71, 179, 252, 229, 81, 170, 6, 206, 191, 153, 67,
            182, 67, 89, 82, 210, 22, 233, 56, 198, 208, 249, 164, 178, 27, 240, 162, 215, 231,
            221, 164, 152, 71, 179, 252, 229, 81, 170, 6, 206, 191, 153, 67, 182, 67, 89, 82, 210,
            22, 233, 56, 198, 208, 249, 164, 178, 27, 240, 162, 215, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        [
            52, 32, 179, 236, 188, 23, 90, 152, 46, 106, 112, 142, 244, 94, 214, 218, 253, 19, 104,
            147, 240, 226, 229, 175, 205, 249, 122, 208, 184, 248, 71, 252, 137, 173, 130, 37, 47,
            60, 197, 229, 225, 64, 209, 91, 80, 107, 188, 104, 249, 49, 219, 252, 212, 177, 229,
            175, 205, 249, 122, 208, 184, 248, 71, 252, 137, 173, 130, 37, 47, 60, 197, 229, 225,
            64, 209, 91, 80, 107, 188, 104, 249, 49, 219, 252, 212, 177, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        [
            52, 32, 2, 13, 181, 123, 127, 242, 138, 79, 226, 65, 186, 108, 10, 174, 161, 222, 31,
            234, 49, 177, 125, 148, 69, 98, 190, 26, 78, 124, 211, 119, 56, 133, 8, 197, 31, 181,
            53, 116, 123, 38, 95, 216, 90, 175, 5, 20, 221, 160, 98, 197, 192, 6, 125, 148, 69, 98,
            190, 26, 78, 124, 211, 119, 56, 133, 8, 197, 31, 181, 53, 116, 123, 38, 95, 216, 90,
            175, 5, 20, 221, 160, 98, 197, 192, 6, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        [
            52, 32, 149, 45, 146, 81, 212, 25, 86, 33, 50, 177, 251, 62, 110, 80, 177, 245, 126,
            152, 112, 52, 48, 128, 16, 227, 225, 129, 23, 220, 122, 36, 0, 26, 162, 51, 114, 163,
            100, 158, 146, 215, 211, 73, 30, 181, 160, 174, 176, 38, 52, 169, 255, 10, 48, 128, 16,
            227, 225, 129, 23, 220, 122, 36, 0, 26, 162, 51, 114, 163, 100, 158, 146, 215, 211, 73,
            30, 181, 160, 174, 176, 38, 52, 169, 255, 10, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        [
            52, 32, 66, 233, 111, 188, 160, 150, 80, 85, 10, 41, 149, 150, 89, 107, 41, 216, 5, 8,
            255, 4, 206, 232, 49, 88, 39, 218, 35, 43, 73, 131, 95, 92, 236, 144, 32, 159, 181,
            216, 21, 171, 177, 129, 249, 202, 223, 90, 237, 11, 55, 229, 229, 12, 206, 232, 49, 88,
            39, 218, 35, 43, 73, 131, 95, 92, 236, 144, 32, 159, 181, 216, 21, 171, 177, 129, 249,
            202, 223, 90, 237, 11, 55, 229, 229, 12, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        [
            52, 32, 159, 161, 59, 17, 118, 13, 243, 71, 32, 130, 21, 45, 24, 198, 214, 98, 137,
            205, 191, 172, 198, 20, 132, 194, 250, 133, 217, 69, 40, 45, 250, 235, 159, 64, 10, 79,
            142, 17, 252, 205, 83, 197, 51, 40, 108, 213, 83, 79, 193, 236, 57, 140, 198, 20, 132,
            194, 250, 133, 217, 69, 40, 45, 250, 235, 159, 64, 10, 79, 142, 17, 252, 205, 83, 197,
            51, 40, 108, 213, 83, 79, 193, 236, 57, 140, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
    ];
}
