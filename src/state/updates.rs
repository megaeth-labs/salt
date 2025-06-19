//! This module implements [`StateUpdates`].
use crate::{
    compute_xor,
    constant::NUM_META_BUCKETS,
    traits::*,
    types::{BucketMeta, Buckets, SaltKey, SaltValue, SaltValueDelta},
    BucketId, PlainKey, PlainValue, MAX_SALT_VALUE_BYTES,
};
use alloy_primitives::{
    private::alloy_rlp::{Decodable, Encodable},
    BlockNumber,
};
use bytes::BufMut;
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
#[cfg(feature = "reth")]
use reth_codecs::{decode_varuint, encode_varuint, Compact};
use serde::{Deserialize, Serialize};
use std::{
    collections::{btree_map::Entry, BTreeMap},
    fmt,
};

/// Records updates to a SALT state (including both prior and new values).
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct StateUpdates {
    /// Stores the old and new state values for a slot, formatted as
    /// `(entry_id, (old_entry, new_entry))`.
    /// The `salt_key` is calculated as `bucket_id << 32 + slot_id`.
    pub data: BTreeMap<SaltKey, (Option<SaltValue>, Option<SaltValue>)>,
}

impl fmt::Display for StateUpdates {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "StateUpdates {{")?;

        for (salt_key, (old_value, new_value)) in &self.data {
            writeln!(
                f,
                "  Entry(bucket: {}, slot: {}) {{",
                salt_key.bucket_id(),
                salt_key.slot_id()
            )?;

            // Helper closure to format SaltValue
            let format_value = |value: &Option<SaltValue>| -> String {
                match value {
                    Some(salt_value) => {
                        // Convert SaltValue to (PlainKey, PlainValue)
                        let (plain_key, plain_value) = salt_value.into();
                        match (plain_key, plain_value) {
                            (PlainKey::Account(addr), PlainValue::Account(account)) => {
                                format!(
                                    "Account({:?}) => balance: {}, nonce: {}, code_hash: {:?}",
                                    addr, account.balance, account.nonce, account.bytecode_hash
                                )
                            }
                            (PlainKey::Storage(addr, key), PlainValue::Storage(value)) => {
                                format!(
                                    "Storage(addr: {:?}, key: {:?}) => value: {}",
                                    addr, key, value
                                )
                            }
                            _ => "Invalid state conversion".to_string(),
                        }
                    }
                    None => "None".to_string(),
                }
            };

            writeln!(f, "    old: {}", format_value(old_value))?;
            writeln!(f, "    new: {}", format_value(new_value))?;
            writeln!(f, "  }}")?;
        }

        write!(f, "}}")
    }
}

impl StateUpdates {
    /// Write the state updates to the backing store.
    pub fn write_to_store<Writer: StateWriter>(
        self,
        writer: &Writer,
    ) -> Result<(), <Writer as BucketMetadataReader>::Error> {
        writer.update(self)
    }

    /// Applies another update set atop this one.
    pub fn merge(&mut self, other: &Self) {
        other.data.iter().for_each(|(k, v)| match self.data.get_mut(k) {
            Some(slot_val) => {
                if slot_val.0 == v.1 {
                    // If the new value is the same as the old value, do not merge and remove the
                    // entry here.
                    self.data.remove(k);
                } else {
                    let _ = std::mem::replace(&mut slot_val.1, v.1.clone());
                }
            }
            None => {
                self.data.insert(*k, v.clone());
            }
        });
    }

    /// Adds a new updated entry to the state changes.
    pub fn add(
        &mut self,
        entry_id: SaltKey,
        old_entry: Option<SaltValue>,
        new_entry: Option<SaltValue>,
    ) {
        match self.data.entry(entry_id) {
            Entry::Occupied(mut entry) => {
                if entry.get().0 == new_entry {
                    entry.remove();
                } else {
                    entry.get_mut().1 = new_entry;
                }
            }
            Entry::Vacant(entry) => {
                entry.insert((old_entry, new_entry));
            }
        }
    }

    /// Represent the given SALT state of a bucket range as a [`StateUpdates`] over the empty state.
    pub fn from_buckets(buckets: &Buckets) -> Self {
        let mut state_updates = Self::default();
        buckets.0.iter().for_each(|(key, value)| {
            // filter out the zero meta slot
            if key.bucket_id() >= NUM_META_BUCKETS as BucketId ||
                BucketMeta::from(value) != BucketMeta::default()
            {
                let old_val = if key.bucket_id() >= NUM_META_BUCKETS as BucketId {
                    None
                } else {
                    Some(BucketMeta::default().into())
                };
                state_updates.data.insert(*key, (old_val, Some(value.clone())));
            }
        });
        state_updates
    }

    /// Generate the inverse of `StateUpdates`.
    pub fn inverse(mut self) -> Self {
        for (old_value, new_value) in self.data.values_mut() {
            std::mem::swap(old_value, new_value);
        }
        self
    }
}

/// Changes in SaltState after each block execution.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SaltDeltas {
    /// List of key-value pairs to be inserted.
    pub puts: BTreeMap<SaltKey, SaltValue>,
    /// List of keys to be deleted.
    pub deletes: BTreeMap<SaltKey, SaltValue>,
    /// List of key-value pairs to be updated.
    pub updates: BTreeMap<SaltKey, SaltValueDelta>,
}

impl From<&StateUpdates> for SaltDeltas {
    fn from(updates: &StateUpdates) -> Self {
        let mut result = Self::default();

        let mut state_update = Vec::with_capacity(updates.data.len());
        updates.data.iter().for_each(|(key, value)| match value {
            (Some(_), Some(_)) => {
                state_update.push((key, value));
            }
            (None, Some(new)) => {
                result.puts.insert(*key, new.clone());
            }
            (Some(old), None) => {
                result.deletes.insert(*key, old.clone());
            }
            _ => {}
        });

        // use rayon calc SaltDelta concurrent
        let state_updates: BTreeMap<SaltKey, SaltValueDelta> = state_update
            .into_par_iter()
            .filter_map(|(key, value)| match value {
                (Some(ref old), Some(ref new)) => Some((*key, SaltValueDelta::new(old, new))),
                _ => None,
            })
            .collect();

        result.updates = state_updates;
        result
    }
}

impl SaltDeltas {
    /// Check whether the `SaltDeltas` is empty.
    pub fn is_empty(&self) -> bool {
        self.puts.is_empty() && self.deletes.is_empty() && self.updates.is_empty()
    }

    /// Read the SALT value deltas from a (persistent) data store.
    pub fn read_from_store<Reader: SaltChangeReader>(
        block_number: BlockNumber,
        reader: &Reader,
    ) -> Result<Self, Reader::Error> {
        reader.read_changesets(block_number)
    }

    /// Write the SALT value deltas to a (persistent) data store.
    pub fn write_to_store<Writer: SaltChangeWriter>(
        self,
        block_number: BlockNumber,
        writer: &Writer,
    ) -> Result<(), Writer::Error> {
        writer.write_changesets(block_number, self)
    }

    /// Use the SALT value deltas to update the state in a (persistent) data store.
    pub fn apply_to_state<Writer: StateWriter>(
        self,
        writer: &Writer,
    ) -> Result<(), <Writer as BucketMetadataReader>::Error> {
        writer.apply_changesets(self)
    }

    /// Generate the inverse of SaltDeltas.
    pub fn inverse(self) -> Self {
        let Self { puts, deletes, updates } = self;
        Self { puts: deletes, deletes: puts, updates }
    }
}

#[cfg(feature = "reth")]
impl Compact for SaltDeltas {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        let mut len = 0;
        len += encode_varuint(self.puts.len(), buf);
        self.puts.iter().for_each(|(key, value)| {
            len += key.to_compact(buf);
            len += value.to_compact(buf);
        });

        len += encode_varuint(self.deletes.len(), buf);
        self.deletes.iter().for_each(|(key, value)| {
            len += key.to_compact(buf);
            len += value.to_compact(buf);
        });

        len += encode_varuint(self.updates.len(), buf);
        self.updates.iter().for_each(|(key, value)| {
            len += key.to_compact(buf);
            len += value.to_compact(buf);
        });
        len
    }

    fn from_compact(buf: &[u8], _len: usize) -> (Self, &[u8]) {
        let (puts_len, mut buf) = decode_varuint(buf);
        let mut puts = BTreeMap::new();
        for _ in 0..puts_len {
            let (key, rest) = SaltKey::from_compact(buf, buf.len());
            let (value, rest) = SaltValue::from_compact(rest, rest.len());
            puts.insert(key, value);
            buf = rest;
        }

        let (deletes_len, mut buf) = decode_varuint(buf);
        let mut deletes = BTreeMap::new();
        for _ in 0..deletes_len {
            let (key, rest) = SaltKey::from_compact(buf, buf.len());
            let (value, rest) = SaltValue::from_compact(rest, rest.len());
            deletes.insert(key, value);
            buf = rest;
        }

        let (updates_len, mut buf) = decode_varuint(buf);
        let mut updates = BTreeMap::new();
        for _ in 0..updates_len {
            let (key, rest) = SaltKey::from_compact(buf, buf.len());
            let (value, rest) = SaltValueDelta::from_compact(rest, rest.len());
            updates.insert(key, value);
            buf = rest;
        }

        (Self { puts, deletes, updates }, buf)
    }
}

impl Encodable for SaltDeltas {
    fn encode(&self, out: &mut dyn BufMut) {
        self.puts.len().encode(out);
        for (put_key, put_value) in &self.puts {
            put_key.0.encode(out);
            put_value.data.encode(out);
        }
        self.deletes.len().encode(out);
        for (deleted_key, deleted_value) in &self.deletes {
            deleted_key.0.encode(out);
            deleted_value.data.encode(out);
        }
        self.updates.len().encode(out);
        for (key, delta) in &self.updates {
            key.0.encode(out);
            delta.0.encode(out);
        }
    }

    fn length(&self) -> usize {
        let mut length =
            self.puts.len().length() + self.deletes.len().length() + self.updates.len().length();
        for (key, value) in &self.puts {
            length += key.0.length() + value.data.length();
        }
        for (key, value) in &self.deletes {
            length += key.0.length() + value.data.length();
        }
        for (key, value) in &self.updates {
            length += key.0.length() + value.length();
        }
        length
    }
}

impl Decodable for SaltDeltas {
    fn decode(buf: &mut &[u8]) -> alloy_primitives::private::alloy_rlp::Result<Self> {
        let put_len = usize::decode(buf)?;
        let mut puts = BTreeMap::default();
        for _ in 0..put_len {
            let key = SaltKey(u64::decode(buf)?);
            let data = <[u8; MAX_SALT_VALUE_BYTES]>::decode(buf)?;
            puts.insert(key, SaltValue { data });
        }
        let deleted_len = usize::decode(buf)?;
        let mut deletes = BTreeMap::default();
        for _ in 0..deleted_len {
            let key = SaltKey(u64::decode(buf)?);
            let data = <[u8; MAX_SALT_VALUE_BYTES]>::decode(buf)?;
            deletes.insert(key, SaltValue { data });
        }
        let updated_len = usize::decode(buf)?;
        let mut updates = BTreeMap::default();
        for _ in 0..updated_len {
            let key = SaltKey(u64::decode(buf)?);
            let delta = SaltValueDelta(Vec::<u8>::decode(buf)?);
            updates.insert(key, delta);
        }
        Ok(Self { puts, deletes, updates })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        compat::Account,
        mem_salt::*,
        state::{state::EphemeralSaltState, updates::StateUpdates},
        types::{compute_xor, PlainKey, PlainValue},
    };
    use alloy_primitives::{Address, B256, U256};
    use reth_codecs::Compact;
    use std::collections::HashMap;

    #[test]
    fn state_updates_merge() {
        let mut updates = StateUpdates::default();
        let mut other = StateUpdates::default();

        let salt_array = [
            Some(SaltValue::new(&[1u8; 32], &[1u8; 32])),
            Some(SaltValue::new(&[2u8; 32], &[1u8; 32])),
            Some(SaltValue::new(&[3u8; 32], &[1u8; 32])),
        ];

        let entry_id0 = (1, 1).into();
        let entry_id1 = (2, 2).into();
        let entry_id2 = (3, 3).into();

        updates.add(entry_id0, salt_array[0].clone(), None);
        updates.add(entry_id1, salt_array[1].clone(), None);
        other.add(entry_id0, None, salt_array[1].clone());
        other.add(entry_id2, None, salt_array[2].clone());

        updates.merge(&other);

        assert_eq!(
            updates.data.get(&entry_id0).unwrap().clone(),
            (salt_array[0].clone(), salt_array[1].clone()),
            "The new entry for slot 1 in table 1 should be (Some((key_array[0],val)), Some((key_array[1],val)))"
        );

        assert_eq!(
            updates.data.get(&entry_id1).unwrap().clone(),
            (salt_array[1].clone(), None),
            "The new entry for slot 2 in table 2 should be (Some((key_array[1],val)), None)"
        );

        assert_eq!(
            updates.data.get(&entry_id2).unwrap().clone(),
            (None, salt_array[2].clone()),
            "The new entry for slot 3 in table 3 should be (None, Some((key_array[2], val)))"
        );
    }

    #[test]
    fn state_updates_reverse_work() {
        let salt_values = [
            SaltValue::new(&[1u8; 32], &[1u8; 32]),
            SaltValue::new(&[2u8; 32], &[2u8; 32]),
            SaltValue::new(&[3u8; 32], &[3u8; 32]),
        ];

        let data1 = vec![
            (SaltKey(0), (Some(salt_values[0].clone()), None)),
            (SaltKey(1), (None, Some(salt_values[1].clone()))),
            (SaltKey(2), (Some(salt_values[1].clone()), Some(salt_values[2].clone()))),
        ];
        let data2 = vec![
            (SaltKey(0), (None, Some(salt_values[0].clone()))),
            (SaltKey(1), (Some(salt_values[1].clone()), None)),
            (SaltKey(2), (Some(salt_values[2].clone()), Some(salt_values[1].clone()))),
        ];

        let updates1 = StateUpdates { data: data1.into_iter().collect() };
        let updates2 = StateUpdates { data: data2.into_iter().collect() };
        assert_eq!(updates1.inverse(), updates2);
    }

    #[test]
    fn salt_change_sets_work() {
        // Randomly generate some Plain{Key|Value} data.
        let addresses: Vec<Address> = (0..5).map(|_| Address::random()).collect();
        let account1 = Account { balance: U256::from(10), ..Default::default() };
        let account2 = Account { balance: U256::from(100), ..Default::default() };
        let (slot1, storage_value1) = (B256::random(), B256::random());
        let (slot2, storage_value2) = (B256::random(), B256::random());
        let mock_db1 = MemSalt::new();
        let mock_db2 = MemSalt::new();

        let kvs1: HashMap<PlainKey, Option<PlainValue>> = vec![
            (PlainKey::Account(addresses[0]), Some(PlainValue::Account(account1))),
            (PlainKey::Account(addresses[1]), Some(PlainValue::Account(account2))),
            (
                PlainKey::Storage(addresses[3], slot1),
                Some(PlainValue::Storage(storage_value2.into())),
            ),
            (
                PlainKey::Storage(addresses[4], slot2),
                Some(PlainValue::Storage(storage_value1.into())),
            ),
        ]
        .into_iter()
        .collect();

        let kvs2: HashMap<PlainKey, Option<PlainValue>> = vec![
            (PlainKey::Account(addresses[1]), Some(PlainValue::Account(Account::default()))),
            (PlainKey::Account(addresses[2]), Some(PlainValue::Account(account2))),
            (
                PlainKey::Storage(addresses[3], slot1),
                Some(PlainValue::Storage(storage_value1.into())),
            ),
            (
                PlainKey::Storage(addresses[4], slot2),
                Some(PlainValue::Storage(storage_value2.into())),
            ),
        ]
        .into_iter()
        .collect();
        // Insert kvs1, empty -> state1
        let state_updates1 = EphemeralSaltState::new(&mock_db1).update(&kvs1).unwrap();
        state_updates1.clone().write_to_store(&mock_db1).unwrap();
        state_updates1.write_to_store(&mock_db2).unwrap();
        // Using `range_bucket` would require accessing many invalid keys, resulting in slow
        // retrieval. Therefore, `get_all` is used instead.
        let state1 = mock_db1.get_all();

        // Insert kvs2, state1 -> state2
        let state_updates2 = EphemeralSaltState::new(&mock_db2).update(&kvs2).unwrap();
        state_updates2.clone().write_to_store(&mock_db2).unwrap();
        let state2 = mock_db2.get_all();

        // Get salt_changes
        let salt_changes = SaltDeltas::from(&state_updates2);

        // state2 xor salt_changes -> state1
        let mut recover_state: HashMap<SaltKey, SaltValue> = state2.clone().into_iter().collect();
        for (key, _) in salt_changes.puts.clone() {
            recover_state.remove(&key);
        }
        for (key, value) in salt_changes.deletes.clone() {
            recover_state.insert(key, value);
        }
        for (key, SaltValueDelta(delta)) in salt_changes.updates.clone() {
            let new_salt_value = recover_state.get(&key).unwrap();
            let new_value_slice = &new_salt_value.data;
            let old_value_slice = compute_xor(new_value_slice, &delta);
            let value = SaltValue::from_compact(&old_value_slice, old_value_slice.len()).0;
            recover_state.insert(key, value);
        }
        let state1: HashMap<SaltKey, SaltValue> = state1.into_iter().collect();
        for (key, value) in state1.iter() {
            assert_eq!(recover_state.get(key), Some(value));
        }

        // state1 oxr salt_changes -> state2
        let mut recover_state: HashMap<SaltKey, SaltValue> = state1.clone().into_iter().collect();
        for (key, value) in salt_changes.puts.clone() {
            recover_state.insert(key, value);
        }
        for (key, SaltValueDelta(salt_delta)) in salt_changes.updates.clone() {
            // Because the default meta slot is not stored in state1,
            // But mock_db1 entry function will return default meta slot
            let old_salt_value = mock_db1.entry(key).unwrap().unwrap();
            let old_value_slice = &old_salt_value.data;
            let new_value_slice = compute_xor(old_value_slice, &salt_delta);
            let new_salt_value = SaltValue::from_compact(&new_value_slice, new_value_slice.len()).0;
            recover_state.insert(key, new_salt_value);
        }
        for (key, _) in salt_changes.deletes.clone() {
            recover_state.remove(&key);
        }
        let state2: HashMap<SaltKey, SaltValue> = state2.into_iter().collect();
        assert_eq!(state2, recover_state);
    }

    #[test]
    fn merge_salt_deltas_with_delete_and_put() {
        let key = SaltKey(31641792868778020);
        let old_value = SaltValue {
            data: [
                52, 32, 154, 46, 95, 247, 175, 91, 18, 199, 141, 252, 115, 230, 157, 177, 27, 33,
                71, 203, 46, 206, 190, 218, 163, 76, 251, 78, 132, 112, 38, 66, 126, 14, 131, 94,
                255, 123, 12, 93, 212, 253, 92, 193, 95, 99, 14, 204, 255, 64, 64, 171, 72, 130, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 90, 114, 127, 155, 173, 252, 24, 23, 106, 61, 34,
                29, 187, 132, 153, 39, 154, 97, 238, 39, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        };
        let new_value = SaltValue {
            data: [
                52, 32, 154, 46, 95, 247, 175, 91, 18, 199, 141, 252, 115, 230, 157, 177, 27, 33,
                71, 203, 46, 206, 190, 218, 163, 76, 251, 78, 132, 112, 38, 66, 126, 14, 131, 94,
                255, 123, 12, 93, 212, 253, 92, 193, 95, 99, 14, 204, 255, 64, 64, 171, 72, 130, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 78, 227, 255, 65, 88, 79, 219, 32, 40, 229, 255,
                90, 21, 161, 152, 183, 37, 136, 79, 247, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        };
        let mut d1 =
            SaltDeltas { deletes: BTreeMap::from([(key, old_value)]), ..Default::default() };
        let d2 = SaltDeltas { puts: BTreeMap::from([(key, new_value)]), ..Default::default() };
        d1.merge(&d2);
        assert_eq!(d1.updates.len(), 1);
        assert_eq!(
            d1.updates.get(&key).unwrap().0,
            [
                20, 145, 128, 218, 245, 179, 195, 55, 66, 216, 221, 71, 174, 37, 1, 144, 191, 233,
                161, 208, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
    }
}
