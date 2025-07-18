//! This module implements [`StateUpdates`].
use crate::types::{SaltKey, SaltValue};
use derive_more::Deref;
use serde::{Deserialize, Serialize};
use std::collections::{btree_map::Entry, BTreeMap};

/// Records updates to a SALT state (including both prior and new values).
#[derive(Clone, Debug, Deref, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct StateUpdates {
    /// Stores the old and new state values for a slot, formatted as
    /// `(entry_id, (old_entry, new_entry))`.
    /// The `salt_key` is calculated as `bucket_id << 32 + slot_id`.
    #[deref]
    pub data: BTreeMap<SaltKey, (Option<SaltValue>, Option<SaltValue>)>,
}

impl StateUpdates {
    /// Applies another update set atop this one.
    pub fn merge(&mut self, other: &Self) {
        other
            .data
            .iter()
            .for_each(|(k, v)| match self.data.get_mut(k) {
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

    /// Generate the inverse of `StateUpdates`.
    pub fn inverse(mut self) -> Self {
        for (old_value, new_value) in self.data.values_mut() {
            std::mem::swap(old_value, new_value);
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            (
                SaltKey(2),
                (Some(salt_values[1].clone()), Some(salt_values[2].clone())),
            ),
        ];
        let data2 = vec![
            (SaltKey(0), (None, Some(salt_values[0].clone()))),
            (SaltKey(1), (Some(salt_values[1].clone()), None)),
            (
                SaltKey(2),
                (Some(salt_values[2].clone()), Some(salt_values[1].clone())),
            ),
        ];

        let updates1 = StateUpdates {
            data: data1.into_iter().collect(),
        };
        let updates2 = StateUpdates {
            data: data2.into_iter().collect(),
        };
        assert_eq!(updates1.inverse(), updates2);
    }
}
