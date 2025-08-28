//! Tracks state changes in SALT with before/after values for atomic updates and rollbacks.
use crate::types::{SaltKey, SaltValue};
use derive_more::Deref;
use hex;
use serde::{Deserialize, Serialize};
use std::{
    collections::{btree_map::Entry, BTreeMap},
    fmt,
};

/// Tracks state changes as (old, new) value pairs for atomic updates and rollbacks.
///
/// Automatically deduplicates no-op changes where old equals new.
#[derive(Clone, Debug, Deref, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct StateUpdates {
    /// Maps keys to (old_value, new_value) pairs. None indicates absence/deletion.
    #[deref]
    pub data: BTreeMap<SaltKey, (Option<SaltValue>, Option<SaltValue>)>,
}

impl StateUpdates {
    /// Records a state change for a key, maintaining transition chaining.
    ///
    /// For new keys, creates an entry tracking the change from `old_value` to `new_value`.
    /// For existing keys, chains the transition by preserving the original old value
    /// while updating to the new value. No-op entries are removed automatically.
    ///
    /// # Arguments
    /// * `salt_key` - The key to update
    /// * `old_value` - The expected current value
    /// * `new_value` - The new value to set
    ///
    /// # Panics
    /// Panics if transitions don't chain properly, i.e., if for any key that exists
    /// in both `self` and `other`, the old_value in `other` doesn't match the
    /// new_value in `self`.
    pub fn add(
        &mut self,
        salt_key: SaltKey,
        old_value: Option<SaltValue>,
        new_value: Option<SaltValue>,
    ) {
        match self.data.entry(salt_key) {
            Entry::Occupied(mut change) => {
                assert_eq!(old_value, change.get().1, "Invalid state transition");
                if change.get().0 == new_value {
                    change.remove();
                } else {
                    change.get_mut().1 = new_value;
                }
            }
            Entry::Vacant(change) => {
                if old_value != new_value {
                    change.insert((old_value, new_value));
                }
            }
        };
    }

    /// Merges another set of state updates into this one, chaining transitions
    /// correctly.
    ///
    /// Logically equivalent to applying `add()` for each entry in `other`.
    pub fn merge(&mut self, other: Self) {
        for (key, (old_val, new_val)) in other.data {
            self.add(key, old_val, new_val);
        }
    }

    /// Creates inverse state updates by swapping old and new values for rollback
    /// operations.
    ///
    /// This method consumes `self` and returns a new `StateUpdates` where each
    /// (old, new) pair becomes (new, old). This is useful for creating rollback
    /// operations that can undo the changes represented by these updates.
    ///
    /// # Returns
    /// A new `StateUpdates` with all value pairs swapped
    pub fn inverse(mut self) -> Self {
        self.data
            .values_mut()
            .for_each(|(old, new)| std::mem::swap(old, new));
        self
    }
}

/// Formats updates for debugging, showing bucket/slot IDs and key/value hex.
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
            let fmt_val = |v: &Option<SaltValue>| match v {
                Some(salt_val) => format!(
                    "key:{:?} value:{:?}",
                    hex::encode(salt_val.key()),
                    hex::encode(salt_val.value())
                ),
                None => "None".to_string(),
            };
            writeln!(
                f,
                "    old: {}\n    new: {}\n  }}",
                fmt_val(old_value),
                fmt_val(new_value)
            )?;
        }
        write!(f, "}}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create test SaltValues with different patterns.
    fn test_salt_value(pattern: u8) -> SaltValue {
        SaltValue::new(&[pattern; 32], &[pattern; 32])
    }

    /// Tests all add() method operations.
    ///
    /// Scenarios tested:
    /// - Adding new entry to empty updates (None → Some)
    /// - Chaining updates preserves original old value
    /// - Deletion that results in no-op (reverting to original state)
    /// - No-op detection for None → None transitions
    #[test]
    fn test_add_operations() {
        let mut updates = StateUpdates::default();
        let [v1, v2] = [test_salt_value(1), test_salt_value(2)];
        let key = SaltKey(0);

        // None → v1 → v2 (chaining preserves original)
        updates.add(key, None, Some(v1.clone()));
        assert_eq!(updates.data[&key], (None, Some(v1.clone())));
        updates.add(key, Some(v1.clone()), Some(v2.clone()));
        assert_eq!(updates.data[&key], (None, Some(v2.clone())));

        // Revert to original (v2 → None) creates no-op
        updates.add(key, Some(v2), None);
        assert!(updates.data.is_empty());

        // None → None is filtered out
        updates.add(key, None, None);
        assert!(updates.data.is_empty());
    }

    /// Tests that add() panics when transitions don't chain properly.
    ///
    /// Scenarios tested:
    /// - Adding v1 → v2 transition chain
    /// - Attempting to add v3 → v1 when current state is v2 (should panic)
    /// - Validates assertion error for non-matching transition chains
    #[test]
    #[should_panic(expected = "Invalid state transition")]
    fn test_add_panics_on_non_chaining() {
        let mut updates = StateUpdates::default();
        let [v1, v2, v3] = [test_salt_value(1), test_salt_value(2), test_salt_value(3)];
        let key = SaltKey(0);

        // First add: v1 → v2
        updates.add(key, Some(v1.clone()), Some(v2));

        // Try to add non-chaining transition: v3 → v1 (should panic)
        updates.add(key, Some(v3), Some(v1));
    }

    /// Tests all merge operations.
    ///
    /// Scenarios tested:
    /// - Basic merge with chaining transitions
    /// - Merging with empty updates (no-op)
    /// - Complex chaining: None → v1 → v2 → v3 results in None → v3
    #[test]
    fn test_merge_operations() {
        let mut updates = StateUpdates::default();
        let [v1, v2, v3] = [test_salt_value(1), test_salt_value(2), test_salt_value(3)];
        let key = SaltKey(0);

        // Basic merge with chaining
        updates.add(key, None, Some(v1.clone()));
        let mut other = StateUpdates::default();
        other.add(key, Some(v1.clone()), Some(v2.clone()));
        updates.merge(other);
        assert_eq!(updates.data[&key], (None, Some(v2.clone())));

        // Merge with empty (no-op)
        let len_before = updates.data.len();
        updates.merge(StateUpdates::default());
        assert_eq!(updates.data.len(), len_before);

        // Chain multiple transitions: v2 → v3
        let mut chain = StateUpdates::default();
        chain.add(key, Some(v2.clone()), Some(v3.clone()));
        updates.merge(chain);
        assert_eq!(updates.data[&key], (None, Some(v3.clone())));
    }

    /// Tests inverse operations.
    ///
    /// Scenarios tested:
    /// - Basic inverse swapping: (old, new) becomes (new, old)
    /// - Double inverse reversibility: inverse(inverse(x)) == x
    #[test]
    fn test_inverse_operations() {
        let mut updates = StateUpdates::default();
        let [v1, v2] = [test_salt_value(1), test_salt_value(2)];
        let key = SaltKey(0);

        // Create a transition: None -> v1 -> v2
        updates.add(key, None, Some(v1.clone()));
        updates.add(key, Some(v1), Some(v2.clone()));

        // Test inverse swapping
        let inverse = updates.clone().inverse();
        assert_eq!(inverse.data[&key], (Some(v2.clone()), None));

        // Test double inverse equals original
        assert_eq!(updates, inverse.inverse());
    }
}
