//! This module implements [`TrieUpdates`].
use crate::{traits::TrieWriter, types::CommitmentBytes, NodeId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Records updates to the internal commitment values of a SALT trie.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrieUpdates {
    /// Stores the old and new commitment values of the trie nodes,
    /// formatted as (node_id, (old_commitment, new_commitment)).
    #[serde(serialize_with = "serialize_commitment")]
    #[serde(deserialize_with = "deserialize_commitment")]
    pub data: Vec<(NodeId, (CommitmentBytes, CommitmentBytes))>,
}

impl TrieUpdates {
    /// Writes the trie updates to a data store.
    pub fn write_to_store<Writer: TrieWriter>(
        self,
        writer: &Writer,
    ) -> Result<(), <Writer as TrieWriter>::Error> {
        for (node_id, (_old, new)) in self.data.into_iter() {
            writer.put(node_id, new)?;
        }
        Ok(())
    }

    /// Generate the inverse of `TrieUpdates`.
    pub fn inverse(mut self) -> Self {
        for (_, (old_value, new_value)) in self.data.iter_mut() {
            std::mem::swap(old_value, new_value);
        }
        self
    }
}

fn serialize_commitment<S>(
    data: &Vec<(NodeId, (CommitmentBytes, CommitmentBytes))>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut commit_bytes = Vec::with_capacity(data.len() * 136);
    for (i, (old, new)) in data.iter() {
        commit_bytes.extend_from_slice(&i.to_le_bytes());
        commit_bytes.extend_from_slice(old);
        commit_bytes.extend_from_slice(new);
    }
    serializer.serialize_bytes(&commit_bytes)
}

fn deserialize_commitment<'de, D>(
    deserializer: D,
) -> Result<Vec<(NodeId, (CommitmentBytes, CommitmentBytes))>, D::Error>
where
    D: Deserializer<'de>,
{
    let commit_bytes = Vec::<u8>::deserialize(deserializer)?;
    Ok(commit_bytes
        .chunks_exact(136)
        .map(|chunk| {
            let node_id =
                NodeId::from_le_bytes(chunk[0..8].try_into().expect("Invalid NodeId length"));
            let old_commitment: [u8; 64] =
                chunk[8..72].try_into().expect("Invalid Commitment length");
            let new_commitment: [u8; 64] =
                chunk[72..136].try_into().expect("Invalid Commitment length");
            (node_id, (old_commitment, new_commitment))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::TrieWriter;
    use std::collections::HashMap;

    // Mock TrieWriter for testing
    struct MockTrieWriter {
        data: std::cell::RefCell<HashMap<NodeId, CommitmentBytes>>,
        should_fail: bool,
    }

    impl MockTrieWriter {
        fn new() -> Self {
            Self { data: std::cell::RefCell::new(HashMap::new()), should_fail: false }
        }

        fn with_failure() -> Self {
            Self { data: std::cell::RefCell::new(HashMap::new()), should_fail: true }
        }

        fn get(&self, node_id: NodeId) -> Option<CommitmentBytes> {
            self.data.borrow().get(&node_id).copied()
        }
    }

    impl TrieWriter for MockTrieWriter {
        type Error = String;

        fn put(&self, node_id: NodeId, commitment: CommitmentBytes) -> Result<(), Self::Error> {
            if self.should_fail {
                return Err("Mock error".to_string());
            }
            self.data.borrow_mut().insert(node_id, commitment);
            Ok(())
        }

        fn clear(&self) -> Result<(), Self::Error> {
            if self.should_fail {
                return Err("Mock error".to_string());
            }
            self.data.borrow_mut().clear();
            Ok(())
        }
    }

    #[test]
    fn test_trie_updates_default() {
        let updates = TrieUpdates::default();
        assert!(updates.data.is_empty());
    }

    #[test]
    fn test_trie_updates_clone_and_eq() {
        let node_id = 42u64;
        let old_commitment = [1u8; 64];
        let new_commitment = [2u8; 64];

        let updates = TrieUpdates { data: vec![(node_id, (old_commitment, new_commitment))] };

        let cloned = updates.clone();
        assert_eq!(updates, cloned);
    }

    #[test]
    fn test_write_to_store_success() {
        let node_id1 = 42u64;
        let node_id2 = 84u64;
        let old_commitment1 = [1u8; 64];
        let new_commitment1 = [2u8; 64];
        let old_commitment2 = [3u8; 64];
        let new_commitment2 = [4u8; 64];

        let updates = TrieUpdates {
            data: vec![
                (node_id1, (old_commitment1, new_commitment1)),
                (node_id2, (old_commitment2, new_commitment2)),
            ],
        };

        let writer = MockTrieWriter::new();
        let result = updates.write_to_store(&writer);

        assert!(result.is_ok());
        assert_eq!(writer.get(node_id1), Some(new_commitment1));
        assert_eq!(writer.get(node_id2), Some(new_commitment2));
    }

    #[test]
    fn test_write_to_store_failure() {
        let node_id = 42u64;
        let old_commitment = [1u8; 64];
        let new_commitment = [2u8; 64];

        let updates = TrieUpdates { data: vec![(node_id, (old_commitment, new_commitment))] };

        let writer = MockTrieWriter::with_failure();
        let result = updates.write_to_store(&writer);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Mock error");
    }

    #[test]
    fn test_inverse() {
        let node_id1 = 42u64;
        let node_id2 = 84u64;
        let old_commitment1 = [1u8; 64];
        let new_commitment1 = [2u8; 64];
        let old_commitment2 = [3u8; 64];
        let new_commitment2 = [4u8; 64];

        let updates = TrieUpdates {
            data: vec![
                (node_id1, (old_commitment1, new_commitment1)),
                (node_id2, (old_commitment2, new_commitment2)),
            ],
        };

        let expected_inverse = TrieUpdates {
            data: vec![
                (node_id1, (new_commitment1, old_commitment1)),
                (node_id2, (new_commitment2, old_commitment2)),
            ],
        };

        let inverse = updates.inverse();
        assert_eq!(inverse, expected_inverse);
    }

    #[test]
    fn test_serde_roundtrip() {
        let node_id1 = 42u64;
        let node_id2 = 84u64;
        let old_commitment1 = [1u8; 64];
        let new_commitment1 = [2u8; 64];
        let old_commitment2 = [3u8; 64];
        let new_commitment2 = [4u8; 64];

        let original_updates = TrieUpdates {
            data: vec![
                (node_id1, (old_commitment1, new_commitment1)),
                (node_id2, (old_commitment2, new_commitment2)),
            ],
        };

        // Test JSON serialization/deserialization
        let json = serde_json::to_string(&original_updates).unwrap();
        let deserialized: TrieUpdates = serde_json::from_str(&json).unwrap();
        assert_eq!(original_updates, deserialized);
    }

    #[test]
    fn test_serde_empty() {
        let empty_updates = TrieUpdates::default();

        // Test JSON serialization/deserialization of empty updates
        let json = serde_json::to_string(&empty_updates).unwrap();
        let deserialized: TrieUpdates = serde_json::from_str(&json).unwrap();
        assert_eq!(empty_updates, deserialized);
    }

    #[test]
    fn test_trie_updates_debug() {
        let node_id = 42u64;
        let old_commitment = [1u8; 64];
        let new_commitment = [2u8; 64];

        let updates = TrieUpdates { data: vec![(node_id, (old_commitment, new_commitment))] };

        // Test Debug trait implementation
        let debug_str = format!("{:?}", updates);
        assert!(debug_str.contains("TrieUpdates"));
    }

    #[test]
    fn test_write_to_store_empty() {
        let updates = TrieUpdates::default();
        let writer = MockTrieWriter::new();
        let result = updates.write_to_store(&writer);
        assert!(result.is_ok());
    }

    #[test]
    fn test_clear_functionality() {
        let writer = MockTrieWriter::new();
        let node_id = 42u64;
        let commitment = [1u8; 64];

        // Put some data first
        writer.put(node_id, commitment).unwrap();
        assert_eq!(writer.get(node_id), Some(commitment));

        // Clear and verify it's gone
        writer.clear().unwrap();
        assert_eq!(writer.get(node_id), None);
    }

    #[test]
    fn test_clear_failure() {
        let writer = MockTrieWriter::with_failure();
        let result = writer.clear();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Mock error");
    }
}
