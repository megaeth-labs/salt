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
