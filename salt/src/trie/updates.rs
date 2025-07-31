//! This module implements [`TrieUpdates`].
use crate::{types::CommitmentBytes, NodeId};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
/// Records updates to the internal commitment values of a SALT trie.
#[serde_as]
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrieUpdates {
    /// Stores the old and new commitment values of the trie nodes,
    /// formatted as (`node_id`, (`old_commitment`, `new_commitment`)).
    #[serde_as(as = "Vec<(_, (Bytes, Bytes))>")]
    pub data: Vec<(NodeId, (CommitmentBytes, CommitmentBytes))>,
}
