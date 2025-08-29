//! This module implements [`TrieUpdates`].
use crate::{types::CommitmentBytes, NodeId};
use derive_more::Deref;
use serde::{Deserialize, Serialize};

/// Records updates to the internal commitment values of a SALT trie.
#[derive(Debug, Default, Deref, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrieUpdates {
    /// Stores the old and new commitment values of the trie nodes,
    /// formatted as (`node_id`, (`old_commitment`, `new_commitment`)).
    #[deref]
    pub data: Vec<(NodeId, (CommitmentBytes, CommitmentBytes))>,
}
