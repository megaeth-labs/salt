//! This module implements [`TrieUpdates`].
use crate::{types::CommitmentBytes, NodeId};
use derive_more::Deref;
/// Records updates to the internal commitment values of a SALT trie.
#[derive(Debug, Default, Deref, Clone, PartialEq, Eq)]
pub struct TrieUpdates {
    /// Stores the old and new commitment values of the trie nodes,
    /// formatted as (`node_id`, (`old_commitment`, `new_commitment`)).
    #[deref]
    pub data: Vec<(NodeId, (CommitmentBytes, CommitmentBytes))>,
}
