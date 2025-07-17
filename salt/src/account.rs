//! Compatibility layer for different ethereum implementations.

use alloy_primitives::{B256, U256};

/// Local Account implementation when reth feature is disabled
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Account {
    /// Account nonce.
    pub nonce: u64,
    /// Account balance.
    pub balance: U256,
    /// Account bytecode hash.
    pub bytecode_hash: Option<B256>,
}

impl Account {
    /// Returns true if account is empty.
    pub fn is_empty(&self) -> bool {
        self.balance.is_zero() && self.nonce == 0 && self.bytecode_hash.is_none()
    }
}
