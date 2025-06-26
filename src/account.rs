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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_is_empty() {
        // Test empty account (default)
        let empty_account = Account::default();
        assert!(empty_account.is_empty());

        // Test account with nonce but zero balance and no bytecode
        let account_with_nonce = Account { nonce: 1, balance: U256::ZERO, bytecode_hash: None };
        assert!(!account_with_nonce.is_empty());

        // Test account with balance but zero nonce and no bytecode
        let account_with_balance =
            Account { nonce: 0, balance: U256::from(100), bytecode_hash: None };
        assert!(!account_with_balance.is_empty());

        // Test account with bytecode hash but zero nonce and balance
        let account_with_bytecode =
            Account { nonce: 0, balance: U256::ZERO, bytecode_hash: Some(B256::default()) };
        assert!(!account_with_bytecode.is_empty());

        // Test account with all fields set
        let full_account =
            Account { nonce: 1, balance: U256::from(100), bytecode_hash: Some(B256::default()) };
        assert!(!full_account.is_empty());
    }

    #[test]
    fn test_account_creation() {
        // Test creating account with specific values
        let account = Account {
            nonce: 42,
            balance: U256::from(1000),
            bytecode_hash: Some(B256::repeat_byte(0x42)),
        };

        assert_eq!(account.nonce, 42);
        assert_eq!(account.balance, U256::from(1000));
        assert_eq!(account.bytecode_hash, Some(B256::repeat_byte(0x42)));
        assert!(!account.is_empty());
    }

    #[test]
    fn test_account_traits() {
        let account1 = Account { nonce: 1, balance: U256::from(100), bytecode_hash: None };

        let account2 = account1; // Test Copy trait
        assert_eq!(account1, account2); // Test PartialEq trait

        let account3 = account1.clone(); // Test Clone trait
        assert_eq!(account1, account3);

        // Test Debug trait (just ensure it doesn't panic)
        let _debug_str = format!("{:?}", account1);
    }
}
