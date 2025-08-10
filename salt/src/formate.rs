//! This is a module that provides a simple test implementation of the SALT
use alloy_primitives::{Address, B256, U256};

/// data length of Key of Storage Slot
const SLOT_KEY_LEN: usize = B256::len_bytes();
/// data length of Key of Account
const PLAIN_ACCOUNT_KEY_LEN: usize = Address::len_bytes();
/// data length of Key of Storage
const PLAIN_STORAGE_KEY_LEN: usize = PLAIN_ACCOUNT_KEY_LEN + SLOT_KEY_LEN;

const U64_BYTES_LEN: usize = 8;
const BALANCE_BYTES_LEN: usize = U256::BYTES;
/// data length of Value of Account(Contract)
const PLAIN_EOA_ACCOUNT_LEN: usize = U64_BYTES_LEN + BALANCE_BYTES_LEN;
/// data length of Value of Account(EOA)
const PLAIN_CONTRACT_ACCOUNT_LEN: usize = PLAIN_EOA_ACCOUNT_LEN + B256::len_bytes();
/// data length of Value of Storage
const PLAIN_STORAGE_LEN: usize = U256::BYTES;

/// Key of PlainAccount/StorageState.
#[derive(Hash, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PlainKey {
    /// Key of plainAccountState.
    Account(Address),
    /// Key of plainStorageState: (address,  storage slot).
    Storage(Address, B256),
}

impl PlainKey {
    /// Convert PlainKey to Vec.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            PlainKey::Account(addr) => addr.as_slice().to_vec(),
            PlainKey::Storage(addr, slot) => addr
                .concat_const::<SLOT_KEY_LEN, PLAIN_STORAGE_KEY_LEN>(*slot)
                .as_slice()
                .to_vec(),
        }
    }

    /// Decode Vec to PlainKey.
    pub fn decode(buf: &[u8]) -> Self {
        match buf.len() {
            PLAIN_ACCOUNT_KEY_LEN => PlainKey::Account(Address::from_slice(buf)),
            PLAIN_STORAGE_KEY_LEN => {
                let addr = Address::from_slice(&buf[..PLAIN_ACCOUNT_KEY_LEN]);
                let slot_id = B256::from_slice(&buf[PLAIN_ACCOUNT_KEY_LEN..]);
                PlainKey::Storage(addr, slot_id)
            }
            _ => unreachable!("unexpected length of plain key."),
        }
    }
}

impl From<Address> for PlainKey {
    #[inline]
    fn from(addr: Address) -> Self {
        PlainKey::Account(addr)
    }
}

impl From<(Address, B256)> for PlainKey {
    #[inline]
    fn from((addr, storage): (Address, B256)) -> Self {
        PlainKey::Storage(addr, storage)
    }
}

/// Value of PlainAccount/StorageState.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlainValue {
    /// If Account is empty, means the account should be deleted.
    Account(Account),
    /// Value of plainStorageState.
    Storage(U256),
}

impl PlainValue {
    /// Convert PlainValue to Vec.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            PlainValue::Account(account) => {
                let mut buffer = [0; PLAIN_CONTRACT_ACCOUNT_LEN];
                buffer[..U64_BYTES_LEN].copy_from_slice(account.nonce.to_be_bytes().as_ref());
                buffer[U64_BYTES_LEN..PLAIN_EOA_ACCOUNT_LEN]
                    .copy_from_slice(account.balance.to_be_bytes::<BALANCE_BYTES_LEN>().as_ref());
                if let Some(bytecode_hash) = account.bytecode_hash {
                    buffer[PLAIN_EOA_ACCOUNT_LEN..PLAIN_CONTRACT_ACCOUNT_LEN]
                        .copy_from_slice(bytecode_hash.as_slice());
                    buffer.to_vec()
                } else {
                    buffer[..PLAIN_EOA_ACCOUNT_LEN].to_vec()
                }
            }
            PlainValue::Storage(value) => value.to_be_bytes::<PLAIN_STORAGE_LEN>().to_vec(),
        }
    }

    /// Decode Vec to PlainValue.
    pub fn decode(buf: &[u8]) -> Self {
        match buf.len() {
            PLAIN_EOA_ACCOUNT_LEN => {
                let nonce = u64::from_be_bytes(buf[..U64_BYTES_LEN].try_into().unwrap());
                let balance = U256::from_be_slice(&buf[U64_BYTES_LEN..PLAIN_EOA_ACCOUNT_LEN]);
                PlainValue::Account(Account {
                    nonce,
                    balance,
                    bytecode_hash: None,
                })
            }
            PLAIN_CONTRACT_ACCOUNT_LEN => {
                let nonce = u64::from_be_bytes(buf[..U64_BYTES_LEN].try_into().unwrap());
                let balance = U256::from_be_slice(&buf[U64_BYTES_LEN..PLAIN_EOA_ACCOUNT_LEN]);
                let bytecode_hash =
                    B256::from_slice(&buf[PLAIN_EOA_ACCOUNT_LEN..PLAIN_CONTRACT_ACCOUNT_LEN]);
                PlainValue::Account(Account {
                    nonce,
                    balance,
                    bytecode_hash: Some(bytecode_hash),
                })
            }
            PLAIN_STORAGE_LEN => PlainValue::Storage(U256::from_be_slice(buf)),
            _ => unreachable!("unexpected length of plain value."),
        }
    }
}

impl From<Account> for PlainValue {
    #[inline]
    fn from(account: Account) -> Self {
        PlainValue::Account(account)
    }
}

impl From<U256> for PlainValue {
    #[inline]
    fn from(value: U256) -> Self {
        PlainValue::Storage(value)
    }
}

impl From<PlainValue> for Account {
    #[inline]
    fn from(value: PlainValue) -> Self {
        match value {
            PlainValue::Account(account) => account,
            _ => unreachable!("PlainValue is not Account"),
        }
    }
}

impl From<PlainValue> for U256 {
    #[inline]
    fn from(value: PlainValue) -> Self {
        match value {
            PlainValue::Storage(value) => value,
            _ => unreachable!("PlainValue is not U256"),
        }
    }
}

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
    fn test_plain_key_encode_decode_account() {
        let addr = Address::repeat_byte(0x11);
        let key = PlainKey::Account(addr);
        let encoded = key.encode();
        assert_eq!(encoded.len(), PLAIN_ACCOUNT_KEY_LEN);
        let decoded = PlainKey::decode(&encoded);
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_plain_key_encode_decode_storage() {
        let addr = Address::repeat_byte(0x22);
        let slot = B256::repeat_byte(0x33);
        let key = PlainKey::Storage(addr, slot);
        let encoded = key.encode();
        assert_eq!(encoded.len(), PLAIN_STORAGE_KEY_LEN);
        let decoded = PlainKey::decode(&encoded);
        assert_eq!(key, decoded);
    }

    #[test]
    #[should_panic(expected = "unexpected length of plain key.")]
    fn test_plain_key_decode_invalid_length() {
        let buf = vec![0u8; 1];
        PlainKey::decode(&buf);
    }

    #[test]
    fn test_plain_value_encode_decode_account_eoa() {
        let account = Account {
            nonce: 42,
            balance: U256::from(1000),
            bytecode_hash: None,
        };
        let value = PlainValue::Account(account);
        let encoded = value.encode();
        assert_eq!(encoded.len(), PLAIN_EOA_ACCOUNT_LEN);
        let decoded = PlainValue::decode(&encoded);
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_plain_value_encode_decode_account_contract() {
        let account = Account {
            nonce: 7,
            balance: U256::from(12345),
            bytecode_hash: Some(B256::repeat_byte(0x44)),
        };
        let value = PlainValue::Account(account);
        let encoded = value.encode();
        assert_eq!(encoded.len(), PLAIN_CONTRACT_ACCOUNT_LEN);
        let decoded = PlainValue::decode(&encoded);
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_plain_value_encode_decode_storage() {
        let storage = U256::from(0xdadbeef);
        let value = PlainValue::Storage(storage);
        let encoded = value.encode();
        assert_eq!(encoded.len(), PLAIN_STORAGE_LEN);
        let decoded = PlainValue::decode(&encoded);
        assert_eq!(value, decoded);
    }

    #[test]
    #[should_panic(expected = "unexpected length of plain value.")]
    fn test_plain_value_decode_invalid_length() {
        let buf = vec![0u8; 1];
        PlainValue::decode(&buf);
    }

    #[test]
    fn test_account_is_empty() {
        let empty = Account::default();
        assert!(empty.is_empty());

        let non_empty = Account {
            nonce: 1,
            balance: U256::from(0),
            bytecode_hash: None,
        };
        assert!(!non_empty.is_empty());

        let non_empty2 = Account {
            nonce: 0,
            balance: U256::from(1),
            bytecode_hash: None,
        };
        assert!(!non_empty2.is_empty());

        let non_empty3 = Account {
            nonce: 0,
            balance: U256::from(0),
            bytecode_hash: Some(B256::repeat_byte(0x01)),
        };
        assert!(!non_empty3.is_empty());
    }
}
