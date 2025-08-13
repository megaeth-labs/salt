//! This module implements the "state" component of the SALT
//! data structure that holds the key-value pairs of the
//! blockchain state to be authenticated.
//!
//! # State Management in SALT
//!
//! The state module provides two main interfaces for working with blockchain state:
//! 1. **Plain State Operations**: EVM-compatible key-value operations using [`EphemeralSaltState`]
//! 2. **SALT State Operations**: Low-level bucket operations using [`StateReader`] trait
//!
//! ## Working with Plain State (EVM-compatible operations)
//!
//! ```rust,ignore
//! use salt::{EphemeralSaltState, MemStore};
//!
//! // Create an in-memory SALT instance
//! let store = MemStore::new();
//! let mut state = EphemeralSaltState::new(&store);
//!
//! // Update plain key-value pairs (like EVM account/storage data)
//! let plain_kvs = vec![
//!     (b"account_address_1".to_vec(), Some(b"balance_100_eth".to_vec())),
//!     (b"storage_slot_key".to_vec(), Some(b"storage_value_data".to_vec())),
//!     (b"contract_code_hash".to_vec(), Some(b"0x1234567890abcdef".to_vec())),
//! ];
//!
//! // Apply updates - this internally maps plain keys to SALT buckets
//! let state_updates = state.update(&plain_kvs).unwrap();
//!
//! // Persist the state updates to storage
//! store.update_state(state_updates);
//!
//! // Reading plain state back
//! let mut state = EphemeralSaltState::new(&store);
//!
//! // Read individual values by plain key
//! let balance = state.get_raw(b"account_address_1").unwrap();
//! assert_eq!(balance, Some(b"balance_100_eth".to_vec()));
//!
//! let storage_val = state.get_raw(b"storage_slot_key").unwrap();
//! assert_eq!(storage_val, Some(b"storage_value_data".to_vec()));
//!
//! // Check for non-existent key
//! let missing = state.get_raw(b"non_existent_key").unwrap();
//! assert_eq!(missing, None);
//! ```
//!
//! ## Working with SALT State (low-level bucket operations)
//!
//! ```rust,ignore
//! use salt::{SaltKey, SaltValue, BucketMeta, traits::StateReader, MemStore};
//!
//! let store = MemStore::new();
//!
//! // Direct SALT key-value operations (bypassing plain key mapping)
//! let bucket_id = 65538; // Specific bucket in the trie
//! let slot_id = 42;       // Slot within the bucket
//! let salt_key = SaltKey::from((bucket_id, slot_id));
//!
//! // Create a SALT value (encoded key-value pair)
//! let salt_value = SaltValue::new(b"raw_key_data", b"raw_value_data");
//!
//! // Store directly in SALT format
//! store.put_state(salt_key, salt_value.clone());
//!
//! // Read back using StateReader trait
//! let retrieved = store.entry(salt_key).unwrap();
//! assert_eq!(retrieved, Some(salt_value));
//!
//! // Read bucket metadata
//! let meta = store.meta(bucket_id).unwrap();
//! println!("Bucket capacity: {}, used slots: {}", meta.capacity, meta.used.unwrap_or(0));
//!
//! // Read range of entries from a bucket
//! let entries = store.entries(bucket_id, 0..=100).unwrap();
//! for (key, value) in entries {
//!     println!("Key: {:?}, Value: {:?}", key, value);
//! }
//! ```
//!
//! ## Batch Operations and Caching
//!
//! ```rust,ignore
//! use salt::{EphemeralSaltState, SaltKey, MemStore};
//!
//! let store = MemStore::new();
//!
//! // Create ephemeral state for batch operations with caching
//! let mut ephemeral_state = EphemeralSaltState::new(&store);
//!
//! // Batch update multiple plain keys
//! let batch_updates = vec![
//!     (b"user1_balance".to_vec(), Some(b"1000".to_vec())),
//!     (b"user2_balance".to_vec(), Some(b"2000".to_vec())),
//!     (b"user3_balance".to_vec(), Some(b"3000".to_vec())),
//!     (b"old_record".to_vec(), None), // Deletion
//! ];
//!
//! let state_updates = ephemeral_state.update(&batch_updates).unwrap();
//!
//! // The ephemeral state caches reads and tracks all changes
//! // Read from cache (fast - no storage access)
//! let cached_state = ephemeral_state.get_entry(SaltKey::from((65538, 1))).unwrap();
//!
//! // Apply all changes atomically
//! store.update_state(state_updates);
//! ```

#[allow(clippy::module_inception)]
pub mod state;
pub mod updates;

pub use state::pk_hasher;
