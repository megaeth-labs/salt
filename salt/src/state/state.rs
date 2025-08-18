//! SALT state management with plain key abstraction and ephemeral state view.
//!
//! This module provides the primary interface for working with SALT state data
//! through plain (unencoded) keys over the underlying SALT storage format.
//!
//! ## Core Functionalities
//!
//! 1. **Plain Key Access**: Translates plain keys into SALT's internal bucket-slot
//!    addressing scheme and provides key-value read/write operations against the
//!    current blockchain state stored in the storage backend.
//!
//! 2. **Ephemeral State Management**: Buffers modifications in memory without
//!    immediately persisting them, allowing for batch operations, rollbacks, and
//!    transactional semantics. All changes are accumulated as [`StateUpdates`]
//!    that can be applied atomically.
//!
//! ## SHI Hash Table Implementation
//!
//! The module also implements the SHI (Strongly History Independent) hash table
//! algorithm used by SALT buckets. The SHI hash table ensures that the same set
//! of key-value pairs always produces the same bucket layout, regardless of
//! insertion order.
//!
//! ### Key Features
//! - **History Independence**: Final layout depends only on the key-value pairs, not insertion order
//! - **Linear Probing**: Uses linear probing with key swapping for collision resolution
//! - **Dynamic Resizing**: Supports bucket expansion when load factor exceeds threshold
//!
//! ### Core Operations
//! - `upsert`: Insert or update a key-value pair
//! - `delete`: Remove a key-value pair
//! - `find`: Locate a key in the table
//! - `rehash`: Resize and reorganize the bucket
//!
//! ## References
//! This implementation is based on the work by Blelloch and Golovin.[^1]
//!
//! [^1]: Blelloch, G. E., & Golovin, D. (2007). Strongly History-Independent Hashing with Applications.
//! *In Proceedings of the 48th Annual IEEE Symposium on Foundations of Computer Science (FOCS '07)*, 272–282.
//! DOI: [10.5555/1333875.1334201](https://dl.acm.org/doi/10.5555/1333875.1334201)

use super::{hasher, updates::StateUpdates};
use crate::{
    constant::{BUCKET_RESIZE_LOAD_FACTOR_PCT, BUCKET_RESIZE_MULTIPLIER},
    traits::StateReader,
    types::*,
};
use std::{
    cmp::Ordering,
    collections::{hash_map::Entry, BTreeMap, HashMap},
};

/// A non-persistent SALT state snapshot that buffers modifications in memory.
///
/// `EphemeralSaltState` provides a mutable view over an immutable storage backend,
/// allowing you to perform tentative state updates without modifying the underlying
/// store. All modifications are tracked as deltas and can be extracted as
/// [`StateUpdates`] for atomic application to persistent storage.
///
/// ## Caching Behavior
///
/// - **Writes**: Always cached to track modifications and provide consistent reads
/// - **Reads**: Only cached when explicitly enabled via [`cache_read()`] to avoid
///   memory overhead for read-heavy workloads
///
/// ## Use Cases
///
/// - **Transaction Processing**: Buffer all state changes during transaction execution,
///   then commit atomically or rollback on failure
/// - **Batch Operations**: Accumulate multiple updates before applying them to storage
/// - **Proof Generation**: Track all accessed state for cryptographic proof construction
///
/// [`cache_read()`]: EphemeralSaltState::cache_read
#[derive(Debug, Clone)]
pub struct EphemeralSaltState<'a, Store> {
    /// Storage backend to fetch data from.
    store: &'a Store,
    /// Cache for state entries accessed or modified during this session.
    ///
    /// Always caches writes to track modifications and provide read consistency.
    /// Optionally caches reads when [`cache_reads`] is enabled. Each entry maps
    /// a [`SaltKey`] to its current value (`Some(value)`) or deletion marker (`None`).
    ///
    /// Note: This field is `pub(crate)` to enable proof generation modules to
    /// access the set of touched keys for witness construction.
    pub(crate) cache: HashMap<SaltKey, Option<SaltValue>>,
    /// Tracks the current usage count for buckets modified in this session.
    ///
    /// This field is essential because when [`BucketMeta`] is serialized to [`SaltValue`],
    /// only the `nonce` and `capacity` fields are preserved - the usage count is dropped.
    /// Without this cache, computing the current bucket occupancy would require complex
    /// logic to reconcile the base store's usage count with all insertions and deletions
    /// tracked in the main cache.
    bucket_used_cache: HashMap<BucketId, u64>,
    /// Whether to cache values read from the store for subsequent access
    cache_read: bool,
}

impl<'a, Store: StateReader> EphemeralSaltState<'a, Store> {
    /// Creates a new ephemeral state view over the given storage backend.
    ///
    /// By default, only writes are cached. Read operations fetch values from
    /// the store on each access.
    pub fn new(store: &'a Store) -> Self {
        Self {
            store,
            cache: HashMap::new(),
            bucket_used_cache: HashMap::new(),
            cache_read: false,
        }
    }

    /// Enables caching of read values from the store.
    pub fn cache_read(self) -> Self {
        Self {
            cache_read: true,
            ..self
        }
    }

    /// Retrieves the plain value associated with the given plain key.
    ///
    /// # Arguments
    /// * `plain_key` - The raw key bytes to look up
    ///
    /// # Returns
    /// * `Ok(Some(value))` - The plain value bytes if the key exists
    /// * `Ok(None)` - If the key does not exist
    /// * `Err(error)` - If there was an error accessing the underlying storage
    pub fn plain_value(&mut self, plain_key: &[u8]) -> Result<Option<Vec<u8>>, Store::Error> {
        let bucket_id = hasher::bucket_id(plain_key);
        let metadata = self.metadata(bucket_id, false)?;
        let hashed_key = hasher::hash_with_nonce(plain_key, metadata.nonce);

        for step in 0..metadata.capacity {
            let slot = probe(hashed_key, step, metadata.capacity);
            // FIXME: too many memory copies on the read path currently
            // 1. self.value() has two internal paths:
            //    - Cache hit: 1 copy from cache
            //    - Cache miss: 1 copy from store, plus 1 more copy if cache_read=true
            // 2. salt_val.value().to_vec() copies the plain value bytes upon return
            if let Some(salt_val) = self.value((bucket_id, slot).into())? {
                match salt_val.key().cmp(plain_key) {
                    Ordering::Less => return Ok(None),
                    Ordering::Equal => return Ok(Some(salt_val.value().to_vec())),
                    Ordering::Greater => (),
                }
            } else {
                return Ok(None);
            }
        }
        Ok(None)
    }

    /// Reads the state value for the given SALT key.
    ///
    /// Always checks the cache first before querying the underlying store.
    pub fn value(&mut self, key: SaltKey) -> Result<Option<SaltValue>, Store::Error> {
        let value = match self.cache.entry(key) {
            Entry::Occupied(cache_entry) => cache_entry.into_mut().clone(),
            Entry::Vacant(cache_entry) => {
                let value = self.store.value(key)?;
                if self.cache_read {
                    cache_entry.insert(value.clone());
                }
                value
            }
        };

        Ok(value)
    }

    /// Updates the SALT state with the given set of plain key-value pairs.
    ///
    /// Empty values (`None`) indicate deletions. Returns the resulting changes
    /// as [`StateUpdates`] that can be applied to persistent storage.
    pub fn update<'b>(
        &mut self,
        kvs: impl IntoIterator<Item = (&'b Vec<u8>, &'b Option<Vec<u8>>)>,
    ) -> Result<StateUpdates, Store::Error> {
        let mut state_updates = StateUpdates::default();
        for (plain_key, plain_val) in kvs {
            let bucket_id = hasher::bucket_id(plain_key);
            match plain_val {
                Some(plain_val) => {
                    self.shi_upsert(
                        bucket_id,
                        plain_key.as_slice(),
                        plain_val.as_slice(),
                        &mut state_updates,
                    )?;
                }
                None => self.shi_delete(bucket_id, plain_key.as_slice(), &mut state_updates)?,
            }
        }
        Ok(state_updates)
    }

    /// Sets a new nonce for the specified bucket, triggering a manual rehash.
    ///
    /// Preserves all existing key-value pairs while changing their slot assignments.
    /// Returns the resulting changes as [`StateUpdates`] that can be applied to
    /// persistent storage.
    pub fn set_nonce(
        &mut self,
        bucket_id: BucketId,
        new_nonce: u32,
    ) -> Result<StateUpdates, Store::Error> {
        let metadata = self.metadata(bucket_id, false)?;
        let mut state_updates = StateUpdates::default();
        self.shi_rehash(bucket_id, new_nonce, metadata.capacity, &mut state_updates)?;

        Ok(state_updates)
    }

    /// Retrieves bucket metadata for the given bucket ID.
    ///
    /// # Arguments
    /// * `bucket_id` - The bucket ID to get metadata for
    /// * `need_used` - Whether to populate the `used` field. Setting this to `false`
    ///   avoids unnecessary `bucket_used_slots()` calls to the underlying storage
    ///   backend when the usage count is not needed (e.g., for read operations like
    ///   `plain_value` that only require `nonce` and `capacity`).
    fn metadata(
        &mut self,
        bucket_id: BucketId,
        need_used: bool,
    ) -> Result<BucketMeta, Store::Error> {
        let mut meta = match self.value(bucket_metadata_key(bucket_id))? {
            Some(v) => v.try_into().expect("Failed to decode bucket metadata"),
            None => BucketMeta::default(),
        };
        if need_used {
            meta.used = Some(
                if let Some(&used) = self.bucket_used_cache.get(&bucket_id) {
                    used
                } else {
                    // Performance note: We intentionally avoid caching this usage
                    // count to save on HashMap insertions. Since plain keys are
                    // distributed randomly across buckets, bucket metadata is rarely
                    // reused between different key operations.
                    self.store.bucket_used_slots(bucket_id)?
                },
            );
        }
        Ok(meta)
    }

    /// Inserts or updates a plain key-value pair using the SHI hash table algorithm.
    ///
    /// This method implements the strongly history-independent hash table insertion
    /// algorithm, which maintains deterministic storage layout regardless of insertion
    /// order. May trigger bucket resizing when load factor exceeds 80%.
    fn shi_upsert(
        &mut self,
        bucket_id: BucketId,
        plain_key: &[u8],
        plain_val: &[u8],
        out_updates: &mut StateUpdates,
    ) -> Result<(), Store::Error> {
        let metadata = self.metadata(bucket_id, true)?;
        let hashed_key = hasher::hash_with_nonce(plain_key, metadata.nonce);

        // Start with the new key-value pair we want to insert
        let mut new_salt_val = SaltValue::new(plain_key, plain_val);

        // Linear probe through the bucket, creating a displacement chain
        for step in 0..metadata.capacity {
            let salt_key = (bucket_id, probe(hashed_key, step, metadata.capacity)).into();
            if let Some(old_salt_val) = self.value(salt_key)? {
                match old_salt_val.key().cmp(new_salt_val.key()) {
                    Ordering::Equal => {
                        // Found the key - this is an update operation
                        self.update_value(
                            out_updates,
                            salt_key,
                            Some(old_salt_val),
                            Some(new_salt_val),
                        );
                        return Ok(());
                    }
                    Ordering::Less => {
                        // Key displacement: the existing key is smaller, so it gets displaced.
                        // Place our key here and continue inserting the displaced key.
                        // This creates a displacement chain that shi_delete will later retrace.
                        self.update_value(
                            out_updates,
                            salt_key,
                            Some(old_salt_val.clone()),
                            Some(new_salt_val),
                        );
                        new_salt_val = old_salt_val; // Continue inserting the displaced key
                    }
                    _ => (), // Existing key is larger, continue probing
                }
            } else {
                // Found empty slot - insert the key and complete
                self.update_value(out_updates, salt_key, None, Some(new_salt_val));

                // Update the bucket usage cache.
                let used = metadata.used.unwrap();
                self.bucket_used_cache.insert(bucket_id, used + 1);

                // Resize the bucket if load factor threshold exceeded
                if used >= metadata.capacity * BUCKET_RESIZE_LOAD_FACTOR_PCT / 100 {
                    self.shi_rehash(
                        bucket_id,
                        metadata.nonce,
                        metadata.capacity * BUCKET_RESIZE_MULTIPLIER,
                        out_updates,
                    )?;
                }
                return Ok(());
            }
        }

        unreachable!(
            "bucket {} capacity {} too large",
            bucket_id, metadata.capacity
        );
    }

    /// Deletes a plain key using the SHI hash table deletion algorithm.
    ///
    /// Implements deletion with slot compaction to maintain the SHI property.
    /// After removing the target key, suitable entries are shifted to fill gaps
    /// and preserve the deterministic layout.
    fn shi_delete(
        &mut self,
        bucket_id: BucketId,
        key: &[u8],
        out_updates: &mut StateUpdates,
    ) -> Result<(), Store::Error> {
        let metadata = self.metadata(bucket_id, true)?;
        if let Some((slot, salt_val)) =
            self.shi_find(bucket_id, metadata.nonce, metadata.capacity, key)?
        {
            // Update the bucket usage cache
            self.bucket_used_cache
                .insert(bucket_id, metadata.used.unwrap() - 1);

            // Slot compaction: retrace the displacement chain created by shi_upsert.
            // When shi_upsert displaced keys to make room, deletion must undo this
            // by moving entries back toward their ideal positions to fill the gap.
            let mut del_slot = slot;
            let mut del_value = salt_val;
            loop {
                // Find the next entry that should move into the gap
                let suitable_slot =
                    self.shi_next(bucket_id, del_slot, metadata.nonce, metadata.capacity)?;
                let salt_key = (bucket_id, del_slot).into();
                match suitable_slot {
                    Some((slot, salt_value)) => {
                        // Move this entry into the current gap and continue filling
                        // the new gap it left behind. This retraces the displacement
                        // chain that shi_upsert created.
                        self.update_value(
                            out_updates,
                            salt_key,
                            Some(del_value),
                            Some(salt_value.clone()),
                        );
                        (del_slot, del_value) = (slot, salt_value);
                    }
                    None => {
                        // No suitable entry found - this gap becomes empty, completing
                        // the deletion. The table is now in the same state as if the
                        // deleted key had never been inserted (history independence).
                        self.update_value(out_updates, salt_key, Some(del_value), None);
                        return Ok(());
                    }
                }
            }
        }
        Ok(())
    }

    /// Rehashes all entries in a bucket with new metadata.
    ///
    /// This operation clears the existing bucket layout and reinserts all entries
    /// using the new bucket metadata (typically with increased capacity or changed
    /// nonce).
    fn shi_rehash(
        &mut self,
        bucket_id: BucketId,
        new_nonce: u32,
        new_capacity: u64,
        out_updates: &mut StateUpdates,
    ) -> Result<(), Store::Error> {
        // Step 1: Extract all existing entries (but do not clear the cache yet)
        let old_metadata = self.metadata(bucket_id, true)?;
        let mut old_bucket = BTreeMap::new();
        for slot in 0..old_metadata.capacity {
            let salt_key = SaltKey::from((bucket_id, slot));
            if let Some(salt_val) = self.value(salt_key)? {
                old_bucket.insert(salt_key, salt_val);
            }
        }

        // Step 2: Convert to plain key-value pairs for reinsertion
        let plain_kv_pairs = old_bucket
            .values()
            .map(|salt_val| (salt_val.key().to_vec(), salt_val.value().to_vec()))
            .collect::<BTreeMap<_, _>>();

        // Step 3: Reinsert plain key-value pairs in reverse lexicographic order.
        // So we use the simplified SHI insertion algorithm without key comparisons.
        let mut new_bucket = BTreeMap::new();
        for (plain_key, plain_val) in plain_kv_pairs.iter().rev() {
            let hashed_key = hasher::hash_with_nonce(plain_key, new_nonce);
            let salt_val = SaltValue::new(plain_key, plain_val);

            // Find first empty slot - no need for key comparison
            for step in 0..new_capacity {
                let salt_key = SaltKey::from((bucket_id, probe(hashed_key, step, new_capacity)));
                // Note the code below operates directly on `new_bucket` as the
                // cache has not been cleared yet
                use std::collections::btree_map::Entry;
                match new_bucket.entry(salt_key) {
                    Entry::Vacant(entry) => {
                        entry.insert(salt_val);
                        break;
                    }
                    Entry::Occupied(_) => {}
                }
            }
        }

        // Step 4: Record state changes by comparing slot-by-slot differences
        for slot in 0..old_metadata.capacity.max(new_capacity) {
            let salt_key = SaltKey::from((bucket_id, slot));
            let old_value = old_bucket.get(&salt_key);
            let new_value = new_bucket.get(&salt_key);
            self.update_value(
                out_updates,
                salt_key,
                old_value.cloned(),
                new_value.cloned(),
            );
        }

        // Update bucket metadata
        let new_metadata = BucketMeta {
            nonce: new_nonce,
            capacity: new_capacity,
            ..old_metadata
        };
        self.update_value(
            out_updates,
            bucket_metadata_key(bucket_id),
            Some(old_metadata.into()),
            Some(new_metadata.into()),
        );

        Ok(())
    }

    /// Searches for a plain key in a bucket using linear probing.
    ///
    /// Returns the slot ID and value if found, or `None` if the key doesn't exist.
    /// The search terminates early when encountering an empty slot or a key with
    /// lower lexicographic order (indicating the target key cannot exist).
    pub(crate) fn shi_find(
        &mut self,
        bucket_id: BucketId,
        nonce: u32,
        capacity: u64,
        plain_key: &[u8],
    ) -> Result<Option<(SlotId, SaltValue)>, Store::Error> {
        let hashed_key = hasher::hash_with_nonce(plain_key, nonce);
        for step in 0..capacity {
            let slot = probe(hashed_key, step, capacity);
            if let Some(salt_val) = self.value((bucket_id, slot).into())? {
                match salt_val.key().cmp(plain_key) {
                    Ordering::Less => return Ok(None),
                    Ordering::Equal => return Ok(Some((slot, salt_val))),
                    Ordering::Greater => (),
                }
            } else {
                return Ok(None);
            }
        }
        Ok(None)
    }

    /// Finds the next entry suitable for moving into the given slot during deletion.
    ///
    /// This method implements the slot compaction algorithm used during SHI deletion.
    /// It searches for an entry that can be moved to fill the gap left by a deleted entry,
    /// ensuring the hash table maintains its strongly history-independent property.
    fn shi_next(
        &mut self,
        bucket_id: BucketId,
        del_slot: SlotId,
        nonce: u32,
        capacity: u64,
    ) -> Result<Option<(u64, SaltValue)>, Store::Error> {
        for i in 1..capacity {
            let next_slot = probe(del_slot, i, capacity);
            let salt_key = (bucket_id, next_slot).into();
            match self.value(salt_key)? {
                Some(salt_val) => {
                    let hashed_key = hasher::hash_with_nonce(salt_val.key(), nonce);
                    if rank(hashed_key, next_slot, capacity) > rank(hashed_key, del_slot, capacity)
                    {
                        return Ok(Some((next_slot, salt_val)));
                    }
                }
                None => return Ok(None),
            }
        }
        Ok(None)
    }

    /// Updates a bucket entry and records the change for state tracking.
    ///
    /// This method handles both the in-memory cache update and the delta tracking
    /// needed for generating [`StateUpdates`]. Changes are only recorded when the
    /// old and new values differ to avoid empty deltas.
    fn update_value(
        &mut self,
        out_updates: &mut StateUpdates,
        key: SaltKey,
        old_value: Option<SaltValue>,
        new_value: Option<SaltValue>,
    ) {
        if old_value != new_value {
            out_updates.add(key, old_value, new_value.clone());
            self.cache.insert(key, new_value);
        }
    }
}

/// Computes the i-th slot in the linear probe sequence for a hashed key.
///
/// This implements linear probing for collision resolution in the SHI hash table,
/// where `i` is used as an offset from the initial hash position.
#[inline(always)]
pub(crate) fn probe(hashed_key: u64, i: u64, capacity: u64) -> SlotId {
    (hashed_key.wrapping_add(i) & (capacity - 1)) as SlotId
}

/// Computes the probe distance for a given slot position.
///
/// This function is the inverse of [`probe`]: given a hashed key and slot ID,
/// it returns the probe distance `i` such that `probe(hashed_key, i, capacity) = slot_id`.
#[inline(always)]
fn rank(hashed_key: u64, slot_id: SlotId, capacity: u64) -> SlotId {
    let first = probe(hashed_key, 0, capacity);
    if slot_id >= first {
        slot_id - first
    } else {
        slot_id + capacity - first
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::{
        constant::{MIN_BUCKET_SIZE, NUM_META_BUCKETS},
        empty_salt::EmptySalt,
        mem_store::*,
        state::{
            hasher,
            state::{probe, rank, EphemeralSaltState},
            updates::StateUpdates,
        },
        traits::StateReader,
        types::*,
    };
    use rand::Rng;

    const TEST_BUCKET: BucketId = NUM_META_BUCKETS as BucketId + 1;

    // FIXME: where are the unit tests that exercise SHI hashtable and SHI hashtable only? CRUD + resize, etc.

    // Randomly generate 'l' key-value pairs
    fn create_random_kvs(l: usize) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let mut keys = vec![];
        let mut vals = vec![];
        let mut rng = rand::thread_rng();
        for _ in 0..l {
            let k: [u8; 32] = rng.gen();
            let v: [u8; 32] = rng.gen();
            keys.push(k.to_vec());
            vals.push(v.to_vec());
        }
        (keys, vals)
    }

    // Reorder keys and values randomly
    fn reorder_keys(
        mut keys: Vec<Vec<u8>>,
        mut vals: Vec<Vec<u8>>,
    ) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let mut rng = rand::thread_rng();
        for i in 0..keys.len() {
            let r: usize = rng.gen_range(0..keys.len());
            keys.swap(i, r);
            vals.swap(i, r);
        }
        (keys, vals)
    }

    // Compare two tables
    fn is_bucket_eq<R1: StateReader, R2: StateReader>(
        bucket_id: BucketId,
        table1: &mut EphemeralSaltState<'_, R1>,
        table2: &mut EphemeralSaltState<'_, R2>,
    ) -> bool {
        let meta1 = table1.metadata(bucket_id, false).unwrap();
        let meta2 = table2.metadata(bucket_id, false).unwrap();
        let max_capacity = meta1.capacity.max(meta2.capacity);

        for slot_id in 0..max_capacity {
            let salt_id = (bucket_id, slot_id as SlotId).into();
            if table1.value(salt_id).unwrap() != table2.value(salt_id).unwrap() {
                return false;
            }
        }
        true
    }

    /// Tests the fundamental inverse relationship between probe and rank functions.
    ///
    /// Verifies that for any valid probe distance i:
    ///   rank(probe(key, i, capacity), capacity) == i.
    /// Also tests boundary conditions, various capacities, and large hash values.
    #[test]
    fn probe_and_rank_inverse_relationship() {
        let test_cases = [
            // Basic cases with MIN_BUCKET_SIZE
            (123456u64, MIN_BUCKET_SIZE as u64),
            (0u64, MIN_BUCKET_SIZE as u64),
            (100u64, MIN_BUCKET_SIZE as u64), // Test boundaries
            // Different capacities
            (42u64, 256u64),
            (1234567890u64, 512u64),
            (999u64, 1024u64),
            // Large hash keys that could cause overflow
            (u64::MAX, MIN_BUCKET_SIZE as u64),
            (u64::MAX - 1, 256u64),
            (u64::MAX / 2, 512u64),
            (0x8000_0000_0000_0000u64, 256u64), // Large power of 2
            (0xFFFF_FFFF_FFFF_FFF0u64, 512u64), // Large with low bits set
        ];

        for (hashed_key, capacity) in test_cases {
            for i in 0..capacity {
                let slot_id = probe(hashed_key, i, capacity);

                // Verify slot is always within bounds
                assert!(
                    slot_id < capacity,
                    "Probe result out of bounds: key={}, i={}, slot={}, capacity={}",
                    hashed_key,
                    i,
                    slot_id,
                    capacity
                );

                // Verify inverse relationship
                let rank_result = rank(hashed_key, slot_id, capacity);
                assert_eq!(
                    i, rank_result as u64,
                    "probe-rank inverse failed: key={}, capacity={}, i={}, slot_id={}, rank={}",
                    hashed_key, capacity, i, slot_id, rank_result
                );
            }
        }
    }

    /// Tests wraparound behavior when probe sequence wraps from end to beginning of bucket.
    ///
    /// Focuses specifically on the wraparound mechanics using modulo arithmetic
    /// to ensure correct slot calculation when probe goes beyond capacity.
    #[test]
    fn probe_and_rank_wraparound() {
        let capacity = 256u64;

        // Test hash key that places initial position near the end
        let hashed_key = capacity - 5; // Should start at position 251 in a 256-slot bucket

        let first_slot = probe(hashed_key, 0, capacity);
        assert_eq!(first_slot, 251, "First slot should be at position 251");

        // Test explicit wraparound behavior
        let test_cases = [
            (0, 251), // i=0 -> slot 251
            (1, 252), // i=1 -> slot 252
            (2, 253), // i=2 -> slot 253
            (3, 254), // i=3 -> slot 254
            (4, 255), // i=4 -> slot 255
            (5, 0),   // i=5 -> wraps to slot 0
            (6, 1),   // i=6 -> wraps to slot 1
            (7, 2),   // i=7 -> wraps to slot 2
        ];

        for (probe_distance, expected_slot) in test_cases {
            let actual_slot = probe(hashed_key, probe_distance, capacity);
            assert_eq!(
                actual_slot, expected_slot,
                "Wraparound failed at i={}: expected slot {}, got {}",
                probe_distance, expected_slot, actual_slot
            );
        }
    }

    /// Comprehensive test for plain_value() method covering all key scenarios.
    ///
    /// Tests: non-existent keys, successful retrieval with hash collisions,
    /// and caching behavior with cache_read enabled/disabled.
    #[test]
    fn test_plain_value() {
        // Test non-existent key returns None
        let store = MemStore::new();
        let mut state = EphemeralSaltState::new(&store);
        assert_eq!(state.plain_value(b"missing").unwrap(), None);

        // Setup test data with collision-prone keys
        let kvs = create_same_bucket_test_data(3);
        let updates = state.update(kvs.iter().map(|(k, v)| (k, v))).unwrap();
        store.update_state(updates);

        // Test successful retrieval (validates collision handling)
        for (key, expected) in &kvs {
            assert_eq!(
                EphemeralSaltState::new(&store).plain_value(key).unwrap(),
                expected.clone()
            );
        }

        // Test cache behavior: without cache_read should not populate cache
        let mut no_cache_state = EphemeralSaltState::new(&store);
        no_cache_state.plain_value(&kvs[0].0).unwrap();
        assert!(no_cache_state.cache.is_empty());

        // Test cache behavior: with cache_read should populate cache
        let mut cache_state = EphemeralSaltState::new(&store).cache_read();
        cache_state.plain_value(&kvs[0].0).unwrap();
        cache_state.plain_value(&kvs[1].0).unwrap();
        assert_eq!(
            cache_state.cache.len(),
            3,
            "Cache should contain exactly 3 entries: bucket metadata + 2 key-value pairs"
        );
        assert!(
            cache_state.bucket_used_cache.is_empty(),
            "Bucket usage cache should remain empty - we don't cache bucket usage counts on read"
        );
    }

    /// Tests cache hit and miss behavior in the value() method.
    ///
    /// Validates that the caching logic correctly handles:
    /// - Cache misses that fetch from store
    /// - Cache hits from previous writes
    /// - Cache population behavior based on cache_read setting
    #[test]
    fn test_salt_value() {
        let store = MemStore::new();
        let test_key = SaltKey(42);
        let test_value = SaltValue::new(&[1u8; 32], &[2u8; 32]);

        // Populate store with test data
        store.update_state(StateUpdates {
            data: [(test_key, (None, Some(test_value.clone())))].into(),
        });

        // Test cache miss without cache_read - should fetch from store but not cache
        let mut state = EphemeralSaltState::new(&store);
        let value = state.value(test_key).unwrap();
        assert_eq!(value.as_ref(), Some(&test_value));
        assert!(
            state.cache.is_empty(),
            "Should not cache reads without cache_read"
        );

        // Test cache miss with cache_read - should fetch and cache
        let mut cached_state = EphemeralSaltState::new(&store).cache_read();
        let value = cached_state.value(test_key).unwrap();
        assert_eq!(value.as_ref(), Some(&test_value));
        assert!(
            cached_state.cache.contains_key(&test_key),
            "Should cache reads with cache_read"
        );

        // Test write operations always populate cache
        let write_key = SaltKey(43);
        state.cache.insert(write_key, Some(test_value.clone()));
        let write_value = state.value(write_key).unwrap();
        assert_eq!(write_value.as_ref(), Some(&test_value));
        assert!(
            state.cache.contains_key(&write_key),
            "Writes should always be cached"
        );

        // Test cache hit - access of the write_key should use cached value
        assert_eq!(state.value(write_key).unwrap().as_ref(), Some(&test_value));
    }

    /// Tests that set_nonce preserves all key-value pairs while changing bucket layout.
    ///
    /// Verifies that changing nonce values causes slot reassignments but maintains
    /// data integrity, and that returning to the original nonce restores the exact
    /// original layout.
    #[test]
    fn test_set_nonce() {
        let store = MemStore::new();
        let mut state = EphemeralSaltState::new(&store);
        let kvs = create_same_bucket_test_data(5);
        let bucket_id = hasher::bucket_id(&kvs[0].0);
        let updates = state.update(kvs.iter().map(|(k, v)| (k, v))).unwrap();
        store.update_state(updates);

        // Take a snapshot of the original bucket layout
        let original_meta = state.metadata(bucket_id, true).unwrap();
        let original_layout = (0..original_meta.capacity)
            .map(|slot| {
                let salt_key = SaltKey::from((bucket_id, slot));
                (slot, state.value(salt_key).unwrap())
            })
            .collect::<BTreeMap<_, _>>();

        // Test multiple nonce values including returning to the original
        let test_nonces = [5, 10, 0]; // Last value should be original nonce
        for &test_nonce in &test_nonces {
            // Set nonce to the test value
            let nonce_updates = state.set_nonce(bucket_id, test_nonce).unwrap();
            store.update_state(nonce_updates.clone());

            // Verify metadata was updated with new nonce
            let meta_key = bucket_metadata_key(bucket_id);
            assert!(nonce_updates.data.contains_key(&meta_key));
            let updated_meta = state.metadata(bucket_id, true).unwrap();
            assert_eq!(updated_meta.nonce, test_nonce);
            assert_eq!(updated_meta.capacity, original_meta.capacity);
            assert_eq!(updated_meta.used, original_meta.used);

            // Verify all key-value pairs are still accessible
            for (key, expected_value) in &kvs {
                let found_value = state.plain_value(key).unwrap();
                assert_eq!(found_value, *expected_value);
            }

            // Take a snapshot of the current bucket layout
            let current_layout = (0..updated_meta.capacity)
                .map(|slot| {
                    let salt_key = SaltKey::from((bucket_id, slot));
                    (slot, state.value(salt_key).unwrap())
                })
                .collect::<BTreeMap<_, _>>();

            // Verify that the number of key-value pairs hasn't changed
            assert_eq!(
                kvs.len(),
                current_layout.values().filter(|v| v.is_some()).count()
            );

            if test_nonce == original_meta.nonce {
                // When we return to the original nonce, layout should match exactly
                assert_eq!(
                    original_layout, current_layout,
                    "Bucket layout should be restored when nonce is set back to original"
                );
            }
        }
    }

    /// This test exposes the bug where metadata retrieved from store
    /// has used=None after deserialization, causing a panic in upsert/delete.
    /// The correct behavior should be successful updates without panics.
    #[test]
    fn test_cached_metadata_bug() {
        let store = MemStore::new();
        let key = hasher::tests::get_same_bucket_test_keys()[0].clone();
        let value = Some(b"value_1".to_vec());
        let bucket_id = hasher::bucket_id(&key);

        // Manually set non-default metadata for this bucket to ensure it gets stored
        let non_default_meta = BucketMeta {
            nonce: 1, // Make it non-default so it gets stored
            capacity: 256,
            used: Some(0),
        };
        let meta_key = bucket_metadata_key(bucket_id);
        let meta_updates = StateUpdates {
            data: [(meta_key, (None, Some(SaltValue::from(non_default_meta))))].into(),
        };
        store.update_state(meta_updates);

        // Now create state and do an update - this should read the non-default metadata
        // from store, hit line 128 where v.try_into() sets used=None, then panic in upsert
        let mut state = EphemeralSaltState::new(&store);
        let kvs = vec![(&key, &value)];
        let _updates = state
            .update(kvs)
            .expect("Update should succeed without panic");
    }

    #[test]
    fn insert_with_diff_order() {
        let (keys, vals) = create_random_kvs(3 * MIN_BUCKET_SIZE);
        let reader = EmptySalt;
        let mut state = EphemeralSaltState::new(&reader);
        let mut out_updates = StateUpdates::default();
        //Insert KEYS_NUM key-value pairs into table 0 of state
        for i in 0..keys.len() {
            state
                .shi_upsert(TEST_BUCKET, &keys[i], &vals[i], &mut out_updates)
                .unwrap();
        }

        for _i in 0..2 {
            let reader = EmptySalt;
            let mut cmp_state = EphemeralSaltState::new(&reader);
            let mut out_updates = StateUpdates::default();
            // Rearrange the order of keys and vals
            let (rand_keys, rand_vals) = reorder_keys(keys.clone(), vals.clone());

            // Insert the reordered keys and vals into table 0
            (0..rand_keys.len()).for_each(|i| {
                cmp_state
                    .shi_upsert(TEST_BUCKET, &rand_keys[i], &rand_vals[i], &mut out_updates)
                    .unwrap();
            });

            assert!(
                is_bucket_eq(TEST_BUCKET, &mut state, &mut cmp_state),
                "The two tables should be equal"
            );
        }
    }

    #[test]
    fn delete_with_diff_order() {
        let (keys, vals) = create_random_kvs(250); // Enough to trigger resize in both buckets
        let reader = EmptySalt;
        let mut state1 = EphemeralSaltState::new(&reader);
        let mut out_updates1 = StateUpdates::default();

        //Insert KEYS_NUM key-value pairs into table 0 of state
        for i in 0..keys.len() {
            state1
                .shi_upsert(TEST_BUCKET, &keys[i], &vals[i], &mut out_updates1)
                .unwrap();
        }

        // Rearrange the order of keys and vals
        let (rand_keys, rand_vals) = reorder_keys(keys.clone(), vals);

        let mut out_updates = StateUpdates::default();
        // Delete exactly 40 keys, leaving 210 keys for state2 to also trigger resize
        let del_num: usize = 40;

        for key in rand_keys.iter().take(del_num) {
            state1
                .shi_delete(TEST_BUCKET, key, &mut out_updates)
                .unwrap();
        }

        // Reinsert the key-value pairs from del_num to keys.len() into table 0 of cmp_state
        let reader = EmptySalt;
        let mut state2 = EphemeralSaltState::new(&reader);
        let mut out_updates2 = StateUpdates::default();

        for j in del_num..rand_keys.len() {
            state2
                .shi_upsert(TEST_BUCKET, &rand_keys[j], &rand_vals[j], &mut out_updates2)
                .unwrap();
        }

        assert!(
            is_bucket_eq(TEST_BUCKET, &mut state1, &mut state2),
            "The two tables should be equal"
        );
    }

    #[test]
    fn get_set_slot_val() {
        let reader = EmptySalt;
        let mut state = EphemeralSaltState::new(&reader);
        let salt_val = Some(SaltValue::new(&[1; 32], &[2; 32]));
        let salt_id = (TEST_BUCKET, 1).into();

        assert_eq!(
            state.value(salt_id).unwrap(),
            None,
            "The default slot should be None",
        );

        state.cache.insert(salt_id, salt_val.clone());
        assert_eq!(
            state.value(salt_id).unwrap(),
            salt_val,
            "After calling set_slot_val, get_slot_val should return the same value",
        );
    }

    #[test]
    fn set_updates() {
        let reader = EmptySalt;
        let mut state = EphemeralSaltState::new(&reader);
        let mut out_updates = StateUpdates::default();
        let salt_val = Some(SaltValue::new(&[1; 32], &[2; 32]));
        let salt_id = (TEST_BUCKET, 1).into();
        state.update_value(&mut out_updates, salt_id, None, salt_val.clone());

        assert_eq!(
            out_updates.data.get(&salt_id).unwrap(),
            &(None, salt_val.clone()),
            "After calling set_updates, out_updates should contain the corresponding updates",
        );

        assert_eq!(
            state.value(salt_id).unwrap(),
            salt_val,
            "After calling set_updates, the value of table 0 slot 1 in the state should match the key and val",
        );
    }

    #[test]
    fn find_key() {
        let reader = EmptySalt;
        let mut state = EphemeralSaltState::new(&reader);
        let meta = BucketMeta {
            used: Some(0),
            ..BucketMeta::default()
        };
        let salt_val1 = SaltValue::new(&[1; 32], &[1; 32]);

        // Calculate the initial slot_id of the key
        let hashed_key = hasher::hash_with_nonce(salt_val1.key(), 0);
        let slot_id = probe(hashed_key, 0, meta.capacity);
        let salt_id = (TEST_BUCKET, slot_id).into();

        // Insert the key-value pair into the position of slot_id
        state.cache.insert(salt_id, Some(salt_val1.clone()));

        // Find key1 in the state
        let find_slot = state
            .shi_find(TEST_BUCKET, meta.nonce, meta.capacity, salt_val1.key())
            .unwrap();
        assert_eq!(
            find_slot.unwrap(),
            (slot_id, salt_val1.clone()),
            "The key1 should be found in the slot_id and the value should equal val1",
        );

        let salt_val2 = SaltValue::new(&[2; 32], &[2; 32]);
        let salt_val3 = SaltValue::new(&[3; 32], &[3; 32]);

        // Create a table 0 with entries like [...(key1_slot_id, (key1, val1)), (key1_slot_id + 1,
        // (key3, val3)), (key1_slot_id + 2, (key1, val1))...], and key2 > key1, key3 > key1
        state.cache.insert(salt_id, Some(salt_val3));
        state.cache.insert(SaltKey(salt_id.0 + 1), Some(salt_val2));
        state
            .cache
            .insert(SaltKey(salt_id.0 + 2), Some(salt_val1.clone()));
        let find_slot = state
            .shi_find(TEST_BUCKET, meta.nonce, meta.capacity, salt_val1.key())
            .unwrap();
        assert_eq!(
            find_slot.unwrap(),
            (slot_id + 2, salt_val1.clone()),
            "The key1 should be found in the slot_id+2 and the value should equal val1",
        );

        // Create a table 0 with entries like [...(key1_slot_id, (key2, val2)), None,
        // , (key1_slot_id + 2, (key1, val1))...], and key2 > key1
        state.cache.insert(SaltKey(salt_id.0 + 1), None);
        let find_slot = state
            .shi_find(TEST_BUCKET, meta.nonce, meta.capacity, salt_val1.key())
            .unwrap();
        assert_eq!(find_slot, None, "should be found None");

        // Create a table 0 with entries like [...(key1_slot_id, (key2, val2)), (key1_slot_id + 1,
        // (key4, val4)), (key1_slot_id + 2, (key1, val1))...], and key2 > key1, key4 < key1
        let salt_val4 = SaltValue::new(&[0; 32], &[0; 32]);
        state.cache.insert(SaltKey(salt_id.0 + 1), Some(salt_val4));
        let find_slot = state
            .shi_find(TEST_BUCKET, meta.nonce, meta.capacity, salt_val1.key())
            .unwrap();
        assert_eq!(find_slot, None, "should be found None");
    }

    #[test]
    fn next_slot() {
        let reader = EmptySalt;
        let mut state = EphemeralSaltState::new(&reader);
        let salt_array = [
            SaltValue::new(&[1u8; 32], &[1u8; 32]),
            SaltValue::new(&[2u8; 32], &[1u8; 32]),
            SaltValue::new(&[3u8; 32], &[1u8; 32]),
        ];

        // Calculate the initial slot_ids of the keys
        let slot_id_vec: Vec<SlotId> = salt_array
            .iter()
            .map(|v| {
                let hashed_key = hasher::hash_with_nonce(v.key(), 0);
                probe(hashed_key, 0, MIN_BUCKET_SIZE as SlotId)
            })
            .collect();

        // Create a table 0 with entries like [...(slot_id_vec[0], (key_array[0], val)),
        // (slot_id_vec[0] + 1, (key_array[1], val)), (slot_id_vec[0] + 2, (key_array[2],
        // val))...]
        let salt_id = (TEST_BUCKET, slot_id_vec[0]).into();
        state.cache.insert(salt_id, Some(salt_array[0].clone()));
        state
            .cache
            .insert(SaltKey(salt_id.0 + 1), Some(salt_array[1].clone()));
        state
            .cache
            .insert(SaltKey(salt_id.0 + 2), Some(salt_array[2].clone()));

        // Find the next suitable slot for the position slot_id_vec[0]
        let rs = state
            .shi_next(TEST_BUCKET, slot_id_vec[0], 0, MIN_BUCKET_SIZE as u64)
            .unwrap();

        if slot_id_vec[1] <= slot_id_vec[0] || slot_id_vec[1] > slot_id_vec[0] + 1 {
            assert_eq!(rs.unwrap(), (slot_id_vec[0] + 1, salt_array[1].clone()));
        } else if slot_id_vec[2] <= slot_id_vec[0] || slot_id_vec[2] > slot_id_vec[0] + 2 {
            assert_eq!(rs.unwrap(), (slot_id_vec[0] + 2, salt_array[2].clone()));
        } else {
            assert_eq!(rs, None);
        }

        // Find the next suitable slot for the position slot_id_vec[0] - 1
        if slot_id_vec[0] > 1 {
            let rs = state
                .shi_next(TEST_BUCKET, slot_id_vec[0] - 1, 0, MIN_BUCKET_SIZE as u64)
                .unwrap();
            if slot_id_vec[1] < slot_id_vec[0] || slot_id_vec[1] > slot_id_vec[0] + 1 {
                assert_eq!(rs.unwrap(), (slot_id_vec[0] + 1, salt_array[1].clone()));
            } else if slot_id_vec[2] < slot_id_vec[0] - 1 || slot_id_vec[2] > slot_id_vec[0] + 2 {
                assert_eq!(rs.unwrap(), (slot_id_vec[0] + 2, salt_array[2].clone()));
            } else {
                assert_eq!(rs, None);
            }
        }

        // Find the next suitable slot for the position slot_id_vec[0] + 1
        let rs = state
            .shi_next(TEST_BUCKET, slot_id_vec[0] + 1, 0, MIN_BUCKET_SIZE as u64)
            .unwrap();
        if slot_id_vec[2] <= slot_id_vec[0] + 1 || slot_id_vec[2] > slot_id_vec[0] + 2 {
            assert_eq!(rs.unwrap(), (slot_id_vec[0] + 2, salt_array[2].clone()));
        } else {
            assert_eq!(rs, None);
        }

        // Find the next suitable slot for the position slot_id_vec[0] + 2
        let rs = state
            .shi_next(TEST_BUCKET, slot_id_vec[0] + 2, 0, MIN_BUCKET_SIZE as u64)
            .unwrap();
        assert_eq!(rs, None);
    }

    #[test]
    fn upsert_delete() {
        let reader = EmptySalt;
        let mut state = EphemeralSaltState::new(&reader);
        let mut out_updates = StateUpdates::default();
        let salt_array = [
            SaltValue::new(&[1u8; 32], &[1u8; 32]),
            SaltValue::new(&[2u8; 32], &[1u8; 32]),
            SaltValue::new(&[3u8; 32], &[1u8; 32]),
        ];

        // Traverse the key_array, generate the initial slot_id
        // for the corresponding key, and insert the key-value pair
        // into the state
        let slot_id_vec: Vec<SlotId> = salt_array
            .iter()
            .map(|v| {
                let hashed_key = hasher::hash_with_nonce(v.key(), 0);
                state
                    .shi_upsert(TEST_BUCKET, v.key(), v.value(), &mut out_updates)
                    .unwrap();
                probe(hashed_key, 0, MIN_BUCKET_SIZE as u64)
            })
            .collect();

        slot_id_vec.iter().enumerate().for_each(|(i, slot_id)| {
            let salt_id = (TEST_BUCKET, *slot_id).into();
            let slot = state.value(salt_id).unwrap();
            assert_eq!(
                slot.unwrap(),
                salt_array[i].clone(),
                "After upsert, the initial slot should store the corresponding key-value pair",
            );
        });

        // Iterate through key_array and delete the corresponding key
        for v in &salt_array {
            state
                .shi_delete(TEST_BUCKET, v.key(), &mut out_updates)
                .unwrap();
        }

        for slot_id in &slot_id_vec {
            let salt_id = (TEST_BUCKET, *slot_id).into();
            let slot = state.value(salt_id).unwrap();
            assert_eq!(slot, None, "after delete slot_id: {slot_id} should be None");
        }
    }

    #[test]
    fn state_update_in_same_bucket() {
        let store = MemStore::new();
        let mut state = EphemeralSaltState::new(&store);

        // Use shared test keys that all hash to the same bucket
        let keys = hasher::tests::get_same_bucket_test_keys();
        let num_keys = keys.len() as u64;
        let bucket_id = hasher::bucket_id(&keys[0]);
        let kvs: BTreeMap<Vec<u8>, Option<Vec<u8>>> =
            keys.into_iter().map(|x| (x.clone(), Some(x))).collect();
        let state_updates = state.update(&kvs).unwrap();

        let meta_key = bucket_metadata_key(bucket_id);
        assert!(
            state_updates.data.contains_key(&meta_key),
            "State updates should contain the meta"
        );
        let new_meta = BucketMeta {
            capacity: 512,
            used: Some(num_keys),
            nonce: 0,
        };
        assert_eq!(
            state_updates.data.get(&meta_key).unwrap(),
            (&(Some(BucketMeta::default().into()), Some(new_meta.into()))),
            "State updates should contain the meta key with default value"
        );
    }

    #[test]
    fn extension_rehash() {
        let old_meta = BucketMeta {
            used: Some(0),
            ..BucketMeta::default()
        };
        let new_meta = BucketMeta {
            capacity: 2 * old_meta.capacity,
            ..old_meta
        };
        check_rehash(old_meta, new_meta, 240);
    }

    #[test]
    fn contraction_rehash() {
        let old_meta = BucketMeta {
            capacity: 512,
            used: Some(0),
            ..BucketMeta::default()
        };
        let new_meta = BucketMeta {
            capacity: old_meta.capacity >> 1,
            ..old_meta
        };
        check_rehash(old_meta, new_meta, 200);
    }

    fn check_rehash(old_meta: BucketMeta, new_meta: BucketMeta, l: usize) {
        let store = MemStore::new();
        let mut rehash_state = EphemeralSaltState::new(&store);
        rehash_state
            .shi_rehash(
                TEST_BUCKET,
                old_meta.nonce,
                old_meta.capacity,
                &mut StateUpdates::default(),
            )
            .unwrap();
        let mut rehash_updates = StateUpdates::default();

        let mut cmp_state = EphemeralSaltState::new(&EmptySalt);
        let mut cmp_updates = StateUpdates::default();
        let cmp_meta = new_meta;

        let mut kvs = create_random_kvs(l);

        // Create initial data. In the case of expansion, `cmp_state` inserts `kvs`.
        // The first half of the data is updated to `store` before the state update,
        // and the second half of the data is in `out_updates`.
        for i in 0..kvs.0.len() {
            rehash_state
                .shi_upsert(TEST_BUCKET, &kvs.0[i], &kvs.1[i], &mut rehash_updates)
                .unwrap();
            if i == l / 2 {
                store.update_state(rehash_updates);
                rehash_updates = StateUpdates::default();
            }
            cmp_state
                .shi_upsert(TEST_BUCKET, &kvs.0[i], &kvs.1[i], &mut cmp_updates)
                .unwrap();
        }

        // update some kvs to state
        for i in l / 2 - l / 4 - 1..l / 2 + l / 4 {
            kvs.1[i] = [i as u8; 32].into();
            rehash_state
                .shi_upsert(TEST_BUCKET, &kvs.0[i], &kvs.1[i], &mut rehash_updates)
                .unwrap();
            cmp_state
                .shi_upsert(TEST_BUCKET, &kvs.0[i], &kvs.1[i], &mut cmp_updates)
                .unwrap();
        }

        // delete some kvs to state
        for i in l / 2 - l / 8 - 1..l / 2 + l / 8 {
            rehash_state
                .shi_delete(TEST_BUCKET, &kvs.0[i], &mut rehash_updates)
                .unwrap();
            cmp_state
                .shi_delete(TEST_BUCKET, &kvs.0[i], &mut cmp_updates)
                .unwrap();
        }

        // state has insert, update and delete operation, rehash state
        rehash_state
            .shi_rehash(
                TEST_BUCKET,
                new_meta.nonce,
                new_meta.capacity,
                &mut rehash_updates,
            )
            .unwrap();

        // Verify the rehashing results
        for i in 0..kvs.0.len() {
            let kv1 = cmp_state
                .shi_find(TEST_BUCKET, cmp_meta.nonce, cmp_meta.capacity, &kvs.0[i])
                .unwrap();
            let kv2 = rehash_state
                .shi_find(TEST_BUCKET, new_meta.nonce, new_meta.capacity, &kvs.0[i])
                .unwrap();
            assert_eq!(kv1, kv2);
        }

        // Verify the rehashing results after writing to store
        store.update_state(rehash_updates.clone());
        let mut state = EphemeralSaltState::new(&store);
        for i in 0..kvs.0.len() {
            let kv1 = cmp_state
                .shi_find(TEST_BUCKET, new_meta.nonce, new_meta.capacity, &kvs.0[i])
                .unwrap();
            let kv2 = state
                .shi_find(TEST_BUCKET, new_meta.nonce, new_meta.capacity, &kvs.0[i])
                .unwrap();
            assert_eq!(kv1, kv2);
        }
        //check changed meta in state updates
        let meta_key = bucket_metadata_key(TEST_BUCKET);
        assert!(
            rehash_updates.data.contains_key(&meta_key),
            "rehash_updates should contain the meta key"
        );
        assert_eq!(
            rehash_updates.data.get(&meta_key).unwrap(),
            &(Some(old_meta.into()), Some(new_meta.into())),
            "rehash_updates should contain the old and new meta"
        );
    }

    // ============================
    // Test Utility Functions
    // ============================

    /// Creates a test EphemeralSaltState with pre-populated sample data.
    ///
    /// This utility function sets up a complete testing environment by creating
    /// random key-value pairs, inserting them into the provided store via state
    /// updates, and returning the configured state along with the test data.
    /// Useful for tests that need existing data to work with rather than starting
    /// from an empty state.
    ///
    /// Returns: (configured_state, test_keys, test_values)
    fn create_test_state_with_data<'a>(
        store: &'a MemStore,
        num_keys: usize,
    ) -> (EphemeralSaltState<'a, MemStore>, Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let mut state = EphemeralSaltState::new(store);
        let (keys, values) = create_random_kvs(num_keys);

        let kvs: BTreeMap<Vec<u8>, Option<Vec<u8>>> = keys
            .iter()
            .zip(values.iter())
            .map(|(k, v)| (k.clone(), Some(v.clone())))
            .collect();

        let updates = state.update(&kvs).unwrap();
        store.update_state(updates);

        (state, keys, values)
    }

    /// Creates test key-value pairs that hash to the same bucket for collision testing.
    ///
    /// This utility function generates test data specifically designed to stress-test
    /// the SHI hash table's collision handling mechanisms. Uses pre-computed keys
    /// from the hasher test module that are guaranteed to hash to the same bucket,
    /// creating scenarios where linear probing and key swapping logic are exercised.
    /// Essential for validating bucket layout algorithms under high collision scenarios.
    ///
    /// Returns: Vector of (key, Some(value)) pairs ready for update() calls
    fn create_same_bucket_test_data(count: usize) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
        let keys = hasher::tests::get_same_bucket_test_keys();
        if count > keys.len() {
            panic!(
                "Requested {} keys but only {} available from get_same_bucket_test_keys",
                count,
                keys.len()
            );
        }
        keys.into_iter()
            .take(count)
            .enumerate()
            .map(|(i, key)| (key, Some(format!("value_{}", i).into_bytes())))
            .collect()
    }

    /// Assertion helper that verifies a state contains all expected key-value pairs.
    ///
    /// This utility function performs batch verification of key-value pair existence
    /// by iterating through expected pairs and using plain_value() to check each one.
    /// Provides clear error messages when assertions fail, making it easier to debug
    /// test failures. Used extensively in tests that need to verify data integrity
    /// after operations like insertions, updates, or bucket rehashing.
    fn assert_state_contains_kvs<Store: StateReader>(
        state: &mut EphemeralSaltState<Store>,
        expected_kvs: &[(Vec<u8>, Vec<u8>)],
    ) {
        for (key, expected_value) in expected_kvs {
            let actual_value = state.plain_value(key).unwrap();
            assert_eq!(
                actual_value,
                Some(expected_value.clone()),
                "Key {:?} should have value {:?}",
                key,
                expected_value
            );
        }
    }

    /// Assertion helper that verifies specified keys are not present in the state.
    ///
    /// This utility function performs batch verification of key absence by checking
    /// that plain_value() returns None for each provided key. Used primarily in
    /// deletion tests to verify that removed keys are no longer accessible.
    /// Provides clear error messages indicating which key was unexpectedly found,
    /// making it easier to identify deletion logic issues.
    fn assert_keys_not_present<Store: StateReader>(
        state: &mut EphemeralSaltState<Store>,
        keys: &[Vec<u8>],
    ) {
        for key in keys {
            let value = state.plain_value(key).unwrap();
            assert_eq!(value, None, "Key {:?} should not exist", key);
        }
    }

    // ============================
    // Batch Update Tests
    // ============================

    /// Tests batch update with insert-only operations.
    ///
    /// This test validates that the update() method correctly handles a batch of
    /// pure insert operations without any existing data conflicts. Creates multiple
    /// random key-value pairs, passes them to update() as inserts (Some values),
    /// then verifies: 1) Non-empty StateUpdates are generated 2) All keys become
    /// accessible after applying updates. This ensures the basic batch insertion
    /// path works correctly through the SHI hash table algorithm.
    #[test]
    fn test_update_insert_only() {
        let store = MemStore::new();
        let mut state = EphemeralSaltState::new(&store);
        let (keys, values) = create_random_kvs(10);

        let kvs: BTreeMap<Vec<u8>, Option<Vec<u8>>> = keys
            .iter()
            .zip(values.iter())
            .map(|(k, v)| (k.clone(), Some(v.clone())))
            .collect();

        let updates = state.update(&kvs).unwrap();
        assert!(!updates.data.is_empty());

        store.update_state(updates);

        // Verify all keys are accessible
        let mut fresh_state = EphemeralSaltState::new(&store);
        assert_state_contains_kvs(
            &mut fresh_state,
            &keys
                .iter()
                .zip(values.iter())
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<Vec<_>>(),
        );
    }

    /// Tests batch update with delete-only operations.
    ///
    /// This test validates that the update() method correctly handles a batch of
    /// pure delete operations on existing data. Creates initial test data, then
    /// performs a batch delete of half the keys (using None values), and verifies:
    /// 1) Deleted keys are no longer accessible 2) Remaining keys are unaffected
    /// This ensures the SHI deletion algorithm with slot compaction works correctly
    /// in batch scenarios.
    #[test]
    fn test_update_delete_only() {
        let store = MemStore::new();
        let (mut state, keys, values) = create_test_state_with_data(&store, 8);

        // Delete half of the keys
        let keys_to_delete = &keys[0..4];
        let remaining_keys = &keys[4..];
        let remaining_values = &values[4..];

        let delete_kvs: BTreeMap<Vec<u8>, Option<Vec<u8>>> =
            keys_to_delete.iter().map(|k| (k.clone(), None)).collect();

        let updates = state.update(&delete_kvs).unwrap();
        store.update_state(updates);

        // Verify deleted keys are not present
        let mut fresh_state = EphemeralSaltState::new(&store);
        assert_keys_not_present(&mut fresh_state, keys_to_delete);

        // Verify remaining keys are still present
        assert_state_contains_kvs(
            &mut fresh_state,
            &remaining_keys
                .iter()
                .zip(remaining_values.iter())
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<Vec<_>>(),
        );
    }

    /// Tests batch update with mixed insert, update, and delete operations.
    ///
    /// This test validates that the update() method correctly handles complex
    /// batches containing all operation types in a single call. Sets up initial
    /// data, then creates a batch with: 1) Value update of existing key
    /// 2) Deletion of existing key 3) Insertion of new key. Verifies each
    /// operation type worked correctly by checking final state. This ensures
    /// the batch processing correctly handles the different operation types
    /// and maintains data consistency.
    #[test]
    fn test_update_mixed_operations() {
        let store = MemStore::new();
        let (mut state, keys, values) = create_test_state_with_data(&store, 6);

        let mut mixed_kvs = BTreeMap::new();

        // Update existing key
        mixed_kvs.insert(keys[0].clone(), Some(b"updated_value".to_vec()));

        // Delete existing key
        mixed_kvs.insert(keys[1].clone(), None);

        // Insert new key
        let new_key = b"new_key".to_vec();
        let new_value = b"new_value".to_vec();
        mixed_kvs.insert(new_key.clone(), Some(new_value.clone()));

        let updates = state.update(&mixed_kvs).unwrap();
        store.update_state(updates);

        // Verify changes
        let mut fresh_state = EphemeralSaltState::new(&store);

        // Updated key should have new value
        assert_eq!(
            fresh_state.plain_value(&keys[0]).unwrap(),
            Some(b"updated_value".to_vec())
        );

        // Deleted key should not exist
        assert_eq!(fresh_state.plain_value(&keys[1]).unwrap(), None);

        // New key should exist
        assert_eq!(fresh_state.plain_value(&new_key).unwrap(), Some(new_value));

        // Untouched keys should remain
        for i in 2..keys.len() {
            assert_eq!(
                fresh_state.plain_value(&keys[i]).unwrap(),
                Some(values[i].clone())
            );
        }
    }

    /// Tests batch update behavior with empty input.
    ///
    /// This test validates that the update() method handles empty batches gracefully
    /// without errors or unnecessary state changes. Passes an empty BTreeMap to
    /// update() and verifies that the returned StateUpdates is also empty, ensuring
    /// no spurious changes are generated. This is important for preventing
    /// unnecessary work in scenarios where no actual updates are needed.
    #[test]
    fn test_update_empty_batch() {
        let store = MemStore::new();
        let mut state = EphemeralSaltState::new(&store);

        let empty_kvs: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
        let updates = state.update(&empty_kvs).unwrap();

        // Should produce empty updates
        assert!(updates.data.is_empty());
    }

    /// Tests duplicate key handling in batch updates.
    ///
    /// This test validates that when the same key appears multiple times in a batch
    /// update, the system correctly applies the last value (BTreeMap deduplication
    /// behavior). Creates a batch with the same key mapped to different values,
    /// then verifies that only the final value is stored. This ensures predictable
    /// behavior when batch operations contain duplicate keys, which could occur
    /// in some application scenarios.
    #[test]
    fn test_update_duplicate_keys() {
        let store = MemStore::new();
        let mut state = EphemeralSaltState::new(&store);

        let key = b"duplicate_key".to_vec();
        let mut kvs = BTreeMap::new();

        // BTreeMap will automatically deduplicate, keeping the last value
        kvs.insert(key.clone(), Some(b"first_value".to_vec()));
        kvs.insert(key.clone(), Some(b"second_value".to_vec()));

        let updates = state.update(&kvs).unwrap();
        store.update_state(updates);

        // Should contain the last value
        let mut fresh_state = EphemeralSaltState::new(&store);
        assert_eq!(
            fresh_state.plain_value(&key).unwrap(),
            Some(b"second_value".to_vec())
        );
    }

    /// Tests that batch updates correctly trigger automatic bucket resizing.
    ///
    /// This test validates that the update() method properly handles bucket capacity
    /// expansion when the load factor threshold is exceeded. Uses pre-computed keys
    /// that hash to the same bucket to force high occupancy, then verifies:
    /// 1) StateUpdates contain bucket metadata changes 2) All keys remain accessible
    /// after resize. This ensures the automatic resizing mechanism works correctly
    /// during batch operations and maintains data integrity through the rehash process.
    #[test]
    fn test_update_triggers_bucket_resize() {
        let store = MemStore::new();
        let mut state = EphemeralSaltState::new(&store);

        // Use keys that hash to the same bucket to force resize
        let keys = hasher::tests::get_same_bucket_test_keys();
        let values: Vec<Vec<u8>> = keys
            .iter()
            .enumerate()
            .map(|(i, _)| format!("value_{}", i).into_bytes())
            .collect();

        let kvs: BTreeMap<Vec<u8>, Option<Vec<u8>>> = keys
            .iter()
            .zip(values.iter())
            .map(|(k, v)| (k.clone(), Some(v.clone())))
            .collect();

        let updates = state.update(&kvs).unwrap();

        // Should contain metadata update for bucket resize
        let bucket_id = hasher::bucket_id(&keys[0]);
        let meta_key = bucket_metadata_key(bucket_id);
        assert!(updates.data.contains_key(&meta_key));

        store.update_state(updates);

        // Verify all keys are still accessible after resize
        let mut fresh_state = EphemeralSaltState::new(&store);
        assert_state_contains_kvs(
            &mut fresh_state,
            &keys
                .iter()
                .zip(values.iter())
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<Vec<_>>(),
        );
    }

    // ============================
    // Edge Cases and Error Handling Tests
    // ============================

    /// Tests state consistency across multiple sequential operation rounds.
    ///
    /// This test validates that EphemeralSaltState maintains data consistency across
    /// complex sequences of mixed operations. Simulates multiple rounds where each
    /// round: 1) Inserts new random keys 2) Verifies insertion success 3) Deletes
    /// half the keys 4) Verifies deletion and remaining data integrity. This stress
    /// test ensures the state management correctly handles accumulating changes over
    /// time without data corruption or consistency issues.
    #[test]
    fn test_state_consistency_multiple_operations() {
        let store = MemStore::new();
        let mut state = EphemeralSaltState::new(&store);

        // Simulate multiple rounds of operations
        for _round in 0..3 {
            let (keys, values) = create_random_kvs(20);

            // Insert all keys
            let kvs: BTreeMap<Vec<u8>, Option<Vec<u8>>> = keys
                .iter()
                .zip(values.iter())
                .map(|(k, v)| (k.clone(), Some(v.clone())))
                .collect();

            let updates = state.update(&kvs).unwrap();
            store.update_state(updates);

            // Verify all keys are accessible
            let mut verification_state = EphemeralSaltState::new(&store);
            assert_state_contains_kvs(
                &mut verification_state,
                &keys
                    .iter()
                    .zip(values.iter())
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<Vec<_>>(),
            );

            // Delete half the keys
            let delete_kvs: BTreeMap<Vec<u8>, Option<Vec<u8>>> =
                keys[0..10].iter().map(|k| (k.clone(), None)).collect();

            let delete_updates = state.update(&delete_kvs).unwrap();
            store.update_state(delete_updates);

            // Verify deletions
            let mut post_delete_state = EphemeralSaltState::new(&store);
            assert_keys_not_present(&mut post_delete_state, &keys[0..10]);
            assert_state_contains_kvs(
                &mut post_delete_state,
                &keys[10..]
                    .iter()
                    .zip(values[10..].iter())
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<Vec<_>>(),
            );
        }
    }
}
