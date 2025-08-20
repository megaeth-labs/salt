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
        let metadata_key = bucket_metadata_key(bucket_id);

        // Check cache first
        let meta = if let Some(cached_value) = self.cache.get(&metadata_key) {
            // Found in cache - decode it
            let mut meta = match cached_value {
                Some(v) => v.try_into().expect("Failed to decode bucket metadata"),
                None => BucketMeta::default(),
            };

            // Cached value doesn't have 'used' field, populate if needed
            if need_used {
                meta.used = Some(
                    if let Some(&used) = self.bucket_used_cache.get(&bucket_id) {
                        used
                    } else {
                        self.store.bucket_used_slots(bucket_id)?
                    },
                );
            }
            meta
        } else {
            // Common path: Not in cache, get from store (more efficient than self.value())
            let mut meta = self.store.metadata(bucket_id)?;

            if need_used {
                // Look up cache for the latest usage count
                if let Some(&cached_used) = self.bucket_used_cache.get(&bucket_id) {
                    meta.used = Some(cached_used);
                }
            } else {
                // Clear "used" if not needed
                meta.used = None;
            }

            // Cache the metadata only if requested
            if self.cache_read {
                // Performance note: We intentionally avoid caching the usage count
                // to save on HashMap insertions. Since plain keys are distributed
                // randomly across buckets, bucket metadata is rarely reused between
                // different keys.
                self.cache.insert(
                    metadata_key,
                    if meta.is_default() {
                        None
                    } else {
                        Some(meta.into())
                    },
                );
            }
            meta
        };

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

        // Should not be possible due to load factor limits
        unreachable!(
            "shi_upsert: no empty slot found in bucket {} after probing all {} slots",
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
                    let ideal_slot = hasher::hash_with_nonce(salt_val.key(), nonce);
                    if rank(ideal_slot, next_slot, capacity) > rank(ideal_slot, del_slot, capacity)
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
    ((hashed_key + i) % capacity) as SlotId
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
        constant::{
            BUCKET_RESIZE_LOAD_FACTOR_PCT, BUCKET_RESIZE_MULTIPLIER, MIN_BUCKET_SIZE,
            NUM_META_BUCKETS,
        },
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
            // Large hash keys
            (u64::MAX / 2, 512u64),
            (0x8000_0000_0000_0000u64, 256u64), // Large power of 2
            (0xFFFF_FFFF_FFFF_F000u64, 512u64), // Large with low bits set
            // Non-power-of-2 capacities to test arbitrary capacity support
            (42u64, 12u64),
            (100u64, 15u64),
            (1000u64, 25u64),
            (12345u64, 13u64), // Prime capacity
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

    /// Comprehensive test for the update() method covering all operation types.
    ///
    /// This test validates the update() method through a sequence of realistic operations:
    /// 1. Empty batch handling
    /// 2. Batch insertion of new keys
    /// 3. Mixed operations (update, delete, insert in single batch)
    /// 4. Batch deletion
    /// 5. Duplicate key handling (last value wins)
    ///
    /// Uses a reference BTreeMap to track expected state and verify consistency after each phase.
    #[test]
    fn test_update_operations() {
        let store = MemStore::new();
        let mut state = EphemeralSaltState::new(&store);

        // Reference map to track expected state
        let mut expected: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();

        // Helper to verify state matches expected
        let verify_state = |expected: &BTreeMap<Vec<u8>, Vec<u8>>| {
            let mut verify = EphemeralSaltState::new(&store);

            // Check all expected keys exist with correct values
            for (key, value) in expected {
                assert_eq!(
                    verify.plain_value(key).unwrap(),
                    Some(value.clone()),
                    "Key {:?} should have value {:?}",
                    std::str::from_utf8(key).unwrap_or("(non-UTF8)"),
                    std::str::from_utf8(value).unwrap_or("(non-UTF8)")
                );
            }

            // Count elements in the target bucket to verify total count
            if !expected.is_empty() {
                // Get bucket ID from first key (all keys should hash to same bucket)
                let first_key = expected.keys().next().unwrap();
                let target_bucket = hasher::bucket_id(first_key);

                // Count actual elements in this bucket
                let mut actual_count = 0;
                if let Ok(meta) = verify.metadata(target_bucket, false) {
                    for slot in 0..meta.capacity {
                        let salt_key = SaltKey::from((target_bucket, slot));
                        if verify.value(salt_key).unwrap().is_some() {
                            actual_count += 1;
                        }
                    }
                }

                assert_eq!(
                    actual_count,
                    expected.len(),
                    "Bucket {} should contain exactly {} elements, found {}",
                    target_bucket,
                    expected.len(),
                    actual_count
                );
            }
        };

        // Get test data - all keys hash to same bucket
        let test_data = create_same_bucket_test_data(15);

        // Helper to apply updates and store them
        let apply_updates =
            |state: &mut EphemeralSaltState<_>, batch: BTreeMap<Vec<u8>, Option<Vec<u8>>>| {
                let updates = state.update(&batch).unwrap();
                store.update_state(updates);
            };

        // Phase 1: Empty batch handling
        assert!(state.update(&BTreeMap::new()).unwrap().data.is_empty());
        verify_state(&expected);

        // Phase 2: Batch insertion of new keys
        let insert_batch: BTreeMap<_, _> = test_data[0..10]
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (k, v) in &insert_batch {
            expected.insert(k.clone(), v.as_ref().unwrap().clone());
        }
        apply_updates(&mut state, insert_batch);
        verify_state(&expected);

        // Phase 3: Mixed operations (update, delete, insert)
        let mixed_batch: BTreeMap<_, _> = [
            (test_data[0].0.clone(), Some(b"updated_value".to_vec())), // Update
            (test_data[1].0.clone(), None),                            // Delete
            (test_data[10].0.clone(), test_data[10].1.clone()),        // Insert new
        ]
        .into_iter()
        .collect();

        expected.insert(test_data[0].0.clone(), b"updated_value".to_vec());
        expected.remove(&test_data[1].0);
        expected.insert(
            test_data[10].0.clone(),
            test_data[10].1.as_ref().unwrap().clone(),
        );

        apply_updates(&mut state, mixed_batch);
        verify_state(&expected);

        // Phase 4: Batch deletion
        let delete_batch: BTreeMap<_, _> = test_data[2..6]
            .iter()
            .map(|(k, _)| (k.clone(), None))
            .collect();
        for (k, _) in &delete_batch {
            expected.remove(k);
        }
        apply_updates(&mut state, delete_batch);
        verify_state(&expected);

        // Phase 5: Duplicate key handling (last value wins)
        let mut dup_batch = BTreeMap::new();
        dup_batch.insert(test_data[11].0.clone(), Some(b"first_value".to_vec()));
        dup_batch.insert(test_data[11].0.clone(), Some(b"second_value".to_vec())); // BTreeMap keeps last
        expected.insert(test_data[11].0.clone(), b"second_value".to_vec());

        apply_updates(&mut state, dup_batch);
        verify_state(&expected);
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

    /// Comprehensive test for the metadata() method covering all scenarios.
    ///
    /// - **Default metadata**: Tests retrieval when no metadata is stored (returns `BucketMeta::default()`)
    /// - **Usage count behavior**: Validates `need_used=false` (no usage) vs `need_used=true` (populates usage)
    /// - **Stored metadata**: Tests custom metadata retrieval (nonce=123, capacity=512)
    /// - **Non-zero usage counting**: Adds data to bucket and verifies usage count reflects actual entries
    /// - **Cache behavior**: Tests that `bucket_used_cache` takes precedence over store counting
    /// - **Cache isolation**: Verifies usage counts aren't cached during read operations
    #[test]
    fn test_metadata() {
        let store = MemStore::new();
        let mut state = EphemeralSaltState::new(&store);

        // Test 1: Default metadata (no stored metadata, need_used=false)
        let meta = state.metadata(TEST_BUCKET, false).unwrap();
        assert_eq!(meta, BucketMeta::default());
        assert!(meta.used.is_none());

        // Test 2: Default metadata with need_used=true (should call bucket_used_slots)
        let meta = state.metadata(TEST_BUCKET, true).unwrap();
        assert_eq!(meta.nonce, 0);
        assert_eq!(meta.capacity, MIN_BUCKET_SIZE as u64);
        assert_eq!(meta.used, Some(0)); // Empty bucket has 0 used slots

        // Test 3: Stored metadata retrieval with need_used=true
        let stored_meta = BucketMeta {
            nonce: 123,
            capacity: 512,
            used: None,
        };
        let meta_key = bucket_metadata_key(TEST_BUCKET);
        store.update_state(StateUpdates {
            data: [(meta_key, (None, Some(stored_meta.into())))].into(),
        });

        let meta = state.metadata(TEST_BUCKET, true).unwrap();
        assert_eq!(meta.nonce, 123);
        assert_eq!(meta.capacity, 512);
        assert_eq!(meta.used, Some(0)); // Still empty

        // Test 4: Add some data to the bucket to test non-zero usage count
        let test_key = SaltKey::from((TEST_BUCKET, 1));
        let test_value = SaltValue::new(&[1u8; 32], &[2u8; 32]);
        store.update_state(StateUpdates {
            data: [(test_key, (None, Some(test_value)))].into(),
        });

        let meta = state.metadata(TEST_BUCKET, true).unwrap();
        assert_eq!(meta.nonce, 123);
        assert_eq!(meta.capacity, 512);
        assert_eq!(meta.used, Some(1)); // Now has 1 slot used
        assert!(
            state.bucket_used_cache.is_empty(),
            "Usage counts not cached on reads"
        );

        // Test 5: Cached usage count (should use cache instead of calling bucket_used_slots)
        state.bucket_used_cache.insert(TEST_BUCKET, 100);

        let meta = state.metadata(TEST_BUCKET, true).unwrap();
        assert_eq!(meta.nonce, 123);
        assert_eq!(meta.capacity, 512);
        assert_eq!(meta.used, Some(100)); // From cache, not store count
    }

    /// Helper function to verify all key-value pairs are present with correct values.
    fn verify_all_keys_present(
        state: &mut EphemeralSaltState<EmptySalt>,
        bucket_id: BucketId,
        nonce: u32,
        capacity: u64,
        keys: &[Vec<u8>],
        vals: &[Vec<u8>],
    ) {
        for i in 0..keys.len() {
            let find_result = state
                .shi_find(bucket_id, nonce, capacity, &keys[i])
                .unwrap();
            assert!(find_result.is_some(), "Key {} should be found in state", i);
            let (_, found_value) = find_result.unwrap();
            assert_eq!(
                found_value.value(),
                &vals[i],
                "Key {} should have correct value",
                i
            );
        }
    }

    /// Common helper function to test insertion order independence.
    ///
    /// Tests that a hash table produces identical results regardless of key
    /// insertion order. Supports testing both with and without bucket resizing.
    ///
    /// # Arguments
    /// * `initial_capacity` - Starting bucket capacity
    /// * `num_keys` - Number of key-value pairs to insert
    /// * `num_iterations` - Number of different insertion orders to test
    fn test_insertion_order_independence(
        initial_capacity: u64,
        num_keys: usize,
        num_iterations: usize,
    ) {
        use rand::seq::SliceRandom;
        use rand::thread_rng;

        // Compute expected final capacity based on load factor
        let expect_resize =
            num_keys as u64 >= initial_capacity * BUCKET_RESIZE_LOAD_FACTOR_PCT / 100;
        let expected_final_capacity = if expect_resize {
            initial_capacity * BUCKET_RESIZE_MULTIPLIER
        } else {
            initial_capacity
        };

        // Create reference state
        let reader = EmptySalt;
        let mut ref_state = EphemeralSaltState::new(&reader);
        let mut ref_updates = StateUpdates::default();

        // Set up bucket with specified capacity
        ref_state
            .shi_rehash(TEST_BUCKET, 0, initial_capacity, &mut ref_updates)
            .unwrap();

        // Create test key-value pairs
        let keys: Vec<Vec<u8>> = (1..=num_keys).map(|i| vec![i as u8; 32]).collect();
        let vals: Vec<Vec<u8>> = (11..=11 + num_keys - 1)
            .map(|i| vec![i as u8; 32])
            .collect();

        // Insert in original order to create reference state
        for i in 0..keys.len() {
            ref_state
                .shi_upsert(TEST_BUCKET, &keys[i], &vals[i], &mut ref_updates)
                .unwrap();
        }

        // Verify the final capacity matches expectation
        let final_meta = ref_state.metadata(TEST_BUCKET, false).unwrap();
        assert_eq!(
            final_meta.capacity, expected_final_capacity,
            "Expected capacity {} after inserting {} keys into bucket with initial capacity {}",
            expected_final_capacity, num_keys, initial_capacity
        );

        // Verify all key-value pairs are present in reference state with correct values
        verify_all_keys_present(
            &mut ref_state,
            TEST_BUCKET,
            0,
            final_meta.capacity,
            &keys,
            &vals,
        );

        // Test multiple different random insertion orders
        for iteration in 0..num_iterations {
            let reader = EmptySalt;
            let mut test_state = EphemeralSaltState::new(&reader);
            let mut test_updates = StateUpdates::default();

            // Set up bucket with same initial capacity
            test_state
                .shi_rehash(TEST_BUCKET, 0, initial_capacity, &mut test_updates)
                .unwrap();

            // Create shuffled order of indices
            let mut indices: Vec<usize> = (0..keys.len()).collect();
            indices.shuffle(&mut thread_rng());

            // Insert in shuffled order
            for &i in &indices {
                test_state
                    .shi_upsert(TEST_BUCKET, &keys[i], &vals[i], &mut test_updates)
                    .unwrap();
            }

            // Verify final metadata matches reference state exactly
            let test_meta = test_state.metadata(TEST_BUCKET, false).unwrap();
            assert_eq!(
                test_meta, final_meta,
                "Iteration {}: Final metadata should match reference state",
                iteration
            );

            // Verify all keys are accessible with correct values and locations
            for i in 0..keys.len() {
                let ref_find = ref_state
                    .shi_find(TEST_BUCKET, 0, final_meta.capacity, &keys[i])
                    .unwrap();
                let test_find = test_state
                    .shi_find(TEST_BUCKET, 0, final_meta.capacity, &keys[i])
                    .unwrap();
                assert_eq!(
                    ref_find, test_find,
                    "Iteration {}: Key {} should be found in same location with same value",
                    iteration, i
                );
            }
        }
    }

    /// Test insertion order independence with small bucket and no resize.
    ///
    /// Verifies that a hash table produces identical final state regardless of the
    /// insertion order of key-value pairs. Uses a small bucket (capacity=8) with
    /// 5 key-value pairs to stay well below the resize threshold, and tests 10
    /// different random insertion orders.
    #[test]
    fn test_insertion_order_independence_small_bucket() {
        test_insertion_order_independence(8, 5, 10);
    }

    /// Test insertion order independence when bucket resize is triggered.
    ///
    /// Verifies that a hash table maintains insertion order independence even when
    /// bucket resizing occurs during insertion. Uses a small bucket (capacity=8) with
    /// 10 key-value pairs to exceed the 80% load factor threshold and trigger resize
    /// to capacity=16. Tests 10 different random insertion orders.
    #[test]
    fn test_insertion_order_independence_with_resize() {
        test_insertion_order_independence(8, 10, 10);
    }

    /// Test history independence with mixed insert, update, and delete operations.
    ///
    /// ## Test Scenario
    /// This test verifies that a hash table produces identical final state regardless
    /// of the order in which mixed operations (insert, update, delete) are performed.
    ///
    /// ## Initial State
    /// - Bucket capacity: 12 slots (smaller capacity to create more collisions)
    /// - Pre-populated with 6 key-value pairs:
    ///   - Key 1 → Value 11
    ///   - Key 2 → Value 12
    ///   - Key 3 → Value 13
    ///   - Key 4 → Value 14
    ///   - Key 5 → Value 15
    ///   - Key 6 → Value 16
    ///
    /// ## Operations Applied (in various orders)
    /// 1. **Delete operations**: Remove keys 3 and 6
    /// 2. **Update operations**:
    ///    - Update key 1 from value 11 to 100
    ///    - Update key 4 from value 14 to 200
    /// 3. **Insert operations**: Add new keys:
    ///    - Key 7 → Value 17
    ///    - Key 8 → Value 18
    ///    - Key 9 → Value 19
    ///
    /// ## Expected Final State (after all operations)
    /// - Key 1 → Value 100 (updated)
    /// - Key 2 → Value 12 (unchanged)
    /// - Key 4 → Value 200 (updated)
    /// - Key 5 → Value 15 (unchanged)
    /// - Key 7 → Value 17 (newly inserted)
    /// - Key 8 → Value 18 (newly inserted)
    /// - Key 9 → Value 19 (newly inserted)
    /// - Keys 3, 6 → Not present (deleted)
    ///
    /// ## Verification Strategy
    /// 1. Apply operations in reference order to create baseline state
    /// 2. For 10 iterations, shuffle operations randomly and apply to fresh state
    /// 3. Verify that each key exists in same slot with same value across all orderings
    /// 4. Verify that deleted keys are absent in all states
    ///
    /// This comprehensive test ensures the SHI (Strongly History-Independent) property
    /// holds for real-world scenarios involving all types of hash table operations.
    #[test]
    fn test_history_independence_with_mixed_operations() {
        use rand::seq::SliceRandom;
        use rand::thread_rng;

        const BUCKET_CAPACITY: u64 = 12;

        #[derive(Clone, Debug)]
        enum Op {
            Delete(u8),
            Update(u8, u8),
            Insert(u8, u8),
        }

        // Initial data: keys 1-6 with values 11-16
        let initial_data: Vec<(u8, u8)> = (1..=6).zip(11..=16).collect();

        // Operations: delete keys 3,6; update keys 1,4; insert keys 7-9
        let operations = vec![
            Op::Delete(3),
            Op::Delete(6),
            Op::Update(1, 100),
            Op::Update(4, 200),
            Op::Insert(7, 17),
            Op::Insert(8, 18),
            Op::Insert(9, 19),
        ];

        // Create reference state
        let reader = EmptySalt;
        let mut ref_state = EphemeralSaltState::new(&reader);
        let mut ref_updates = StateUpdates::default();

        ref_state
            .shi_rehash(TEST_BUCKET, 0, BUCKET_CAPACITY, &mut ref_updates)
            .unwrap();
        for (k, v) in &initial_data {
            ref_state
                .shi_upsert(TEST_BUCKET, &vec![*k; 32], &vec![*v; 32], &mut ref_updates)
                .unwrap();
        }
        for op in &operations {
            match op {
                Op::Delete(k) => {
                    ref_state
                        .shi_delete(TEST_BUCKET, &vec![*k; 32], &mut ref_updates)
                        .unwrap();
                }
                Op::Update(k, v) | Op::Insert(k, v) => {
                    ref_state
                        .shi_upsert(TEST_BUCKET, &vec![*k; 32], &vec![*v; 32], &mut ref_updates)
                        .unwrap();
                }
            }
        }
        let ref_meta = ref_state.metadata(TEST_BUCKET, false).unwrap();

        // Verify reference state has all expected final key-value pairs
        let expected_keys: Vec<Vec<u8>> = vec![
            vec![1; 32],
            vec![2; 32],
            vec![4; 32],
            vec![5; 32],
            vec![7; 32],
            vec![8; 32],
            vec![9; 32],
        ];
        let expected_values: Vec<Vec<u8>> = vec![
            vec![100; 32],
            vec![12; 32],
            vec![200; 32],
            vec![15; 32],
            vec![17; 32],
            vec![18; 32],
            vec![19; 32],
        ];
        verify_all_keys_present(
            &mut ref_state,
            TEST_BUCKET,
            0,
            ref_meta.capacity,
            &expected_keys,
            &expected_values,
        );

        // Test 10 random operation orders
        for iteration in 0..10 {
            let mut shuffled = operations.clone();
            shuffled.shuffle(&mut thread_rng());

            let test_reader = EmptySalt;
            let mut test_state = EphemeralSaltState::new(&test_reader);
            let mut test_updates = StateUpdates::default();

            test_state
                .shi_rehash(TEST_BUCKET, 0, BUCKET_CAPACITY, &mut test_updates)
                .unwrap();
            for (k, v) in &initial_data {
                test_state
                    .shi_upsert(TEST_BUCKET, &vec![*k; 32], &vec![*v; 32], &mut test_updates)
                    .unwrap();
            }
            for op in &shuffled {
                match op {
                    Op::Delete(k) => {
                        test_state
                            .shi_delete(TEST_BUCKET, &vec![*k; 32], &mut test_updates)
                            .unwrap();
                    }
                    Op::Update(k, v) | Op::Insert(k, v) => {
                        test_state
                            .shi_upsert(
                                TEST_BUCKET,
                                &vec![*k; 32],
                                &vec![*v; 32],
                                &mut test_updates,
                            )
                            .unwrap();
                    }
                }
            }

            assert_eq!(
                test_state.metadata(TEST_BUCKET, false).unwrap().capacity,
                ref_meta.capacity
            );

            // Expected final keys: 1(100), 2(12), 4(200), 5(15), 7(17), 8(18), 9(19)
            for (k, _) in [
                (1, 100),
                (2, 12),
                (4, 200),
                (5, 15),
                (7, 17),
                (8, 18),
                (9, 19),
            ] {
                let key = vec![k; 32];
                let ref_find = ref_state
                    .shi_find(TEST_BUCKET, 0, ref_meta.capacity, &key)
                    .unwrap();
                let test_find = test_state
                    .shi_find(TEST_BUCKET, 0, ref_meta.capacity, &key)
                    .unwrap();
                assert_eq!(
                    ref_find, test_find,
                    "Iteration {}: Key {} mismatch",
                    iteration, k
                );
            }

            // Verify deleted keys don't exist
            for k in [3, 6] {
                let key = vec![k; 32];
                assert_eq!(
                    ref_state
                        .shi_find(TEST_BUCKET, 0, ref_meta.capacity, &key)
                        .unwrap(),
                    None
                );
                assert_eq!(
                    test_state
                        .shi_find(TEST_BUCKET, 0, ref_meta.capacity, &key)
                        .unwrap(),
                    None
                );
            }
        }
    }

    /// Comprehensive test for shi_rehash method covering various scenarios.
    #[test]
    fn test_shi_rehash_comprehensive() {
        // Test cases: (old_nonce, old_capacity, new_nonce, new_capacity, num_entries)
        let test_cases = [
            (0, 8, 0, 8, 0),  // Empty bucket, no change
            (0, 8, 1, 8, 5),  // Nonce change only
            (0, 8, 0, 16, 6), // Capacity expansion
            (0, 16, 0, 8, 5), // Capacity contraction (reduced entries to fit)
            (0, 8, 1, 16, 6), // Both nonce and capacity change
            (0, 8, 0, 8, 6),  // Near-full bucket
        ];

        for (old_nonce, old_capacity, new_nonce, new_capacity, num_entries) in test_cases {
            verify_rehash(
                old_nonce,
                old_capacity,
                new_nonce,
                new_capacity,
                num_entries,
            );
        }
    }

    /// Helper function to verify shi_rehash behavior for a specific configuration.
    fn verify_rehash(
        old_nonce: u32,
        old_capacity: u64,
        new_nonce: u32,
        new_capacity: u64,
        num_entries: usize,
    ) {
        let reader = EmptySalt;
        let mut state = EphemeralSaltState::new(&reader);
        let mut updates = StateUpdates::default();

        // Initialize bucket with old configuration
        state
            .shi_rehash(TEST_BUCKET, old_nonce, old_capacity, &mut updates)
            .unwrap();

        // Create test data - deterministic for reproducibility
        let keys: Vec<Vec<u8>> = (1..=num_entries).map(|i| vec![i as u8; 32]).collect();
        let vals: Vec<Vec<u8>> = (100..=100 + num_entries - 1)
            .map(|i| vec![i as u8; 32])
            .collect();

        // Insert test entries
        for i in 0..num_entries {
            state
                .shi_upsert(TEST_BUCKET, &keys[i], &vals[i], &mut updates)
                .unwrap();
        }

        // Verify initial state before rehash
        let old_meta = state.metadata(TEST_BUCKET, false).unwrap();
        assert_eq!(old_meta.nonce, old_nonce);
        assert_eq!(old_meta.capacity, old_capacity);

        // Perform rehash
        let mut rehash_updates = StateUpdates::default();
        state
            .shi_rehash(TEST_BUCKET, new_nonce, new_capacity, &mut rehash_updates)
            .unwrap();

        // Verify metadata after rehash
        let new_meta = state.metadata(TEST_BUCKET, false).unwrap();
        assert_eq!(new_meta.nonce, new_nonce, "Nonce should be updated");
        assert_eq!(
            new_meta.capacity, new_capacity,
            "Capacity should be updated"
        );

        // Verify all entries are preserved with correct values
        verify_all_keys_present(
            &mut state,
            TEST_BUCKET,
            new_nonce,
            new_capacity,
            &keys,
            &vals,
        );

        // Verify StateUpdates contains metadata change
        if old_nonce != new_nonce || old_capacity != new_capacity {
            let meta_key = bucket_metadata_key(TEST_BUCKET);
            assert!(
                rehash_updates.data.contains_key(&meta_key),
                "Rehash should update metadata in StateUpdates"
            );
        }
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

    /// Tests that `shi_next` correctly identifies displaced entries that should
    /// move closer to their ideal position.
    ///
    /// **Behavior under test**: The core SHI hashing invariant where entries
    /// with higher displacement (rank) from their ideal position get priority
    /// for movement during deletion operations.
    ///
    /// **Setup**: Entry at slot 2 that ideally belongs at slot 0 (displacement = 2)
    /// **Action**: Delete slot 1 (between ideal and current position)
    /// **Expected**: Returns the displaced entry because rank(current=2) > rank(del_slot=1)
    /// from ideal position 0
    ///
    /// **Invariant verified**:
    /// `rank(hashed_key, current_slot, capacity) > rank(hashed_key, del_slot, capacity)`
    /// implies the entry should be moved to del_slot for better positioning.
    #[test]
    fn test_shi_next_finds_displaced_entry() {
        let mut state = EphemeralSaltState::new(&EmptySalt);
        let capacity = 4;
        let nonce = 0;

        // Create a key that ideally belongs at slot 0
        let key_a = create_key_for_slot(0, nonce, capacity);
        let value_a = vec![0xFF; 32];

        // Place it at slot 2 (displaced by 2 positions)
        setup_bucket_layout(
            &mut state,
            TEST_BUCKET,
            vec![(2, Some(SaltValue::new(&key_a, &value_a)))],
        );

        // Test deletion at slot 1
        let result = state.shi_next(TEST_BUCKET, 1, nonce, capacity).unwrap();

        // Should find the displaced entry at slot 2
        assert!(result.is_some());
        let (found_slot, found_value) = result.unwrap();
        assert_eq!(found_slot, 2);
        assert_eq!(found_value.key(), &key_a);

        // Verify rank calculation: rank(hashed_key, 2, 4) > rank(hashed_key, 1, 4)
        let hashed_key = hasher::hash_with_nonce(&key_a, nonce);
        assert!(rank(hashed_key, 2, capacity) > rank(hashed_key, 1, capacity));
    }

    /// Tests that `shi_next` properly terminates when encountering an empty slot
    /// during linear probing.
    ///
    /// **Behavior under test**: Stop searching when an empty slot is found, since
    /// no qualified entries can exist beyond the first empty slot in a properly
    /// maintained SHI table.
    ///
    /// **Setup**: Entry at slot 0, empty slot at 1, entry at slot 3
    /// **Action**: Delete slot 0 (probe sequence: 1, 2, 3...)
    /// **Expected**: Returns None because probe stops at empty slot 1, never reaching slot 3
    #[test]
    fn test_shi_next_stops_at_empty_slot() {
        let mut state = EphemeralSaltState::new(&EmptySalt);
        let capacity = 4;
        let nonce = 0;

        // Create keys for specific slots
        let key_a = create_key_for_slot(0, nonce, capacity);
        let key_b = create_key_for_slot(2, nonce, capacity);

        // Setup: entry at slot 0, empty at slot 1, entry at slot 3 that ideally belongs at slot 2
        setup_bucket_layout(
            &mut state,
            TEST_BUCKET,
            vec![
                (0, Some(SaltValue::new(&key_a, &vec![0x01; 32]))),
                (1, None), // empty slot
                (3, Some(SaltValue::new(&key_b, &vec![0x02; 32]))),
            ],
        );

        // Delete slot 0, which should probe slot 1 first
        let result = state.shi_next(TEST_BUCKET, 0, nonce, capacity).unwrap();

        // Should return None because probe stops at empty slot 1
        assert_eq!(result, None);
    }

    /// Tests that `shi_next` correctly handles probe sequence wraparound at bucket boundaries.
    ///
    /// **Behavior under test**: Circular probing behavior where the linear probe sequence wraps
    /// from the end of the bucket (slot capacity-1) back to the beginning (slot 0).
    ///
    /// **Setup**: Entry at slot 0 that ideally belongs at slot 3 (wrapped during original insertion)
    /// **Action**: Delete slot 3 (the entry's ideal position)
    /// **Expected**: Finds entry at slot 0 because it would prefer to be at the deleted slot 3
    ///
    /// **Invariant verified**: Wraparound probing maintains consistent rank calculations across
    /// bucket boundaries, ensuring `rank(hashed_key, 0, capacity) > rank(hashed_key, 3, capacity)`
    /// when the ideal position is slot 3.
    #[test]
    fn test_shi_next_wraparound_at_boundary() {
        let mut state = EphemeralSaltState::new(&EmptySalt);
        let capacity = 4;
        let nonce = 0;

        // Create a key that ideally belongs at slot 3
        let key_a = create_key_for_slot(3, nonce, capacity);
        let value_a = vec![0xFF; 32];

        // Place it at slot 0 (it wrapped around when originally inserted)
        setup_bucket_layout(
            &mut state,
            TEST_BUCKET,
            vec![(0, Some(SaltValue::new(&key_a, &value_a)))],
        );

        // Delete slot 3 (its ideal position)
        let result = state.shi_next(TEST_BUCKET, 3, nonce, capacity).unwrap();

        // Should find the entry at slot 0 since it wants to be at slot 3
        assert!(result.is_some());
        let (found_slot, found_value) = result.unwrap();
        assert_eq!(found_slot, 0);
        assert_eq!(found_value.key(), &key_a);

        // Verify: rank from slot 0 to ideal 3 > rank from slot 3 to ideal 3
        let hashed_key = hasher::hash_with_nonce(&key_a, nonce);
        assert!(rank(hashed_key, 0, capacity) > rank(hashed_key, 3, capacity));
    }

    /// Tests that `shi_next` correctly skips over entries that wouldn't benefit
    /// from movement.
    ///
    /// **Behavior under test**: `shi_next` examines multiple entries during linear
    /// probing but only returns those that would improve their positioning by moving
    /// to the deletion slot.
    ///
    /// **Setup**:
    /// - Slot 2: Entry with ideal position 2 (already optimal, rank=0)
    /// - Slot 3: Entry with ideal position 0 (displaced by 3, rank=3)
    /// **Action**: Delete slot 1 (probe sequence: 2 → 3 → 0...)
    /// **Expected**: Skips slot 2 (no rank improvement: 0 vs 3) and returns slot 3 (rank improves: 3 → 1)
    #[test]
    fn test_shi_next_skips_non_suitable_entries() {
        let mut state = EphemeralSaltState::new(&EmptySalt);
        let capacity = 4;
        let nonce = 0;

        // Create keys with specific ideal positions
        let key_optimal = create_key_for_slot(2, nonce, capacity); // wants slot 2 (optimal)
        let key_displaced = create_key_for_slot(0, nonce, capacity); // wants slot 0 (displaced)

        // Setup bucket:
        // - Slot 2: Entry at its ideal position (rank=0, won't benefit from move to slot 1)
        // - Slot 3: Entry displaced from ideal slot 0 (rank=3, will benefit from move to slot 1)
        setup_bucket_layout(
            &mut state,
            TEST_BUCKET,
            vec![
                (2, Some(SaltValue::new(&key_optimal, &vec![0x02; 32]))),
                (3, Some(SaltValue::new(&key_displaced, &vec![0x03; 32]))),
            ],
        );

        // Delete slot 1 (probe sequence: 2 → 3 → 0...)
        let result = state.shi_next(TEST_BUCKET, 1, nonce, capacity).unwrap();

        // Should skip slot 2 (already optimal) and return slot 3 (benefits from move)
        assert!(result.is_some());
        let (found_slot, found_value) = result.unwrap();
        assert_eq!(found_slot, 3);
        assert_eq!(found_value.key(), &key_displaced);

        // Verify rank calculations:
        // - Slot 2 entry: rank(2->2)=0, rank(1->2)=3, no benefit (0 <= 3)
        // - Slot 3 entry: rank(3->0)=3, rank(1->0)=1, benefits (3 > 1)
        let optimal_hashed = hasher::hash_with_nonce(&key_optimal, nonce);
        let displaced_hashed = hasher::hash_with_nonce(&key_displaced, nonce);

        assert!(rank(optimal_hashed, 2, capacity) <= rank(optimal_hashed, 1, capacity));
        assert!(rank(displaced_hashed, 3, capacity) > rank(displaced_hashed, 1, capacity));
    }

    /// Tests that `shi_next` exhaustively scans all remaining slots when no suitable
    /// candidate is found.
    ///
    /// **Behavior under test**: Complete traversal behavior ensuring the algorithm
    /// doesn't miss potential candidates and correctly terminates with None after
    /// checking all possible positions.
    ///
    /// **Setup**: Full bucket where every entry is at its exact ideal position (perfect hash distribution)
    /// **Action**: Delete any slot (testing with slot 1)
    /// **Expected**: Returns None after scanning all remaining slots (0, 2, 3)
    ///
    /// **Invariant verified**: When `rank(hashed_key, current_slot, capacity) <=
    /// rank(hashed_key, del_slot, capacity)` for all entries, no movement should occur.
    #[test]
    fn test_shi_next_scans_all_slots() {
        let mut state = EphemeralSaltState::new(&EmptySalt);
        let capacity = 4;
        let nonce = 0;

        // Fill bucket with entries at their ideal positions
        let keys: Vec<_> = (0..capacity as SlotId)
            .map(|slot| create_key_for_slot(slot, nonce, capacity))
            .collect();

        let layout: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(slot, key)| {
                (
                    slot as SlotId,
                    Some(SaltValue::new(key, &vec![slot as u8; 32])),
                )
            })
            .collect();

        setup_bucket_layout(&mut state, TEST_BUCKET, layout);

        // Delete any slot (let's use slot 1)
        let result = state.shi_next(TEST_BUCKET, 1, nonce, capacity).unwrap();

        // Should return None after checking all remaining slots
        // because all entries are at their ideal positions
        assert_eq!(result, None);
    }

    /// Tests the `update_value` method for correct state tracking and cache updates.
    ///
    /// Verifies that `update_value` properly handles all value transition scenarios:
    /// - Insert (None → Some): Records new entry in StateUpdates
    /// - Update (Some → Some): Tracks value changes with original old_value
    /// - Delete (Some → None): Completes insert/delete roundtrip by removing from StateUpdates
    /// - No-ops (None → None, Some → Same): Skips recording when values are identical
    #[test]
    fn test_update_value() {
        let reader = EmptySalt;
        let mut state = EphemeralSaltState::new(&reader);
        let mut updates = StateUpdates::default();
        let key = (TEST_BUCKET, 1).into();
        let val1 = Some(SaltValue::new(&[1; 32], &[2; 32]));
        let val2 = Some(SaltValue::new(&[3; 32], &[4; 32]));

        // None → Some (insert)
        state.update_value(&mut updates, key, None, val1.clone());
        assert_eq!(updates.data.get(&key), Some(&(None, val1.clone())));

        // Some → Some different (update)
        state.update_value(&mut updates, key, val1.clone(), val2.clone());
        assert_eq!(updates.data.get(&key), Some(&(None, val2.clone())));

        // Some → None (delete)
        state.update_value(&mut updates, key, val2, None);
        assert_eq!(updates.data.get(&key), None); // Full roundtrip

        // No-op cases (no updates recorded)
        let prev_len = updates.data.len();
        state.update_value(&mut updates, key, None, None);
        state.update_value(&mut updates, key, val1.clone(), val1);
        assert_eq!(updates.data.len(), prev_len);
    }

    // ============================
    // Test Utility Functions
    // ============================

    /// Helper to create a key that hashes to a specific slot for testing.
    /// Uses a simple approach: tries incrementing key values until finding one
    /// that hashes to the desired slot.
    fn create_key_for_slot(ideal_slot: SlotId, nonce: u32, capacity: u64) -> Vec<u8> {
        for i in 0..1000u32 {
            let key = i.to_le_bytes().to_vec();
            let hashed_key = hasher::hash_with_nonce(&key, nonce);
            if probe(hashed_key, 0, capacity) == ideal_slot {
                return key;
            }
        }
        panic!(
            "Could not find key for slot {} with nonce {} capacity {}",
            ideal_slot, nonce, capacity
        );
    }

    /// Helper to visualize bucket state for debugging tests.
    #[allow(dead_code)]
    fn print_bucket_state(
        state: &mut EphemeralSaltState<impl StateReader>,
        bucket_id: BucketId,
        capacity: u64,
        nonce: u32,
    ) {
        println!("Bucket {} layout (capacity={}):", bucket_id, capacity);
        for slot in 0..capacity {
            let salt_key = (bucket_id, slot).into();
            let entry = state.value(salt_key).unwrap();
            match entry {
                Some(val) => {
                    let hashed_key = hasher::hash_with_nonce(val.key(), nonce);
                    let ideal = probe(hashed_key, 0, capacity);
                    let displacement = rank(hashed_key, slot, capacity);
                    println!(
                        "  Slot {}: Key {:?} (ideal={}, displacement={})",
                        slot,
                        val.key(),
                        ideal,
                        displacement
                    );
                }
                None => println!("  Slot {}: empty", slot),
            }
        }
    }

    /// Helper to set up a bucket with specific entry placements for testing.
    fn setup_bucket_layout(
        state: &mut EphemeralSaltState<impl StateReader>,
        bucket_id: BucketId,
        layout: Vec<(SlotId, Option<SaltValue>)>,
    ) {
        for (slot, value) in layout {
            let salt_key = (bucket_id, slot).into();
            state.cache.insert(salt_key, value);
        }
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
}
