//! This module provides two major functionalities:
//! (1) Use plain keys to access the current blockchain state,
//!     which is stored in some storage backend in SALT format.
//! (2) Tentatively update the current state and accumulate the
//!     resulting incremental changes in memory.
use super::updates::StateUpdates;
use crate::{constant::BUCKET_SLOT_BITS, traits::StateReader, types::*};
use std::{
    cmp::Ordering,
    collections::{hash_map::Entry, HashMap},
};
use tracing::info;

/// A non-persistent SALT state snapshot.
///
/// This allows users to tentatively update some SALT state without actually
/// modifying it (the resulting changes are buffered in memory).
#[derive(Debug)]
pub struct EphemeralSaltState<'a, BaseState> {
    /// Base state to apply incremental changes. Typically backed
    /// by a persistent storage backend.
    base_state: &'a BaseState,
    /// Cache the values of datas and bucket metas read from `base_state`
    /// and the changes made to it.
    pub(crate) cache: HashMap<SaltKey, Option<SaltValue>>,
    /// Whether to save access records
    save_access: bool,
}

/// Implement the `Clone` trait for `EphemeralSaltState`.
impl<BaseState> Clone for EphemeralSaltState<'_, BaseState> {
    fn clone(&self) -> Self {
        Self {
            base_state: self.base_state,
            cache: self.cache.clone(),
            save_access: self.save_access,
        }
    }
}

impl<'a, BaseState: StateReader> EphemeralSaltState<'a, BaseState> {
    /// Create a [`EphemeralSaltState`] object.
    pub fn new(reader: &'a BaseState) -> Self {
        Self {
            base_state: reader,
            cache: HashMap::new(),
            save_access: true,
        }
    }

    /// After calling `extend_cache`, the state will be updated to `state`.
    pub fn extend_cache(mut self, state_updates: &StateUpdates) -> Self {
        for (k, (_, v)) in &state_updates.data {
            self.cache
                .entry(*k)
                .and_modify(|change| *change = v.clone())
                .or_insert_with(|| v.clone());
        }
        self
    }

    /// Create a [`EphemeralSaltState`] object with the given cache.
    pub fn with_cache(self, cache: HashMap<SaltKey, Option<SaltValue>>) -> Self {
        Self { cache, ..self }
    }

    /// Create a [`EphemeralSaltState`] object with the given `save_access` flag.
    pub fn with_record_access(self, save_access: bool) -> Self {
        Self {
            save_access,
            ..self
        }
    }

    /// Consumes the state and returns the underlying cache containing all changes made to the base
    /// state.
    pub fn consume_cache(self) -> HashMap<SaltKey, Option<SaltValue>> {
        self.cache
    }

    /// Return the plain value associated with the given plain key.
    pub fn get_raw(&mut self, plain_key: &[u8]) -> Result<Option<Vec<u8>>, BaseState::Error> {
        // Computes the `bucket_id` based on the `key`.
        let bucket_id = pk_hasher::bucket_id(plain_key);
        let metadata = match self.get_entry(bucket_metadata_key(bucket_id))? {
            Some(v) => v.try_into().expect("Failed to decode bucket metadata"),
            // FIXME: this is highly inefficient & unnecessary; get_raw doesn't need "used"
            // calling base_state.metadata is basically repeating the work of get_entry() -> base_state.value()
            None => self.base_state.metadata(bucket_id)?,
        };
        // let meta = self.salt_state.meta(bucket_id)?;
        // Calculates the `hashed_id`(the initial slot position) based on the `key` and `nonce`.
        let hashed_id = pk_hasher::hashed_key(plain_key, metadata.nonce);

        // Starts from the initial slot position and searches for the slot corresponding to the
        // `key`.
        for step in 0..metadata.capacity {
            let slot_id = probe(hashed_id, step, metadata.capacity);
            if let Some(slot_val) = self.get_entry((bucket_id, slot_id).into())? {
                match slot_val.key().cmp(plain_key) {
                    Ordering::Less => return Ok(None),
                    // FIXME: no need to copy out the value using "to_vec()"; leave that decision to the caller!
                    Ordering::Equal => return Ok(Some(slot_val.value().to_vec())),
                    Ordering::Greater => (),
                }
            } else {
                return Ok(None);
            }
        }
        Ok(None)
    }

    /// Update the SALT state with the given set of `PlainKey`'s and `PlainValue`'s
    /// (following the semantics of EVM storage, empty values indicate deletions).
    /// Return the resulting changes of the affected SALT bucket entries.
    pub fn update<'b>(
        &mut self,
        kvs: impl IntoIterator<Item = (&'b Vec<u8>, &'b Option<Vec<u8>>)>,
    ) -> Result<StateUpdates, BaseState::Error> {
        let mut state_updates = StateUpdates::default();
        for (key_bytes, value_bytes) in kvs {
            let bucket_id = pk_hasher::bucket_id(key_bytes);

            // Get the meta corresponding to the bucket_id
            let mut meta = match self.get_entry(bucket_metadata_key(bucket_id))? {
                // FIXME: this seems buggy; if the code goes here, meta.used must be None
                // how come existing test case not fail!? NEED TO ENHANCE THE TESTS!!!
                Some(v) => v.try_into().expect("Failed to decode bucket metadata"),
                // FIXME: calling base_state.metadata() is also wrong! what if self.cache
                // contains updates that modify "used"?
                // Solution: maintain a HashMap from BucketId to u64 (used); whenever a bucket
                // metadata is accessed, cache its used in this new HashMap; update this hashmap
                // upon self.upsert; and when you need to read metadata, combine the cached "used"
                // with cached "nonce + capacity"
                None => self.base_state.metadata(bucket_id)?,
            };
            match value_bytes {
                Some(value_bytes) => {
                    self.upsert(
                        bucket_id,
                        &mut meta,
                        key_bytes.clone(),
                        value_bytes.clone(),
                        &mut state_updates,
                    )?;
                }
                None => self.delete(bucket_id, &mut meta, key_bytes.clone(), &mut state_updates)?,
            }
        }
        Ok(state_updates)
    }

    /// Inserts or updates a plain key-value pair in the given bucket. This method
    /// implements the SHI hash table insertion algorithm described in the paper.
    fn upsert(
        &mut self,
        bucket_id: BucketId,
        meta: &mut BucketMeta,
        mut pending_key: Vec<u8>,
        mut pending_value: Vec<u8>,
        out_updates: &mut StateUpdates,
    ) -> Result<(), BaseState::Error> {
        let hashed_key = pk_hasher::hashed_key(&pending_key, meta.nonce);

        // Explores all slots until a suitable one is found. If no suitable slot is found,
        // resizing is required. Iterates through all slots to find a suitable location for
        // the key-value pair. If no empty slot is found, indicating that the table is full,
        // the function triggers a resize operation.
        for step in 0..meta.capacity {
            let salt_id = (bucket_id, probe(hashed_key, step, meta.capacity)).into();
            let slot_val = self.get_entry(salt_id)?;

            // During the process, the size of the key is
            // compared with existing keys:
            // - If the key is equal, the value is updated and the function returns.
            // - If the key is greater, the exploration continues to the next slot.
            // - If the key is less, the key-value pair is swapped and the exploration continues to
            // the next slot.
            // - If a slot is empty, the new key-value pair is inserted and the function returns.
            if let Some(val) = slot_val {
                match val.key().cmp(&pending_key) {
                    Ordering::Equal => {
                        self.update_entry(
                            out_updates,
                            salt_id,
                            Some(val),
                            Some(SaltValue::new(&pending_key, &pending_value)),
                        );
                        return Ok(());
                    }
                    Ordering::Less => {
                        // exchange the slot key & value with pending key & value, and then
                        // shift to next slot for further operation.
                        self.update_entry(
                            out_updates,
                            salt_id,
                            Some(val.clone()),
                            Some(SaltValue::new(&pending_key, &pending_value)),
                        );
                        (pending_key, pending_value) = (val.key().to_vec(), val.value().to_vec());
                    }
                    _ => (),
                }
            } else {
                self.update_entry(
                    out_updates,
                    salt_id,
                    None,
                    Some(SaltValue::new(&pending_key, &pending_value)),
                );

                let used = meta
                    .used
                    .expect("BucketMeta.used should always be populated");
                // if the used of the bucket exceeds 4/5 of the capacity, resize the bucket.
                if used >= meta.capacity * 4 / 5 && meta.capacity < (1 << BUCKET_SLOT_BITS) {
                    // double the capacity of the bucket.
                    info!(
                        "bucket_id {} capacity extend from {} to {}",
                        bucket_id,
                        meta.capacity,
                        meta.capacity << 1
                    );
                    self.rehash(
                        bucket_id,
                        meta,
                        &mut BucketMeta {
                            capacity: meta.capacity * 2,
                            ..*meta
                        },
                        out_updates,
                    )?;

                    meta.capacity <<= 1;
                }
                meta.used = Some(used + 1);
                return Ok(());
            }
        }

        unreachable!("bucket {} capacity {} too large", bucket_id, meta.capacity);
    }

    /// Deletes a plain key from the given bucket. This method implements
    /// the SHI hash table deletion algorithm described in the paper.
    fn delete(
        &mut self,
        bucket_id: BucketId,
        meta: &mut BucketMeta,
        key: Vec<u8>,
        out_updates: &mut StateUpdates,
    ) -> Result<(), BaseState::Error> {
        let find_slot = self.find(bucket_id, meta, &key)?;

        if let Some((slot_id, slot_val)) = find_slot {
            let old_used = meta
                .used
                .expect("BucketMeta.used should always be populated");
            meta.used = Some(old_used.saturating_sub(1));
            let mut delete_slot = (slot_id, slot_val);

            // Iterates over all slots in the table until a suitable slot is found.
            // If a suitable slot is found, it is swapped with the delete slot.
            // The process repeats until no more suitable slots are found, and then
            // the delete slot is cleared.
            //
            // [..(delete_slot)......(suitable_slot)....]
            //        ^--------<-->---------^
            // delete_slot = suitable_slot , suitable_slot = delete_slot, repeats until
            // no more suitable slots are found.
            for _i in 0..meta.capacity {
                // Searches for the next suitable slot to transfer to the delete slot.
                let suitable_slot =
                    self.next(bucket_id, delete_slot.0, meta.nonce, meta.capacity)?;
                let salt_id = (bucket_id, delete_slot.0).into();
                match suitable_slot {
                    Some((slot_id, slot_value)) => {
                        // Swap the delete slot with the suitable slot and continue the
                        // exploration.
                        self.update_entry(
                            out_updates,
                            salt_id,
                            Some(delete_slot.1),
                            Some(slot_value.clone()),
                        );
                        delete_slot = (slot_id, slot_value);
                    }
                    None => {
                        // If no suitable slot is found, the delete slot is cleared.
                        self.update_entry(out_updates, salt_id, Some(delete_slot.1), None);
                        return Ok(());
                    }
                }
            }
        }
        Ok(())
    }

    /// rehash the bucket with the new meta.
    fn rehash(
        &mut self,
        bucket_id: u32,
        old_meta: &BucketMeta,
        new_meta: &mut BucketMeta,
        out_updates: &mut StateUpdates,
    ) -> Result<(), BaseState::Error> {
        // Merge the original bucket's data with the change records to create a new bucket state
        // Clear the original bucket's data, then insert the updated data with the new metadata
        // into the new state.
        // The state's cache marks the original data as empty, allowing the state to treat the
        // original data as deleted, while out_updates records this change process (Old, None)

        // create a new state of the bucket with the updates, and clear entries from cache and
        // out_updates
        let mut old_data = vec![];
        let mut new_state: HashMap<SaltKey, SaltValue> = self
            .base_state
            .entries(
                SaltKey::from((bucket_id, 0))..=SaltKey::from((bucket_id, old_meta.capacity - 1)),
            )?
            .into_iter()
            .filter_map(|(k, old_v)| {
                // clear entries from cache
                self.cache.remove(&k);
                old_data.push((k, old_v.clone()));

                // Update new_state based on the change records in out_updates
                match out_updates.data.remove(&k) {
                    Some((_, Some(new_v))) => Some((k, new_v)),
                    Some((_, None)) => None,
                    _ => Some((k, old_v)),
                }
            })
            .collect();

        // After clear entries by old bucket state, clear new entries from the cache and
        // out_updates, update these changes to new state.
        self.cache.retain(|k, _| {
            if k.bucket_id() == bucket_id {
                if let Some((_, Some(new_v))) = out_updates.data.remove(k) {
                    new_state.insert(*k, new_v);
                }
                false
            } else {
                true
            }
        });

        // Updating the state cache's value to None is equivalent to clearing the bucket,
        // so that during the next access, it can directly get None from the cache
        for (k, old_v) in old_data {
            self.cache.insert(k, None);
            out_updates.data.insert(k, (Some(old_v), None));
        }

        // update the state with the new entry
        new_meta.used = Some(0);
        new_state.into_iter().try_for_each(|(_, v)| {
            self.upsert(
                bucket_id,
                new_meta,
                v.key().to_vec(),
                v.value().to_vec(),
                out_updates,
            )
        })?;

        // Add meta change to the updates
        self.update_entry(
            out_updates,
            bucket_metadata_key(bucket_id),
            Some((*old_meta).into()),
            Some((*new_meta).into()),
        );

        Ok(())
    }

    /// Read the bucket entry of the given SALT key. Always look up `cache` before `base_state`.
    #[inline(always)]
    pub fn get_entry(&mut self, key: SaltKey) -> Result<Option<SaltValue>, BaseState::Error> {
        let value = match self.cache.entry(key) {
            Entry::Occupied(entry) => entry.into_mut().clone(),
            Entry::Vacant(entry) => {
                let value = self.base_state.value(key)?;
                if self.save_access {
                    entry.insert(value.clone());
                }
                value
            }
        };

        Ok(value)
    }

    /// Updates the bucket entry and records the change in `out_updates`.
    #[inline(always)]
    pub fn update_entry(
        &mut self,
        out_updates: &mut StateUpdates,
        key: SaltKey,
        old_value: Option<SaltValue>,
        new_value: Option<SaltValue>,
    ) {
        // we only record the change if the old value is different from the new value, unless there
        // will be empty salt deltas.
        if old_value != new_value {
            out_updates.add(key, old_value, new_value.clone());
            self.cache.insert(key, new_value);
        }
    }

    /// Finds the given plain key in a bucket. Returns the corresponding entry and its index, if
    /// any.
    pub(crate) fn find(
        &mut self,
        bucket_id: BucketId,
        meta: &BucketMeta,
        plain_key: &[u8],
    ) -> Result<Option<(SlotId, SaltValue)>, BaseState::Error> {
        let hashed_key = pk_hasher::hashed_key(plain_key, meta.nonce);

        // Search the key sequentially until we find it or are certain it doesn't exist
        // (either the current slot is empty or the key it contains has a lower priority
        // than the target key).
        for step in 0..meta.capacity {
            let slot_id = probe(hashed_key, step, meta.capacity);
            if let Some(entry) = self.get_entry((bucket_id, slot_id).into())? {
                match entry.key().cmp(plain_key) {
                    Ordering::Less => return Ok(None),
                    Ordering::Equal => return Ok(Some((slot_id, entry))),
                    Ordering::Greater => (),
                }
            } else {
                return Ok(None);
            }
        }
        Ok(None)
    }

    /// Finds the SALT value that will be moved into `slot_id` once the current value is deleted.
    #[inline(always)]
    fn next(
        &mut self,
        bucket_id: BucketId,
        slot_id: SlotId,
        nonce: u32,
        capacity: u64,
    ) -> Result<Option<(u64, SaltValue)>, BaseState::Error> {
        for i in 0..capacity {
            let next_slot_id = (slot_id + 1 + i as SlotId) & (capacity as SlotId - 1);
            let salt_key = (bucket_id, next_slot_id).into();
            let entry = self.get_entry(salt_key)?;
            match entry {
                // check next slot is suitable to store or not
                Some(entry) => {
                    let hashed_id = pk_hasher::hashed_key(entry.key(), nonce);

                    // Compares the weight of the next slot position with the weight of
                    // `cur_slot_id`.
                    if rank(hashed_id, next_slot_id, capacity) > rank(hashed_id, slot_id, capacity)
                    {
                        // If the weight is greater, it returns the current slot and slot value.
                        return Ok(Some((next_slot_id, entry)));
                    }
                }
                None => return Ok(None),
            }
        }
        Ok(None)
    }
}

/// Returns the i-th slot in the probe sequence of `hashed_key`. Our SHI hash table
/// uses linear probing to address key collisions, so `i` is used as an offset. Since
/// the first slot of each bucket is reserved for metadata (i.e., nonce & capacity),
/// the returned value must be in the range of [1, bucket size).
#[inline(always)]
pub(crate) fn probe(hashed_key: u64, i: u64, capacity: u64) -> SlotId {
    ((hashed_key + i) & (capacity - 1)) as SlotId
}

/// This function is the inverse of probe: i.e.,
/// ```rank(hashed_key, slot_id, bucket_size) = i``` iff.
/// ```probe(hashed_key, i, bucket_size) = slot_id```
#[inline(always)]
fn rank(hashed_key: u64, slot_id: SlotId, capacity: u64) -> SlotId {
    let first = probe(hashed_key, 0, capacity);
    if slot_id >= first {
        slot_id - first
    } else {
        slot_id + capacity - first
    }
}

/// Provides utility functions to convert plain keys to hashed keys (and eventually SALT keys).
pub mod pk_hasher {
    use crate::constant::{NUM_KV_BUCKETS, NUM_META_BUCKETS};
    use megaeth_ahash::RandomState;
    use std::hash::{BuildHasher, Hasher};

    use super::BucketId;

    /// Use the lower 32 bytes of keccak256("Make Ethereum Great Again") as the seed values.
    const HASHER_SEED_0: u64 = 0x921321f4;
    const HASHER_SEED_1: u64 = 0x2ccb667e;
    const HASHER_SEED_2: u64 = 0x60d68842;
    const HASHER_SEED_3: u64 = 0x077ada9d;

    /// Hash the given byte string.
    #[inline(always)]
    pub(crate) fn hash(bytes: &[u8]) -> u64 {
        static HASH_BUILDER: RandomState =
            RandomState::with_seeds(HASHER_SEED_0, HASHER_SEED_1, HASHER_SEED_2, HASHER_SEED_3);

        let mut hasher = HASH_BUILDER.build_hasher();
        hasher.write(bytes);
        hasher.finish()
    }

    /// Convert the plain key to a hashed key using the given bucket nonce.
    /// The resulting hashed key will be used to search for the final bucket
    /// location (i.e., the SALT key) where the plain key will be placed.
    #[inline(always)]
    pub(crate) fn hashed_key(plain_key: &[u8], nonce: u32) -> u64 {
        let mut data = plain_key.to_vec();
        data.extend_from_slice(&nonce.to_le_bytes());

        hash(&data)
    }

    /// Locate the bucket where the given plain key resides.
    #[inline(always)]
    pub fn bucket_id(key: &[u8]) -> BucketId {
        (hash(key) % NUM_KV_BUCKETS as u64 + NUM_META_BUCKETS as u64) as BucketId
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
            state::{pk_hasher, probe, rank, EphemeralSaltState},
            updates::StateUpdates,
        },
        traits::StateReader,
        types::*,
    };
    use rand::Rng;

    const KEYS_NUM: usize = 3 * MIN_BUCKET_SIZE - 1;
    const BUCKET_ID: BucketId = NUM_META_BUCKETS as BucketId + 1;

    // FIXME: need a unit test to fix the hash function we used to compute bucket id; avoid accidental hash change

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
        for slot_id in 0..MIN_BUCKET_SIZE {
            let salt_id = (bucket_id, slot_id as SlotId).into();
            if table1.get_entry(salt_id).unwrap() != table2.get_entry(salt_id).unwrap() {
                return false;
            }
        }
        true
    }

    #[test]
    fn check_extend_cache() {
        let reader = EmptySalt;
        let mock_db = MemStore::new();
        let mut state = EphemeralSaltState::new(&reader);
        let mut meta = BucketMeta {
            used: Some(0),
            ..BucketMeta::default()
        };

        for _ in 0..3 {
            let mut state1 = EphemeralSaltState::new(&mock_db);
            let kvs = create_random_kvs(40);
            let mut state_updates = StateUpdates::default();
            //Insert KEYS_NUM key-value pairs into table 65538 of state
            for (k, v) in kvs.0.into_iter().zip(kvs.1.into_iter()) {
                state1
                    .upsert(65538, &mut meta, k, v, &mut state_updates)
                    .unwrap();
            }

            state = state.extend_cache(&state_updates);
            mock_db.update_state(state_updates);

            assert!(is_bucket_eq(65538, &mut state, &mut state1));
        }
    }

    #[test]
    fn probe_and_rank_work() {
        let hashed_key = 123456u64;
        let bucket_size = MIN_BUCKET_SIZE as u64;

        for i in 0..bucket_size - 1 {
            let slot_id = probe(hashed_key, i, bucket_size);
            let j = rank(hashed_key, slot_id, bucket_size);
            assert_eq!(i, j as u64);
        }
    }

    #[test]
    fn insert_with_diff_order() {
        let (keys, vals) = create_random_kvs(KEYS_NUM);
        let reader = EmptySalt;
        let mut meta = BucketMeta {
            used: Some(0),
            ..BucketMeta::default()
        };
        let mut state = EphemeralSaltState::new(&reader);
        let mut out_updates = StateUpdates::default();
        //Insert KEYS_NUM key-value pairs into table 0 of state
        for i in 0..keys.len() {
            state
                .upsert(
                    BUCKET_ID,
                    &mut meta,
                    keys[i].clone(),
                    vals[i].clone(),
                    &mut out_updates,
                )
                .unwrap();
        }

        for _i in 0..2 {
            let reader = EmptySalt;
            let mut cmp_state = EphemeralSaltState::new(&reader);
            let mut out_updates = StateUpdates::default();
            // Rearrange the order of keys and vals
            let (rand_keys, rand_vals) = reorder_keys(keys.clone(), vals.clone());
            let mut meta = BucketMeta {
                used: Some(0),
                ..BucketMeta::default()
            };

            // Insert the reordered keys and vals into table 0
            (0..rand_keys.len()).for_each(|i| {
                cmp_state
                    .upsert(
                        BUCKET_ID,
                        &mut meta,
                        rand_keys[i].clone(),
                        rand_vals[i].clone(),
                        &mut out_updates,
                    )
                    .unwrap();
            });

            assert!(
                is_bucket_eq(BUCKET_ID, &mut state, &mut cmp_state),
                "The two tables should be equal"
            );
        }
    }

    #[test]
    fn delete_with_diff_order() {
        let mut rng = rand::thread_rng();
        let (keys, vals) = create_random_kvs(KEYS_NUM);
        let reader = EmptySalt;
        let mut state = EphemeralSaltState::new(&reader);
        let mut out_updates = StateUpdates::default();
        let mut meta = BucketMeta {
            used: Some(0),
            ..BucketMeta::default()
        };

        //Insert KEYS_NUM key-value pairs into table 0 of state
        for i in 0..keys.len() {
            state
                .upsert(
                    BUCKET_ID,
                    &mut meta,
                    keys[i].clone(),
                    vals[i].clone(),
                    &mut out_updates,
                )
                .unwrap();
        }

        // Rearrange the order of keys and vals
        let (rand_keys, rand_vals) = reorder_keys(keys.clone(), vals);

        let mut out_updates = StateUpdates::default();
        //Randomly generate a number between 0 and keys.len(), then delete the first del_num keys
        let del_num: usize = rng.gen_range(0..keys.len());
        for key in rand_keys.iter().take(del_num) {
            state
                .delete(BUCKET_ID, &mut meta, key.clone(), &mut out_updates)
                .unwrap();
        }

        // Reinsert the key-value pairs from del_num to keys.len() into table 0 of cmp_state
        let reader = EmptySalt;
        let mut cmp_state = EphemeralSaltState::new(&reader);
        let mut out_updates = StateUpdates::default();
        meta.used = Some(0);

        for j in del_num..rand_keys.len() {
            cmp_state
                .upsert(
                    BUCKET_ID,
                    &mut meta,
                    rand_keys[j].clone(),
                    rand_vals[j].clone(),
                    &mut out_updates,
                )
                .unwrap();
        }
        assert!(
            is_bucket_eq(BUCKET_ID, &mut state, &mut cmp_state),
            "The two tables should be equal"
        );
    }

    #[test]
    fn get_set_slot_val() {
        let reader = EmptySalt;
        let mut state = EphemeralSaltState::new(&reader);
        let salt_val = Some(SaltValue::new(&[1; 32], &[2; 32]));
        let salt_id = (BUCKET_ID, 1).into();

        assert_eq!(
            state.get_entry(salt_id).unwrap(),
            None,
            "The default slot should be None",
        );

        state.cache.insert(salt_id, salt_val.clone());
        assert_eq!(
            state.get_entry(salt_id).unwrap(),
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
        let salt_id = (BUCKET_ID, 1).into();
        state.update_entry(&mut out_updates, salt_id, None, salt_val.clone());

        assert_eq!(
            out_updates.data.get(&salt_id).unwrap(),
            &(None, salt_val.clone()),
            "After calling set_updates, out_updates should contain the corresponding updates",
        );

        assert_eq!(
            state.get_entry(salt_id).unwrap(),
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
        let hashed_key = pk_hasher::hashed_key(salt_val1.key(), 0);
        let slot_id = probe(hashed_key, 0, meta.capacity);
        let salt_id = (BUCKET_ID, slot_id).into();

        // Insert the key-value pair into the position of slot_id
        state.cache.insert(salt_id, Some(salt_val1.clone()));

        // Find key1 in the state
        let find_slot = state.find(BUCKET_ID, &meta, salt_val1.key()).unwrap();
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
        let find_slot = state.find(BUCKET_ID, &meta, salt_val1.key()).unwrap();
        assert_eq!(
            find_slot.unwrap(),
            (slot_id + 2, salt_val1.clone()),
            "The key1 should be found in the slot_id+2 and the value should equal val1",
        );

        // Create a table 0 with entries like [...(key1_slot_id, (key2, val2)), None,
        // , (key1_slot_id + 2, (key1, val1))...], and key2 > key1
        state.cache.insert(SaltKey(salt_id.0 + 1), None);
        let find_slot = state.find(BUCKET_ID, &meta, salt_val1.key()).unwrap();
        assert_eq!(find_slot, None, "should be found None");

        // Create a table 0 with entries like [...(key1_slot_id, (key2, val2)), (key1_slot_id + 1,
        // (key4, val4)), (key1_slot_id + 2, (key1, val1))...], and key2 > key1, key4 < key1
        let salt_val4 = SaltValue::new(&[0; 32], &[0; 32]);
        state.cache.insert(SaltKey(salt_id.0 + 1), Some(salt_val4));
        let find_slot = state.find(BUCKET_ID, &meta, salt_val1.key()).unwrap();
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
                let hashed_key = pk_hasher::hashed_key(v.key(), 0);
                probe(hashed_key, 0, MIN_BUCKET_SIZE as SlotId)
            })
            .collect();

        // Create a table 0 with entries like [...(slot_id_vec[0], (key_array[0], val)),
        // (slot_id_vec[0] + 1, (key_array[1], val)), (slot_id_vec[0] + 2, (key_array[2],
        // val))...]
        let salt_id = (BUCKET_ID, slot_id_vec[0]).into();
        state.cache.insert(salt_id, Some(salt_array[0].clone()));
        state
            .cache
            .insert(SaltKey(salt_id.0 + 1), Some(salt_array[1].clone()));
        state
            .cache
            .insert(SaltKey(salt_id.0 + 2), Some(salt_array[2].clone()));

        // Find the next suitable slot for the position slot_id_vec[0]
        let rs = state
            .next(BUCKET_ID, slot_id_vec[0], 0, MIN_BUCKET_SIZE as u64)
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
                .next(BUCKET_ID, slot_id_vec[0] - 1, 0, MIN_BUCKET_SIZE as u64)
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
            .next(BUCKET_ID, slot_id_vec[0] + 1, 0, MIN_BUCKET_SIZE as u64)
            .unwrap();
        if slot_id_vec[2] <= slot_id_vec[0] + 1 || slot_id_vec[2] > slot_id_vec[0] + 2 {
            assert_eq!(rs.unwrap(), (slot_id_vec[0] + 2, salt_array[2].clone()));
        } else {
            assert_eq!(rs, None);
        }

        // Find the next suitable slot for the position slot_id_vec[0] + 2
        let rs = state
            .next(BUCKET_ID, slot_id_vec[0] + 2, 0, MIN_BUCKET_SIZE as u64)
            .unwrap();
        assert_eq!(rs, None);
    }

    #[test]
    fn upsert_delete() {
        let reader = EmptySalt;
        let mut state = EphemeralSaltState::new(&reader);
        let mut out_updates = StateUpdates::default();
        let mut meta = BucketMeta {
            used: Some(0),
            ..BucketMeta::default()
        };
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
                let hashed_key = pk_hasher::hashed_key(v.key(), 0);
                state
                    .upsert(
                        BUCKET_ID,
                        &mut meta,
                        v.key().to_vec(),
                        v.value().to_vec(),
                        &mut out_updates,
                    )
                    .unwrap();
                probe(hashed_key, 0, MIN_BUCKET_SIZE as u64)
            })
            .collect();

        slot_id_vec.iter().enumerate().for_each(|(i, slot_id)| {
            let salt_id = (BUCKET_ID, *slot_id).into();
            let slot = state.get_entry(salt_id).unwrap();
            assert_eq!(
                slot.unwrap(),
                salt_array[i].clone(),
                "After upsert, the initial slot should store the corresponding key-value pair",
            );
        });

        // Iterate through key_array and delete the corresponding key
        for v in &salt_array {
            state
                .delete(BUCKET_ID, &mut meta, v.key().to_vec(), &mut out_updates)
                .unwrap();
        }

        for slot_id in &slot_id_vec {
            let salt_id = (BUCKET_ID, *slot_id).into();
            let slot = state.get_entry(salt_id).unwrap();
            assert_eq!(slot, None, "after delete slot_id: {slot_id} should be None");
        }
    }

    #[test]
    fn test_hash() {
        // tested data.
        let data1 = b"hello";
        let data2 = b"world";
        let data3 = b"hash test";
        // set related hash value(generated by ahash fallback algorithm).
        let hash1 = 1027176506268606463;
        let hash2 = 2337896903564117184;
        let hash3 = 2116618212096523432;

        // check the hash value
        assert_eq!(hash1, pk_hasher::hash(data1));
        assert_eq!(hash2, pk_hasher::hash(data2));
        assert_eq!(hash3, pk_hasher::hash(data3));
    }

    #[test]
    fn state_update_in_same_bucket() {
        let store = MemStore::new();
        let mut state = EphemeralSaltState::new(&store);
        //state.update(kvs)
        let keys: Vec<Vec<u8>> = vec![
            hex::decode("e1f65916535230d5abcc5d022348fced0ebcbd16").unwrap(),
            hex::decode("bd2369b04dd7db579559851609fb9d47c4c64895").unwrap(),
            hex::decode("1efa3d6eef22ed3971c3ad2c06743880fe147bda").unwrap(),
            hex::decode("78fb562691afd9adf22cf8d6c2c615c366905409").unwrap(),
            hex::decode("13887c502be115287121f245f0093db41f9f101a").unwrap(),
            hex::decode("b043e57ec98f407f18b668a7ac10f83bedab0f27").unwrap(),
            hex::decode("770721e247aa2e506410fbcaf7ab53ad07d970c5").unwrap(),
            hex::decode("284fb7bf01259d2138cc3a81611bb20b09614a34").unwrap(),
            hex::decode("69e861f856635f4bca286c869a81e9cfc799e2df").unwrap(),
            hex::decode("0f020303e4ffa83cd20f77804f9e66ba8b928973").unwrap(),
            hex::decode("a76c9c3d6d474c6ea31e8d9346030ad6b36d7e8c").unwrap(),
            hex::decode("504a5b7d743c67906a62d5c2d05533e9ae72730d").unwrap(),
            hex::decode("31aebbd3ed3eb24f6871bcfbc290cec16718531b").unwrap(),
            hex::decode("94e13a9fcaaa53f00e7e0b305679e1e4fbba445a").unwrap(),
            hex::decode("24c86f115e5977f945083c8412b84467bce6582a").unwrap(),
            hex::decode("db9c6824ca1e7fd3ce7ea6b76e142b00eb276e86").unwrap(),
            hex::decode("5e86a0d73196db70ce5ffc1594fc8aa34683940c").unwrap(),
            hex::decode("d9f0048750d657628169eac0e2b590008fb5b41f").unwrap(),
            hex::decode("61cbff572f4fbecfb2a23433df9379ac80c8e4f7").unwrap(),
            hex::decode("804ebecf4f930839c0588af6f8e4806ca22d472a").unwrap(),
            hex::decode("1969f584ad7326a5e4261bc69b1d4028e9755fb7").unwrap(),
            hex::decode("6d35371e7d35c863813a1b76cc451775f8c56a63").unwrap(),
            hex::decode("e7f1d9533a632df4e3fe45f8d60cd38bc9801702").unwrap(),
            hex::decode("0225e9090fc4e52fe6596d4580cebe604eb1f7f2").unwrap(),
            hex::decode("8424dc1036b8a0df2b00829afcb859194804b073").unwrap(),
            hex::decode("a133dc051bddb7bc523323cfe32b9911b27b45c5").unwrap(),
            hex::decode("867f498dc1dbc74d296b73247e6afd54e4f6272c").unwrap(),
            hex::decode("175461365f3c1d5078ec7c46709c9bb3d254a157").unwrap(),
            hex::decode("fafb30960467dda483532daf3e8c96feff5bbf78").unwrap(),
            hex::decode("84aae69cf289f649e57d9bd16b6c800389917dd5").unwrap(),
            hex::decode("2490e7724a132530040a38dab9a7276f46aabb7f").unwrap(),
            hex::decode("3e0629e2eefe49497c8a0ad304292493dd653eeb").unwrap(),
            hex::decode("cf68411e5f5e320252469db076eb8b63977fe843").unwrap(),
            hex::decode("6e1367ff77e9ee2c56d0c8e36761772fdadd2445").unwrap(),
            hex::decode("ab5902583830b67b2c2826a73fdbe4baee17e101").unwrap(),
            hex::decode("7989fd14da779f888933e05c48e2d00726759d6e").unwrap(),
            hex::decode("424946ef5cf40e13bec0ae899fd2027e41c0756b").unwrap(),
            hex::decode("a9a52ccfda068097f4074badd3455acccfd01fd9").unwrap(),
            hex::decode("3a5173bbc3cf41abb95764db4339ec5c932fc619").unwrap(),
            hex::decode("494f159f1440fdf61ef8d3e6ecb1e6c88db51c7a").unwrap(),
            hex::decode("58875044163c08a6559c45bad86a26e0150885bf").unwrap(),
            hex::decode("67ae34b933ff64fb79eb0b8d87621a0a46d03cbe").unwrap(),
            hex::decode("b8c0405d4f3cbab2d7568e1c0111ea075485d664").unwrap(),
            hex::decode("fbd345fc288be7c88fb29bf6e51446d991ae109f").unwrap(),
            hex::decode("81423fe75a836091b165dca1e4d9ca611196bf00").unwrap(),
            hex::decode("c66f27ed67930cfeb8a31ab481de893faad9bea0").unwrap(),
            hex::decode("8e7e29672947574dadb5c2657d6c7ce5d3f2d173").unwrap(),
            hex::decode("d4e3efadd21f134939b01882162296e47d689159").unwrap(),
            hex::decode("b331070db53f06ef2be992a7a3fe11403f10ccfa").unwrap(),
            hex::decode("f798cd0abdbb912ff7846bc74a8dc6dd50cb495d").unwrap(),
            hex::decode("f0e4cf9f741a7d4dd8519cd8ef27c2002eac9346").unwrap(),
            hex::decode("f87c850ee516323f381ab001ba97e0710e004e86").unwrap(),
            hex::decode("116b8801f6de50732b311afe42dbf4936d28b44f").unwrap(),
            hex::decode("3a5fd9ad896b0165bb0da5bfd571d91d56b6e578").unwrap(),
            hex::decode("348f8581bb4e5c82623a29dace59317f6dc84916").unwrap(),
            hex::decode("d44d2d9435ca46f5658ada25c42a2c46f5140a9d").unwrap(),
            hex::decode("39ba7adfd4138b38c78db114992041d3e00149cf").unwrap(),
            hex::decode("8fc8233781b1c91a25c75263cc9586bb0441f7d7").unwrap(),
            hex::decode("472b06e228faa54b44d435aa2f8469fbf9826dff").unwrap(),
            hex::decode("4d5b85570d5efe455df6ced9df837415e202848e").unwrap(),
            hex::decode("1683ef6ea6be17cf931c8a011bba63323537daea").unwrap(),
            hex::decode("a6a9a4365c3917d76f4c1efa7eef6ff9f4f916f6").unwrap(),
            hex::decode("569d7e6bf232445fc50b12d8a9cedd761393cb41").unwrap(),
            hex::decode("47c357b168a55c419eb5e9ff1e14ecf95f159f23").unwrap(),
            hex::decode("6ff316145834857a4b4fc4257830ff7a2f8ad5b1").unwrap(),
            hex::decode("da368d50721a5664844aabf331b748dcc1f9c710").unwrap(),
            hex::decode("52dd5243167661da2ae364ecf514e7f5032855de").unwrap(),
            hex::decode("ac40c5802776ec4cc4d1900e4a1d401a6f5664a4").unwrap(),
            hex::decode("5666f6256e4d61f8bdbf935dbbca156a6c1dad80").unwrap(),
            hex::decode("dcc54080b585d9a93ed9b9e0b9e9c4a85405a022").unwrap(),
            hex::decode("903036e0cc93cf84cb4af40ffd28047d1f881791").unwrap(),
            hex::decode("75039bc826a91bbeb6035efb36c2d965f5dd983a").unwrap(),
            hex::decode("55c8323675118a715df66188be458b6d7e3957fc").unwrap(),
            hex::decode("d21bb8fb595c4b2d243221776bd4cb393554c2b3").unwrap(),
            hex::decode("5f943a9aa5c9c8bcc3f433e6591cdebce3022a58").unwrap(),
            hex::decode("182bcc4ff7d450a4929b5e04b8949bb3fe6cf151").unwrap(),
            hex::decode("1f96b56e2e780568ef938e2478a9ea9305d8288f").unwrap(),
            hex::decode("b40d6af96e4b237ae72b87827c79e5e63e28e33e").unwrap(),
            hex::decode("1acb45a676f303a1c046e70ae3c556fc17b2bfff").unwrap(),
            hex::decode("4ff1f8c58358f57f71b3aa0abc60f82364f4f354").unwrap(),
            hex::decode("ca84b4748261ca963fb7ea65351d52a60ecb7209").unwrap(),
            hex::decode("be12fed226d5c855021871de32c063a1cb8859ae").unwrap(),
            hex::decode("c26d891c4095b2137a331d2deec9dbc82239dbf5").unwrap(),
            hex::decode("547e960b68fa8493bf9b6c87f5cdbef96a695af7").unwrap(),
            hex::decode("59b00b3cffdf786cf0fe1549b267dbd9dcf9e1fd").unwrap(),
            hex::decode("9e30284877ff1999c32b408e17cb52f276f45e51").unwrap(),
            hex::decode("d0248f83fc2e2a62b823e5fe61da586d977cad97").unwrap(),
            hex::decode("68fcd6e4de75f818cfd38fc8dfeb27508889b2cc").unwrap(),
            hex::decode("574e0c6c23b125e14d97e130faf61187de29dd10").unwrap(),
            hex::decode("51fbc8cf485b8fbae0c45edad879356d84cf5a6a").unwrap(),
            hex::decode("2b4d57d6e169c2ecc5cd6c0789f0cd60f68a0039").unwrap(),
            hex::decode("20456c58f25199fc770db6742b91e698ac73da85").unwrap(),
            hex::decode("8baa869a14f6899fa1c645958e76f38b3e32c972").unwrap(),
            hex::decode("9344bfb1d1d3f7623a0f4e0d80ac05fd5cfa94c0").unwrap(),
            hex::decode("fa642ab320349447cba3c2027872eacb092bea94").unwrap(),
            hex::decode("1f94e9e1f0efaf37e8aa122a04b5ffcecc6b6393").unwrap(),
            hex::decode("ceabed24f8b5fbf3cbc245019592793e76b4cb07").unwrap(),
            hex::decode("823b496bfe4695b1440710090627a6f27500324e").unwrap(),
            hex::decode("2e76c918b2ee11ed434e7fd295dba0088f7abd6f").unwrap(),
            hex::decode("959d5af44d074b408fb23111bb7994b4c47596a1").unwrap(),
            hex::decode("f917e957ddba2331c4a44f754973be53d7796f9c").unwrap(),
            hex::decode("c2fdbade893721f8b2a5cecde0d9503d5d8890f4").unwrap(),
            hex::decode("8af54d7a62e232a2bc073adcb201cf17cf95cba3").unwrap(),
            hex::decode("48385303ed8015d73469b14c0b987b323699c434").unwrap(),
            hex::decode("a2787466a220129145df73845cdd868ef7dd0314").unwrap(),
            hex::decode("b1a92179b1f741307601af2a06cd898fe717895b").unwrap(),
            hex::decode("38d05b540911bb73279e71a8acc2f3c73190bb3c").unwrap(),
            hex::decode("e206af14c6601ba7a3d4743b38a16afe33b54b4c").unwrap(),
            hex::decode("3d6cebe3ea4101b5790c7dddbea7ac0ea14babdb").unwrap(),
            hex::decode("6236a0fa2afd24249b404bf89410299c4838e5c6").unwrap(),
            hex::decode("15ea7048eae0aba4812c39bee42b73d6f53b5a6e").unwrap(),
            hex::decode("b70c9d3e19896532ca3f25b4122a5d0dfa2721df").unwrap(),
            hex::decode("df50a31e4396ece15ace561bfe5126d44bf1a910").unwrap(),
            hex::decode("431f76943566882d753964cbec651c57fcb7559f").unwrap(),
            hex::decode("f90213684110db1502eeb9220f960a0780596e72").unwrap(),
            hex::decode("8472c8be85a8bf1f9e65e662bb71c2a8e34d4326").unwrap(),
            hex::decode("be719168ad97183ea6e3a9b3c079483de2d395f4").unwrap(),
            hex::decode("0969afed05fdb678f09ee517fe8ca22154af5780").unwrap(),
            hex::decode("392fa334a99560a717a7d25ed7417e530a2f1851").unwrap(),
            hex::decode("4f0b3a84f9d68d5db228baed5acd250da3638cd6").unwrap(),
            hex::decode("194a6fc974bc69ab8ff94b041dadb99292010d91").unwrap(),
            hex::decode("05c748eaf5b8c8e5d9d955b863a96a68ed3c35e7").unwrap(),
            hex::decode("c92fe28f145ff3073d6006978d76ebeec8e54e67").unwrap(),
            hex::decode("1b93e980386e45e36256db6f9f3f0ecfa99f7c34").unwrap(),
            hex::decode("06b7e8d43668887121e9da08143b8c1ce2e7c942").unwrap(),
            hex::decode("334e794296624a4ce8294dd57e191abac27767e1").unwrap(),
            hex::decode("2156e5056d40e4e338abb9fa0bc838e2a28b3777").unwrap(),
            hex::decode("364bbba8b90868c37616896191b0e75331009c65").unwrap(),
            hex::decode("b8e6230fb4327ea9ddf57246b00b6999d0b75c6f").unwrap(),
            hex::decode("9c8abef600fbad09676bd11e29eaff9c357c358c").unwrap(),
            hex::decode("b0cca1598a457e0d8e23a3a0f6edaf0899998b28").unwrap(),
            hex::decode("98f10ec6e3d63bf6ebc3ccc73df8b6cae8afad0c").unwrap(),
            hex::decode("7d8f5d58b4ea3833dbd30142333f4e25f0728ae9").unwrap(),
            hex::decode("832b829c718a61343210e7eb5b28f55f6d3ef72d").unwrap(),
            hex::decode("e5bf402a158e49abb6a070528ae0d61512b6856f").unwrap(),
            hex::decode("b67206223394ce91dc2d2042ff61fb48cbe34c2a").unwrap(),
            hex::decode("72962b7ff636454e0aabaa882175296d6ce1da83").unwrap(),
            hex::decode("3cc35334c0030c8178a955a7165bc23fb5b98c78").unwrap(),
            hex::decode("f2ebcd92726d7cf09ebf204dd31486a351536535").unwrap(),
            hex::decode("e4f02fab9b9a38bda1401b2111074c8659ab80ff").unwrap(),
            hex::decode("a56d2f4d7fd0e36a8f48bc0ad0d6837046c98c95").unwrap(),
            hex::decode("ef60f2de2cfcee6465918a6754947177ba709085").unwrap(),
            hex::decode("d2017feee30f144e7cb97c573268ee40955d7a86").unwrap(),
            hex::decode("fdd20e6343fd9d8644a0ad21c5969381f8968b3d").unwrap(),
            hex::decode("3ed720005584636747541d2454598903efdc3660").unwrap(),
            hex::decode("907b3e51defc0ddec075ae91756a203a4c1138f1").unwrap(),
            hex::decode("c0065b54de4719c8eb938ca900fe013817ce674c").unwrap(),
            hex::decode("0545db489202813397de41d0d16a3f2505c78d68").unwrap(),
            hex::decode("7218e85f3cfef7d962976e89e5026d5e4bdc4863").unwrap(),
            hex::decode("eabe9d26e0ac33f48923c8608dabc3769e95cb70").unwrap(),
            hex::decode("dcc01246f0b84ccc4333592bd0d7060e42173d72").unwrap(),
            hex::decode("8e67feb32f15b840c0a2adf563da96b152464f4d").unwrap(),
            hex::decode("f99fe6831f951f0bcea99fe77796944ff2653fd0").unwrap(),
            hex::decode("25a88813b3c06db2bc3d3ed4b603e04561372e7c").unwrap(),
            hex::decode("0afea4edcfc71db88de7cc6cca2fd3bc263c789c").unwrap(),
            hex::decode("8769ba933daa1cd2b20162ddbb47b36423cd41ea").unwrap(),
            hex::decode("db84bc1eb2d8c30121da6293c25c1a90e0d70348").unwrap(),
            hex::decode("d2fd3ae822e0117cd9f6db75b757f803db8443d3").unwrap(),
            hex::decode("f5762e3b80dd58329c5d6ed0ec06ba108c72da9d").unwrap(),
            hex::decode("13ed0fbe2379f64481c6979ed2a8579fcf2f0acf").unwrap(),
            hex::decode("5731d0ec88d0a10d52606242f97f3d4c98044bfc").unwrap(),
            hex::decode("c70e057c2d99b2191ac07366f0c64f94bc41aeaa").unwrap(),
            hex::decode("d257d3c33709bec4c02218cfb9e286a79f7e3275").unwrap(),
            hex::decode("769bcd88d8a05be50e4c6199ed131b1e288fb32b").unwrap(),
            hex::decode("928edce9b923526516f2104b9beb40ec43e267e3").unwrap(),
            hex::decode("ccb1a286f183df0343a59d8520d467af500d444c").unwrap(),
            hex::decode("d4f2112c554660a926f3fafab4d41b15d3b5cf10").unwrap(),
            hex::decode("83a57ea221e4d3736c023e4d4c372122561ce1ff").unwrap(),
            hex::decode("48d45fb0f612e55ce52ccb00844edc39e9fe1bd2").unwrap(),
            hex::decode("72f8125cf45449b092ade7b93868c2ffeb701a5c").unwrap(),
            hex::decode("5153dd4d669819d2b72723c868a1e707ce7c449a").unwrap(),
            hex::decode("c5b82f750e32188cad5ea7bd102237448c33d8d4").unwrap(),
            hex::decode("57c32818c414eee7de0cc6520e1500395fc752df").unwrap(),
            hex::decode("6aa3b0b7beb062b451bb7860ea3be234828f9826").unwrap(),
            hex::decode("6532032683a23044ab728f1108171f319542828b").unwrap(),
            hex::decode("8e4a706d954389dd894df0150150ac8e48d47f05").unwrap(),
            hex::decode("e7caf81c03f5366bdc4401f77bddec23cded337f").unwrap(),
            hex::decode("5a1f7d0a01bac1bf3713384a6c638fe0e31a2552").unwrap(),
            hex::decode("48fc5f59213c5c2e219fc8fca607397bd770c072").unwrap(),
            hex::decode("032841bebb4d01b44802d9b6b0ca287f0e7473ac").unwrap(),
            hex::decode("aa1ceeecc8a52a1da61905f79ce5bdc2b9ea56c5").unwrap(),
            hex::decode("f49a4eeebfe4851d53c5c3f67fade15ea8daa759").unwrap(),
            hex::decode("d3253bb176781be29e2a02710dab501a9614ff95").unwrap(),
            hex::decode("18a9965bd604373ba380e9c351a8796bd204f332").unwrap(),
            hex::decode("e82f37aa1dbf8a818d6ab1394bdcd798041f12c6").unwrap(),
            hex::decode("42da474393aa81703cdddfe671c74e19192b33a6").unwrap(),
            hex::decode("b6908279efe881a446beeef156e2d4a01f276a3f").unwrap(),
            hex::decode("7ee42121913687a4f46bb4d5ba74985d63080081").unwrap(),
            hex::decode("d5116e9a2a8d1af4e05c15eeba10581b3417df55").unwrap(),
            hex::decode("823ddf66d3c38d42620db82c3f098d8bacad3af8").unwrap(),
            hex::decode("9998b53972fdf8f2b7a74f72a343f9060a2a9a97").unwrap(),
            hex::decode("8daec6e313df686aac11e92b6219ae9c6e5bd7bf").unwrap(),
            hex::decode("e332953ea38e1080ed2e80bdc5ae30a9f0029178").unwrap(),
            hex::decode("f1b11f9defc5b578455c38b104baa9d41b6473f2").unwrap(),
            hex::decode("17a2ca7219a50e53ed66d8254842a2f3b2eabcf8").unwrap(),
            hex::decode("2ac2e1b602fdd1e2d65612fc2f64ba71ad687e62").unwrap(),
            hex::decode("487e424eafbb7dc791229eeb2436366d6ea7db03").unwrap(),
            hex::decode("282dc6c257794bce200bb1bac0b5455b19a8b3a3").unwrap(),
            hex::decode("07f804f62ef0cd76283a01d0b4141a337865d304").unwrap(),
            hex::decode("9c05d1cae71a12bdb4eea15a212ecee0f5f8bef1").unwrap(),
            hex::decode("b389524ef254f907660836f17c57c82178119d57").unwrap(),
            hex::decode("a089d36fd722b2eaea341a40a275d8c4ef1eea61").unwrap(),
            hex::decode("2e99f8559d303bf75efe417bc8b3420f4ef00007").unwrap(),
            hex::decode("705e7fe2071210885867c2653218f616466048cd").unwrap(),
            hex::decode("dd07024712621a63d7f82e8626bf1a2559b2084b").unwrap(),
            hex::decode("3c2025486d263760126406ab3127427c7c007c40").unwrap(),
            hex::decode("1060143cbdc7a4ce20b877f52dca875523d26232").unwrap(),
            hex::decode("838a7472d985fc407c0ab29c29cebc4b13efaf6b").unwrap(),
            hex::decode("35e0d94f8b852672ebe410ced86f79aa8715544d").unwrap(),
            hex::decode("473ebdc9b6ffbfd90a56fe6599ab73101fc764d4").unwrap(),
            hex::decode("ce8e53cf00c6541f3adc0d44dcb66373dfc14c29").unwrap(),
            hex::decode("2eca1f5afd7203fd812366d76df5d6140d0caee2").unwrap(),
            hex::decode("fb9b2abde5989ff28f9c64e6d0b1e75a4720a8d4").unwrap(),
            hex::decode("0a893bca7bd6cdb0bbf240f55829eaebeb662fc6").unwrap(),
            hex::decode("a7efa2e34a210adb7ec99843b530005391ace433").unwrap(),
            hex::decode("01816a50d223416a9ed2a6918066e28ccd163968").unwrap(),
            hex::decode("2f39e37db58ca9b8bb4169f5aeeb9eb99f2353fe").unwrap(),
            hex::decode("d0b56e727fedef1996ba0d3f456d211c81f95db8").unwrap(),
            hex::decode("b34f2f81eb15bdde1f9c37128a602d3411ea4d4e").unwrap(),
            hex::decode("9ac78d963b7bbc621f038d524330e10a1a375410").unwrap(),
            hex::decode("00e5e5b7daa8c9cfa12ac796aa679a1b3f672fc2").unwrap(),
            hex::decode("84ad36144296c512ec71002c5703031350feb146").unwrap(),
            hex::decode("bd58b1f3535db30c3915dee1c3916e0a73ac9152").unwrap(),
            hex::decode("3641000ebf374fb884176d4e84c720356d9ebcab").unwrap(),
            hex::decode("bbf7589212e35d8eb1fec514449b4826d82993c4").unwrap(),
            hex::decode("9f0be5968e80b83a9760c6a585db19538bf903fa").unwrap(),
            hex::decode("7f54c8bae2c983a294088a9e18471a30b485e1c1").unwrap(),
            hex::decode("acd5738d679aee5c3dc91a62af84800114f23eae").unwrap(),
            hex::decode("40d4fcf0b3616beb88bd65f741eb1b0ae7b3cee2").unwrap(),
            hex::decode("da7138de654e9120c43973f30f6ba18b41b17a98").unwrap(),
            hex::decode("2b44a321dd7de1c2d86e0070874eed841e4be018").unwrap(),
            hex::decode("24727b7dffd478786e45635f81ea3d4aa59397f3").unwrap(),
            hex::decode("850317d890ebe57393777aaebfaafca1a2c49c01").unwrap(),
            hex::decode("e7b6b0ec9f703d02a12f0fae7db10d0b97af3942").unwrap(),
            hex::decode("04d6a465deb581cb4f4cc52c6bcb03e693a9228d").unwrap(),
            hex::decode("58352d1887325f0904b58524f4acba80e6dfa3ce").unwrap(),
            hex::decode("c671d279be4fa36f185bcb0b23da1e121a93d6db").unwrap(),
            hex::decode("47a740551260f0f837e7c7b5e4817e628fb163bb").unwrap(),
            hex::decode("2448c53bcf62e6ab546dbe195e247f4788ae529a").unwrap(),
            hex::decode("74449a5f6d6cbd774d55b10d5d516d0b0f2daa59").unwrap(),
            hex::decode("c0982b7f5794090735307455360b47db9866a573").unwrap(),
            hex::decode("e1c29f6ff543792bee0bff133cd73985e49455ff").unwrap(),
            hex::decode("e8d7b68447e1f53c30b838051aaed4893ac057c9").unwrap(),
            hex::decode("0c0b5538c49aaa5b93c32d845298882a5e8909d5").unwrap(),
            hex::decode("5d1ca4b0381496c4a14844ac8cfa15c6c0ab8ef3").unwrap(),
            hex::decode("0d81754a6f5811902914b658206668a2d64bb594").unwrap(),
            hex::decode("c9033fa36d577ac92dfc4b3fbde34fb3f85448cd").unwrap(),
            hex::decode("6354050444f0c85b90fd6d30af23a56cdb7c5e14").unwrap(),
            hex::decode("9554a50909212ad70041d4424ff5b4f797f9ba39").unwrap(),
            hex::decode("87ed5afccd2c870c2c3394562527f100f554dc3d").unwrap(),
            hex::decode("865435b88bb58912d942d091a2603cfc84a5b5d7").unwrap(),
            hex::decode("e01e8ffd0016276bfe4efef0d74b3bd0c25413b5").unwrap(),
            hex::decode("f768f02b225678f3e5366684041c7a6d3d1e10aa").unwrap(),
            hex::decode("34f560adbf9ea6be669a764eb5baecbaf30fc0a1").unwrap(),
            hex::decode("97c4c995321c6dd8451a0580801bf9836fa5aecf").unwrap(),
            hex::decode("9d5761fccaff2d145889b2eada24439d20da6811").unwrap(),
            hex::decode("2ae277675ce8cdeb965903667d2e36d7611fc2c0").unwrap(),
            hex::decode("560fe5e41fb23cd92f7558e9b6c384b9bfdf33bd").unwrap(),
            hex::decode("33e5dc632f7e9c1f5f5d1665f2f3500850368ad2").unwrap(),
            hex::decode("00797d9c751a1e633b3d9d0711469026d8c84278").unwrap(),
        ];
        let num_keys = keys.len() as u64;
        let bucket_id = pk_hasher::bucket_id(&keys[0]);
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

    fn check_rehash(old_meta: BucketMeta, mut new_meta: BucketMeta, l: usize) {
        let store = MemStore::new();
        let mut meta1 = old_meta.clone();
        let mut rehash_state = EphemeralSaltState::new(&store);
        let mut rehash_updates = StateUpdates::default();

        let mut cmp_state = EphemeralSaltState::new(&EmptySalt);
        let mut cmp_updates = StateUpdates::default();
        let mut cmp_meta = new_meta;

        let mut kvs = create_random_kvs(l);

        // Create initial data. In the case of expansion, `cmp_state` inserts `kvs`.
        // The first half of the data is updated to `store` before the state update,
        // and the second half of the data is in `out_updates`.
        for i in 0..kvs.0.len() {
            rehash_state
                .upsert(
                    BUCKET_ID,
                    &mut meta1,
                    kvs.0[i].clone(),
                    kvs.1[i].clone(),
                    &mut rehash_updates,
                )
                .unwrap();
            if i == l / 2 {
                store.update_state(rehash_updates);
                rehash_updates = StateUpdates::default();
            }
            cmp_state
                .upsert(
                    BUCKET_ID,
                    &mut cmp_meta,
                    kvs.0[i].clone(),
                    kvs.1[i].clone(),
                    &mut cmp_updates,
                )
                .unwrap();
        }

        // update some kvs to state
        for i in l / 2 - l / 4 - 1..l / 2 + l / 4 {
            kvs.1[i] = [i as u8; 32].into();
            rehash_state
                .upsert(
                    BUCKET_ID,
                    &mut meta1,
                    kvs.0[i].clone(),
                    kvs.1[i].clone(),
                    &mut rehash_updates,
                )
                .unwrap();
            cmp_state
                .upsert(
                    BUCKET_ID,
                    &mut cmp_meta,
                    kvs.0[i].clone(),
                    kvs.1[i].clone(),
                    &mut cmp_updates,
                )
                .unwrap();
        }

        // delete some kvs to state
        for i in l / 2 - l / 8 - 1..l / 2 + l / 8 {
            rehash_state
                .delete(BUCKET_ID, &mut meta1, kvs.0[i].clone(), &mut rehash_updates)
                .unwrap();
            cmp_state
                .delete(BUCKET_ID, &mut cmp_meta, kvs.0[i].clone(), &mut cmp_updates)
                .unwrap();
        }

        // state has insert, update and delete operation, rehash state
        rehash_state
            .rehash(BUCKET_ID, &old_meta, &mut new_meta, &mut rehash_updates)
            .unwrap();

        // Verify the rehashing results
        for i in 0..kvs.0.len() {
            let kv1 = cmp_state.find(BUCKET_ID, &cmp_meta, &kvs.0[i]).unwrap();
            let kv2 = rehash_state.find(BUCKET_ID, &new_meta, &kvs.0[i]).unwrap();
            assert_eq!(kv1, kv2);
        }

        // Verify the rehashing results after writing to store
        store.update_state(rehash_updates.clone());
        let mut state = EphemeralSaltState::new(&store);
        for i in 0..kvs.0.len() {
            let kv1 = cmp_state.find(BUCKET_ID, &new_meta, &kvs.0[i]).unwrap();
            let kv2 = state.find(BUCKET_ID, &new_meta, &kvs.0[i]).unwrap();
            assert_eq!(kv1, kv2);
        }
        //check changed meta in state updates
        let meta_key = bucket_metadata_key(BUCKET_ID);
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
}
