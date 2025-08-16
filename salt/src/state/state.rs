//! This module provides two major functionalities:
//! (1) Use plain keys to access the current blockchain state,
//!     which is stored in some storage backend in SALT format.
//! (2) Tentatively update the current state and accumulate the
//!     resulting incremental changes in memory.
use super::{hasher, updates::StateUpdates};
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
    /// Cache the values of datas and bucket metadata (nonce and capacity) read from `base_state`
    /// and the changes made to it.
    pub(crate) cache: HashMap<SaltKey, Option<SaltValue>>,
    /// Caches the usage counts in buckets when insertions or deletions occurred.
    bucket_used_cache: HashMap<BucketId, u64>,
    /// Whether to save access records
    save_access: bool,
}

/// Implement the `Clone` trait for `EphemeralSaltState`.
impl<BaseState> Clone for EphemeralSaltState<'_, BaseState> {
    fn clone(&self) -> Self {
        Self {
            base_state: self.base_state,
            cache: self.cache.clone(),
            bucket_used_cache: self.bucket_used_cache.clone(),
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
            bucket_used_cache: HashMap::new(),
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

    /// Retrieves the plain value associated with the given plain key.
    ///
    /// # Arguments
    /// * `plain_key` - The raw key bytes to look up
    ///
    /// # Returns
    /// * `Ok(Some(value))` - The plain value bytes if the key exists
    /// * `Ok(None)` - If the key does not exist
    /// * `Err(error)` - If there was an error accessing the underlying storage
    pub fn plain_value(&mut self, plain_key: &[u8]) -> Result<Option<Vec<u8>>, BaseState::Error> {
        // Computes the `bucket_id` based on the `key`.
        let bucket_id = hasher::bucket_id(plain_key);
        let metadata = self.bucket_metadata(bucket_id, false)?;

        // Calculates the `hashed_id`(the initial slot position) based on the `key` and `nonce`.
        let hashed_id = hasher::hash_with_nonce(plain_key, metadata.nonce);

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
            let bucket_id = hasher::bucket_id(key_bytes);
            let mut meta = self.bucket_metadata(bucket_id, true)?;
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

    /// Get bucket metadata for the given bucket ID.
    ///
    /// # Arguments
    /// * `bucket_id` - The bucket ID to get metadata for
    /// * `need_used` - Whether to populate the `used` field. Setting this to `false`
    ///   avoids unnecessary `bucket_used_slots()` calls to the underlying storage
    ///   backend when the usage count is not needed (e.g., for read operations like
    ///   `plain_value` that only need `nonce` and `capacity`).
    fn bucket_metadata(
        &mut self,
        bucket_id: BucketId,
        need_used: bool,
    ) -> Result<BucketMeta, BaseState::Error> {
        let mut meta = match self.get_entry(bucket_metadata_key(bucket_id))? {
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
                    self.base_state.bucket_used_slots(bucket_id)?
                },
            );
        }
        Ok(meta)
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
        let hashed_key = hasher::hash_with_nonce(&pending_key, meta.nonce);

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
                // Update the bucket usage cache
                self.bucket_used_cache.insert(bucket_id, used + 1);
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
            let new_used = old_used.saturating_sub(1);
            meta.used = Some(new_used);
            // Update the bucket usage cache
            self.bucket_used_cache.insert(bucket_id, new_used);
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
        let hashed_key = hasher::hash_with_nonce(plain_key, meta.nonce);

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
                    let hashed_id = hasher::hash_with_nonce(entry.key(), nonce);

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

    const KEYS_NUM: usize = 3 * MIN_BUCKET_SIZE - 1;
    const BUCKET_ID: BucketId = NUM_META_BUCKETS as BucketId + 1;

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
        let hashed_key = hasher::hash_with_nonce(salt_val1.key(), 0);
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
                let hashed_key = hasher::hash_with_nonce(v.key(), 0);
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
                let hashed_key = hasher::hash_with_nonce(v.key(), 0);
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

    #[test]
    fn test_cached_metadata_bug() {
        // This test exposes the bug where metadata retrieved from store
        // has used=None after deserialization, causing a panic in upsert/delete.
        // The correct behavior should be successful updates without panics.

        let store = MemStore::new();

        // Use pre-computed key that maps to a specific bucket
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
}
