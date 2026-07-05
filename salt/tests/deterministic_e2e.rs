use bincode::config::legacy;
use salt::{
    EphemeralSaltState, MemStore, PlainStateProvider, SaltWitness, StateRoot, StateUpdates, Witness,
};
use std::collections::BTreeMap;

type PlainBatch = BTreeMap<Vec<u8>, Option<Vec<u8>>>;

fn batch(entries: &[(&[u8], Option<&[u8]>)]) -> PlainBatch {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_vec(), value.map(Vec::from)))
        .collect()
}

fn compute_state_updates(store: &MemStore, batch: &PlainBatch) -> StateUpdates {
    EphemeralSaltState::new(store)
        .cache_read()
        .update_fin(batch.iter())
        .expect("compute state updates")
}

fn compute_trie_update_root(
    store: &MemStore,
    updates: &StateUpdates,
) -> ([u8; 32], salt::TrieUpdates) {
    let mut trie = StateRoot::new(store);
    trie.update_fin(updates).expect("compute trie updates")
}

fn apply_full_update(store: &MemStore, updates: StateUpdates) -> [u8; 32] {
    store.update_state(updates.clone());
    let (root, trie_updates) = compute_trie_update_root(store, &updates);
    store.update_trie(trie_updates);
    root
}

#[test]
fn witness_replay_matches_full_store_and_survives_codec_round_trip() {
    let store = MemStore::new();
    let initial_batch = batch(&[
        (b"account:alice", Some(b"balance:100")),
        (b"account:bob", Some(b"balance:50")),
        (b"storage:alice:slot:0", Some(b"0x01")),
        (b"storage:alice:slot:1", Some(b"0x02")),
        (
            b"long/storage/key/that/looks/like/an/evm-slot",
            Some(b"0xbeef"),
        ),
    ]);
    let initial_updates = compute_state_updates(&store, &initial_batch);
    let initial_root = apply_full_update(&store, initial_updates);

    let block_updates = batch(&[
        (b"account:alice", Some(b"balance:125")),
        (b"storage:alice:slot:1", None),
        (b"storage:alice:slot:2", Some(b"0x03")),
        (b"new:contract:codehash", Some(b"0xc0de")),
    ]);
    let lookups = vec![
        b"account:alice".to_vec(),
        b"account:bob".to_vec(),
        b"missing:read:key".to_vec(),
    ];

    let witness = Witness::create([], &lookups, &block_updates, &store).expect("create witness");
    assert_eq!(witness.state_root().unwrap(), initial_root);
    witness.verify().expect("verify witness");

    let witness_bytes =
        bincode::serde::encode_to_vec(&witness.salt_witness, legacy()).expect("encode witness");
    let (salt_witness, consumed): (SaltWitness, usize) =
        bincode::serde::decode_from_slice(&witness_bytes, legacy()).expect("decode witness");
    assert_eq!(consumed, witness_bytes.len());
    let witness = Witness::from(salt_witness);
    assert_eq!(witness.state_root().unwrap(), initial_root);
    witness.verify().expect("verify round-tripped witness");

    let full_updates = compute_state_updates(&store, &block_updates);
    let witness_updates = EphemeralSaltState::new(&witness)
        .cache_read()
        .update_fin(block_updates.iter())
        .expect("replay updates from witness");
    assert_eq!(witness_updates, full_updates);

    let full_next_store = store.clone();
    full_next_store.update_state(full_updates.clone());
    let (full_next_root, mut full_trie_updates) =
        compute_trie_update_root(&full_next_store, &full_updates);

    let mut witness_trie = StateRoot::new(&witness);
    let (witness_next_root, mut witness_trie_updates) = witness_trie
        .update_fin(&witness_updates)
        .expect("compute trie updates from witness");
    assert_eq!(witness_next_root, full_next_root);

    full_trie_updates.sort_unstable_by_key(|(node_id, _)| *node_id);
    witness_trie_updates.sort_unstable_by_key(|(node_id, _)| *node_id);
    assert_eq!(witness_trie_updates, full_trie_updates);

    full_next_store.update_trie(full_trie_updates);
    let provider = PlainStateProvider::new(&full_next_store);
    assert_eq!(
        provider.plain_value(b"account:alice", None).unwrap(),
        Some(b"balance:125".to_vec())
    );
    assert_eq!(
        provider.plain_value(b"storage:alice:slot:1", None).unwrap(),
        None
    );
    assert_eq!(
        provider.plain_value(b"storage:alice:slot:2", None).unwrap(),
        Some(b"0x03".to_vec())
    );
}

#[test]
fn inverse_updates_round_trip_back_to_the_empty_state() {
    let store = MemStore::new();
    let updates = compute_state_updates(
        &store,
        &batch(&[
            (b"rollback:key:0", Some(b"value:0")),
            (b"rollback:key:1", Some(b"value:1")),
            (b"rollback:key:2", Some(b"value:2")),
        ]),
    );

    let populated_root = apply_full_update(&store, updates.clone());
    assert_ne!(
        populated_root,
        StateRoot::rebuild(&MemStore::new()).unwrap().0,
        "fixture must change the empty root"
    );

    store.update_state(updates.inverse());
    let (rolled_back_root, _) = StateRoot::rebuild(&store).unwrap();
    let empty_root = StateRoot::rebuild(&MemStore::new()).unwrap().0;
    assert_eq!(rolled_back_root, empty_root);

    let provider = PlainStateProvider::new(&store);
    assert_eq!(provider.plain_value(b"rollback:key:0", None).unwrap(), None);
    assert_eq!(provider.plain_value(b"rollback:key:1", None).unwrap(), None);
    assert_eq!(provider.plain_value(b"rollback:key:2", None).unwrap(), None);
}
