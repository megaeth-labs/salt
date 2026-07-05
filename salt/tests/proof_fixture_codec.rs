use bincode::config::legacy;
use salt::{
    proof::{prover::parents_commitments_serde, SerdeCommitment},
    types::NodeId,
    SaltProof,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(serde::Deserialize)]
struct ParentsCommitmentsFixture {
    #[serde(deserialize_with = "parents_commitments_serde::deserialize")]
    inner: BTreeMap<NodeId, SerdeCommitment>,
}

fn proof_fixtures() -> [(&'static str, &'static [u8]); 2] {
    [
        (
            "6906405",
            include_bytes!("../benches/fixtures/6906405.proof"),
        ),
        (
            "6906412",
            include_bytes!("../benches/fixtures/6906412.proof"),
        ),
    ]
}

#[test]
fn committed_proof_fixtures_decode_and_reencode_deterministically() {
    for (name, bytes) in proof_fixtures() {
        let (proof, consumed): (SaltProof, usize) =
            bincode::serde::decode_from_slice(bytes, legacy())
                .unwrap_or_else(|err| panic!("decode fixture {name}: {err}"));

        assert_eq!(consumed, bytes.len(), "{name} left trailing bytes");
        assert!(
            proof.parents_commitments.contains_key(&0),
            "{name} has no root commitment"
        );
        assert!(
            !proof.levels.is_empty(),
            "{name} should contain bucket level metadata"
        );

        let level_keys = proof.levels.keys().copied().collect::<BTreeSet<_>>();
        assert_eq!(
            level_keys.len(),
            proof.levels.len(),
            "{name} has duplicate level keys after decode"
        );

        let encoded = bincode::serde::encode_to_vec(&proof, legacy())
            .unwrap_or_else(|err| panic!("encode fixture {name}: {err}"));
        assert_eq!(
            encoded.as_slice(),
            bytes,
            "{name} proof bytes changed after decode/encode"
        );

        let encoded_again = bincode::serde::encode_to_vec(&proof, legacy())
            .unwrap_or_else(|err| panic!("re-encode fixture {name}: {err}"));
        assert_eq!(
            encoded, encoded_again,
            "{name} proof encoding is not deterministic"
        );
    }
}

#[test]
fn committed_parent_commitment_maps_decode_through_parallel_path() {
    for (name, bytes) in proof_fixtures() {
        let (proof, _): (SaltProof, usize) = bincode::serde::decode_from_slice(bytes, legacy())
            .unwrap_or_else(|err| panic!("decode fixture {name}: {err}"));
        let map_bytes = bincode::serde::encode_to_vec(&proof.parents_commitments, legacy())
            .unwrap_or_else(|err| panic!("encode parent map {name}: {err}"));

        let (decoded, consumed): (ParentsCommitmentsFixture, usize) =
            bincode::serde::decode_from_slice(&map_bytes, legacy())
                .unwrap_or_else(|err| panic!("parallel decode parent map {name}: {err}"));

        assert_eq!(
            consumed,
            map_bytes.len(),
            "{name} parent map left trailing bytes"
        );
        assert_eq!(
            decoded.inner, proof.parents_commitments,
            "{name} parent map changed after optimized decode"
        );
    }
}
