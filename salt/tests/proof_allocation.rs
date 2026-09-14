use salt::proof::PathCommitments;

#[test]
fn hostile_96_byte_witness_returns_error() {
    for n in [1u64 << 56, u64::MAX] {
        // Empty key/value map, then a proof map with a false length and two entries.
        let mut wire = 0u64.to_le_bytes().to_vec();
        wire.extend_from_slice(&n.to_le_bytes());
        for id in 0u64..2 {
            wire.extend_from_slice(&id.to_le_bytes());
            wire.extend_from_slice(&[0u8; 32]);
        }
        assert_eq!(wire.len(), 96);
        let result = std::panic::catch_unwind(|| {
            bincode::serde::decode_from_slice::<salt::SaltWitness, _>(
                &wire,
                bincode::config::legacy(),
            )
        });
        assert!(result.is_ok(), "witness panic with length {n}");
        assert!(result.unwrap().is_err());
        let limited = std::panic::catch_unwind(|| {
            bincode::serde::decode_from_slice::<salt::SaltWitness, _>(
                &wire,
                bincode::config::legacy().with_limit::<1024>(),
            )
        });
        assert!(limited.is_ok(), "limited witness panic with length {n}");
        assert!(limited.unwrap().is_err());
    }
}

#[test]
fn fabricated_lengths_return_errors_without_panicking() {
    for n in [0, 1, 65_535, 65_536, 65_537, 1u64 << 56, u64::MAX] {
        let bytes = n.to_le_bytes();
        let result = std::panic::catch_unwind(|| {
            bincode::serde::decode_from_slice::<salt::SaltProof, _>(
                &bytes,
                bincode::config::legacy(),
            )
        });
        assert!(result.is_ok(), "panic with declared length {n}");
        assert!(result.unwrap().is_err());
        let limited = std::panic::catch_unwind(|| {
            bincode::serde::decode_from_slice::<salt::SaltProof, _>(
                &bytes,
                bincode::config::legacy().with_limit::<1024>(),
            )
        });
        assert!(limited.is_ok(), "panic with byte budget, length {n}");
        assert!(limited.unwrap().is_err());
    }
}

#[test]
fn valid_map_larger_than_initial_cap_still_decodes() {
    let n = 65_537u64;
    let mut wire = n.to_le_bytes().to_vec();
    for id in 0..n {
        wire.extend_from_slice(&id.to_le_bytes());
        // The zero-byte encoding is a valid identity commitment.
        wire.extend_from_slice(&[0u8; 32]);
    }
    let (map, consumed) =
        bincode::serde::decode_from_slice::<PathCommitments, _>(&wire, bincode::config::legacy())
            .unwrap();
    assert_eq!(map.len(), n as usize);
    assert_eq!(consumed, wire.len());
    let encoded = bincode::serde::encode_to_vec(&map, bincode::config::legacy()).unwrap();
    assert_eq!(encoded, wire);
}
