use banderwagon::{CanonicalSerialize};

pub(crate) fn fr_to_le_bytes(fr: banderwagon::Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    fr.serialize_compressed(&mut bytes[..])
        .expect("Failed to serialize scalar to bytes");
    bytes
}
