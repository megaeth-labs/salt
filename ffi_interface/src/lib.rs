mod serialization;

use banderwagon::Element;
use serialization::fr_to_le_bytes;

/// A serialized uncompressed group element
pub type CommitmentBytes = [u8; 64];

/// A serialized scalar field element
pub type ScalarBytes = [u8; 32];

#[derive(Debug, Clone)]
pub enum Error {
    FailedToDeserializeScalar {
        bytes: Vec<u8>,
    },
    // Add other error variants if they are used by the remaining code
}

pub fn hash_commitment(commitment: CommitmentBytes) -> ScalarBytes {
    // TODO: We could introduce a method named `hash_commit_to_scalars`
    // TODO: which would save this serialization roundtrip. We should profile/check that
    // TODO: this is actually a bottleneck for the average workflow before doing this.
    fr_to_le_bytes(Element::from_bytes_unchecked_uncompressed(commitment).map_to_scalar_field())
}