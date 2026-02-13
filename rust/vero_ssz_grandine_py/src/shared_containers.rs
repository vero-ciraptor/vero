use serde::Deserialize;
use ssz_grandine::{ByteVector, Ssz};
use typenum::U32;

#[derive(Clone, Debug, Ssz, Deserialize)]
pub(crate) struct Checkpoint {
    pub(crate) epoch: u64,
    pub(crate) root: ByteVector<U32>,
}

#[derive(Clone, Debug, Ssz, Deserialize)]
pub(crate) struct AttestationData {
    pub(crate) slot: u64,
    pub(crate) index: u64,
    pub(crate) beacon_block_root: ByteVector<U32>,
    pub(crate) source: Checkpoint,
    pub(crate) target: Checkpoint,
}
