//! Lighthouse-SSZ spike (separate from active lib.rs)
//!
//! Goal: prove that we can model the same BeaconBlockElectra pipeline using
//! Lighthouse ecosystem crates (`ethereum_ssz`, `ssz_types`, `tree_hash`) while
//! keeping the current API shape.
//!
//! This file is intentionally not wired into the active module exports yet.
//! It is a migration spike so we don't lose progress in `lib.rs`.

use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{BitList, BitVector, FixedVector, VariableList};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;
use typenum::{
    U1, U2, U8, U16, U20, U32, U33, U48, U64, U96, U256, U512, U2048, U4096, U8192, U131072,
    U1048576, U1073741824,
};

// Mainnet/Gnosis preset values (shared for most fields)
type SyncCommitteeSize = U512;
type MaxCommitteesPerSlot = U64;
type MaxValidatorsPerCommittee = U2048;
type MaxAttestingIndices = U131072; // 2048 * 64
type MaxProposerSlashings = U16;
type MaxAttesterSlashingsElectra = U1;
type MaxAttestationsElectra = U8;
type MaxDeposits = U16;
type MaxVoluntaryExits = U16;
type MaxBlsToExecutionChanges = U16;
type MaxWithdrawalsPerPayload = U16;
type MaxBlobCommitmentsPerBlock = U4096;
type MaxDepositRequestsPerPayload = U8192;
type MaxWithdrawalRequestsPerPayload = U16;
type MaxConsolidationRequestsPerPayload = U2;
type MaxBytesPerTransaction = U1073741824;
type MaxTransactionsPerPayload = U1048576;
type BytesPerLogsBloom = U256;
type MaxExtraDataBytes = U32;

type Bytes32 = FixedVector<u8, U32>;
type Bytes48 = FixedVector<u8, U48>;
type Bytes96 = FixedVector<u8, U96>;
type ExecutionAddress = FixedVector<u8, U20>;
type U256Bytes = FixedVector<u8, U32>;

type CommitteeBits = BitVector<MaxCommitteesPerSlot>;
type AggregationBits = BitList<MaxAttestingIndices>;
type Transaction = VariableList<u8, MaxBytesPerTransaction>;

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct Checkpoint {
    pub epoch: u64,
    pub root: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct AttestationData {
    pub slot: u64,
    pub index: u64,
    pub beacon_block_root: Bytes32,
    pub source: Checkpoint,
    pub target: Checkpoint,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct AttestationElectra {
    pub aggregation_bits: AggregationBits,
    pub data: AttestationData,
    pub signature: Bytes96,
    pub committee_bits: CommitteeBits,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct IndexedAttestationElectra {
    pub attesting_indices: VariableList<u64, MaxAttestingIndices>,
    pub data: AttestationData,
    pub signature: Bytes96,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct AttesterSlashingElectra {
    pub attestation_1: IndexedAttestationElectra,
    pub attestation_2: IndexedAttestationElectra,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct Eth1Data {
    pub deposit_root: Bytes32,
    pub deposit_count: u64,
    pub block_hash: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct DepositData {
    pub pubkey: Bytes48,
    pub withdrawal_credentials: Bytes32,
    pub amount: u64,
    pub signature: Bytes96,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct Deposit {
    pub proof: FixedVector<Bytes32, U33>,
    pub data: DepositData,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct BeaconBlockHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: Bytes32,
    pub state_root: Bytes32,
    pub body_root: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct SignedBeaconBlockHeader {
    pub message: BeaconBlockHeader,
    pub signature: Bytes96,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct ProposerSlashing {
    pub signed_header_1: SignedBeaconBlockHeader,
    pub signed_header_2: SignedBeaconBlockHeader,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct VoluntaryExit {
    pub epoch: u64,
    pub validator_index: u64,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct SignedVoluntaryExit {
    pub message: VoluntaryExit,
    pub signature: Bytes96,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct SyncAggregate {
    pub sync_committee_bits: BitVector<SyncCommitteeSize>,
    pub sync_committee_signature: Bytes96,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct Withdrawal {
    pub index: u64,
    pub validator_index: u64,
    pub address: ExecutionAddress,
    pub amount: u64,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct ExecutionPayloadV3 {
    pub parent_hash: Bytes32,
    pub fee_recipient: ExecutionAddress,
    pub state_root: Bytes32,
    pub receipts_root: Bytes32,
    pub logs_bloom: FixedVector<u8, BytesPerLogsBloom>,
    pub prev_randao: Bytes32,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: VariableList<u8, MaxExtraDataBytes>,
    pub base_fee_per_gas: U256Bytes,
    pub block_hash: Bytes32,
    pub transactions: VariableList<Transaction, MaxTransactionsPerPayload>,
    pub withdrawals: VariableList<Withdrawal, MaxWithdrawalsPerPayload>,
    pub blob_gas_used: u64,
    pub excess_blob_gas: u64,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct BlsToExecutionChange {
    pub validator_index: u64,
    pub from_bls_pubkey: Bytes48,
    pub to_execution_address: ExecutionAddress,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct SignedBlsToExecutionChange {
    pub message: BlsToExecutionChange,
    pub signature: Bytes96,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct DepositRequest {
    pub pubkey: Bytes48,
    pub withdrawal_credentials: Bytes32,
    pub amount: u64,
    pub signature: Bytes96,
    pub index: u64,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct WithdrawalRequest {
    pub source_address: ExecutionAddress,
    pub validator_pubkey: Bytes48,
    pub amount: u64,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct ConsolidationRequest {
    pub source_address: ExecutionAddress,
    pub source_pubkey: Bytes48,
    pub target_pubkey: Bytes48,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct ExecutionRequests {
    pub deposits: VariableList<DepositRequest, MaxDepositRequestsPerPayload>,
    pub withdrawals: VariableList<WithdrawalRequest, MaxWithdrawalRequestsPerPayload>,
    pub consolidations: VariableList<ConsolidationRequest, MaxConsolidationRequestsPerPayload>,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct BeaconBlockBodyElectra {
    pub randao_reveal: Bytes96,
    pub eth1_data: Eth1Data,
    pub graffiti: Bytes32,
    pub proposer_slashings: VariableList<ProposerSlashing, MaxProposerSlashings>,
    pub attester_slashings: VariableList<AttesterSlashingElectra, MaxAttesterSlashingsElectra>,
    pub attestations: VariableList<AttestationElectra, MaxAttestationsElectra>,
    pub deposits: VariableList<Deposit, MaxDeposits>,
    pub voluntary_exits: VariableList<SignedVoluntaryExit, MaxVoluntaryExits>,
    pub sync_aggregate: SyncAggregate,
    pub execution_payload: ExecutionPayloadV3,
    pub bls_to_execution_changes:
        VariableList<SignedBlsToExecutionChange, MaxBlsToExecutionChanges>,
    pub blob_kzg_commitments: VariableList<Bytes48, MaxBlobCommitmentsPerBlock>,
    pub execution_requests: ExecutionRequests,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct BeaconBlockElectra {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: Bytes32,
    pub state_root: Bytes32,
    pub body: BeaconBlockBodyElectra,
}

pub fn decode_block_from_ssz(bytes: &[u8]) -> Result<BeaconBlockElectra, ssz::DecodeError> {
    BeaconBlockElectra::from_ssz_bytes(bytes)
}

pub fn encode_block_to_ssz(block: &BeaconBlockElectra) -> Vec<u8> {
    block.as_ssz_bytes()
}

pub fn block_root(block: &BeaconBlockElectra) -> [u8; 32] {
    block.tree_hash_root().0
}

pub fn body_root(block: &BeaconBlockElectra) -> [u8; 32] {
    block.body.tree_hash_root().0
}
