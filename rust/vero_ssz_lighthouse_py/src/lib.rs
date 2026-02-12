use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{BitList, BitVector, FixedVector, VariableList};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;
use typenum::{
    U1, U2, U4, U8, U16, U20, U32, U33, U48, U64, U96, U256, U512, U2048, U4096, U8192,
    U131072, U1048576, U1073741824,
};

#[derive(Clone, Copy)]
enum Preset {
    Mainnet,
    Gnosis,
    Minimal,
}

impl Preset {
    fn parse(preset: &str) -> PyResult<Self> {
        match preset.to_ascii_lowercase().as_str() {
            "mainnet" => Ok(Self::Mainnet),
            "gnosis" => Ok(Self::Gnosis),
            "minimal" => Ok(Self::Minimal),
            _ => Err(PyValueError::new_err(
                "Unsupported preset. Expected one of: mainnet, gnosis, minimal",
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Gnosis => "gnosis",
            Self::Minimal => "minimal",
        }
    }
}

macro_rules! define_preset_module {
    (
        $mod_name:ident,
        $sync_committee_size:ty,
        $max_committees_per_slot:ty,
        $max_attesting_indices:ty,
        $max_proposer_slashings:ty,
        $max_attester_slashings_electra:ty,
        $max_attestations_electra:ty,
        $max_deposits:ty,
        $max_voluntary_exits:ty,
        $max_bls_to_execution_changes:ty,
        $max_withdrawals_per_payload:ty,
        $max_blob_commitments_per_block:ty,
        $max_deposit_requests_per_payload:ty,
        $max_withdrawal_requests_per_payload:ty,
        $max_consolidation_requests_per_payload:ty,
        $max_bytes_per_transaction:ty,
        $max_transactions_per_payload:ty,
        $bytes_per_logs_bloom:ty,
        $max_extra_data_bytes:ty
    ) => {
        mod $mod_name {
            use super::*;

            type SyncCommitteeSize = $sync_committee_size;
            type MaxCommitteesPerSlot = $max_committees_per_slot;
            type MaxAttestingIndices = $max_attesting_indices;
            type MaxProposerSlashings = $max_proposer_slashings;
            type MaxAttesterSlashingsElectra = $max_attester_slashings_electra;
            type MaxAttestationsElectra = $max_attestations_electra;
            type MaxDeposits = $max_deposits;
            type MaxVoluntaryExits = $max_voluntary_exits;
            type MaxBlsToExecutionChanges = $max_bls_to_execution_changes;
            type MaxWithdrawalsPerPayload = $max_withdrawals_per_payload;
            type MaxBlobCommitmentsPerBlock = $max_blob_commitments_per_block;
            type MaxDepositRequestsPerPayload = $max_deposit_requests_per_payload;
            type MaxWithdrawalRequestsPerPayload = $max_withdrawal_requests_per_payload;
            type MaxConsolidationRequestsPerPayload = $max_consolidation_requests_per_payload;
            type MaxBytesPerTransaction = $max_bytes_per_transaction;
            type MaxTransactionsPerPayload = $max_transactions_per_payload;
            type BytesPerLogsBloom = $bytes_per_logs_bloom;
            type MaxExtraDataBytes = $max_extra_data_bytes;

            type Bytes32 = FixedVector<u8, U32>;
            type Bytes48 = FixedVector<u8, U48>;
            type Bytes96 = FixedVector<u8, U96>;
            type ExecutionAddress = FixedVector<u8, U20>;
            type U256Bytes = FixedVector<u8, U32>;
            type CommitteeBits = BitVector<MaxCommitteesPerSlot>;
            type AggregationBits = BitList<MaxAttestingIndices>;
            type Transaction = VariableList<u8, MaxBytesPerTransaction>;

            #[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
            struct Checkpoint {
                epoch: u64,
                root: Bytes32,
            }

            #[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
            struct AttestationData {
                slot: u64,
                index: u64,
                beacon_block_root: Bytes32,
                source: Checkpoint,
                target: Checkpoint,
            }

            #[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
            struct AttestationElectra {
                aggregation_bits: AggregationBits,
                data: AttestationData,
                signature: Bytes96,
                committee_bits: CommitteeBits,
            }

            #[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
            struct IndexedAttestationElectra {
                attesting_indices: VariableList<u64, MaxAttestingIndices>,
                data: AttestationData,
                signature: Bytes96,
            }

            #[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
            struct AttesterSlashingElectra {
                attestation_1: IndexedAttestationElectra,
                attestation_2: IndexedAttestationElectra,
            }

            #[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
            struct Eth1Data {
                deposit_root: Bytes32,
                deposit_count: u64,
                block_hash: Bytes32,
            }

            #[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
            struct DepositData {
                pubkey: Bytes48,
                withdrawal_credentials: Bytes32,
                amount: u64,
                signature: Bytes96,
            }

            #[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
            struct Deposit {
                proof: FixedVector<Bytes32, U33>,
                data: DepositData,
            }

            #[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
            struct BeaconBlockHeader {
                slot: u64,
                proposer_index: u64,
                parent_root: Bytes32,
                state_root: Bytes32,
                body_root: Bytes32,
            }

            #[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
            struct SignedBeaconBlockHeader {
                message: BeaconBlockHeader,
                signature: Bytes96,
            }

            #[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
            struct ProposerSlashing {
                signed_header_1: SignedBeaconBlockHeader,
                signed_header_2: SignedBeaconBlockHeader,
            }

            #[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
            struct VoluntaryExit {
                epoch: u64,
                validator_index: u64,
            }

            #[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
            struct SignedVoluntaryExit {
                message: VoluntaryExit,
                signature: Bytes96,
            }

            #[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
            struct SyncAggregate {
                sync_committee_bits: BitVector<SyncCommitteeSize>,
                sync_committee_signature: Bytes96,
            }

            #[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
            struct Withdrawal {
                index: u64,
                validator_index: u64,
                address: ExecutionAddress,
                amount: u64,
            }

            #[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
            struct ExecutionPayloadV3 {
                parent_hash: Bytes32,
                fee_recipient: ExecutionAddress,
                state_root: Bytes32,
                receipts_root: Bytes32,
                logs_bloom: FixedVector<u8, BytesPerLogsBloom>,
                prev_randao: Bytes32,
                block_number: u64,
                gas_limit: u64,
                gas_used: u64,
                timestamp: u64,
                extra_data: VariableList<u8, MaxExtraDataBytes>,
                base_fee_per_gas: U256Bytes,
                block_hash: Bytes32,
                transactions: VariableList<Transaction, MaxTransactionsPerPayload>,
                withdrawals: VariableList<Withdrawal, MaxWithdrawalsPerPayload>,
                blob_gas_used: u64,
                excess_blob_gas: u64,
            }

            #[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
            struct BlsToExecutionChange {
                validator_index: u64,
                from_bls_pubkey: Bytes48,
                to_execution_address: ExecutionAddress,
            }

            #[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
            struct SignedBlsToExecutionChange {
                message: BlsToExecutionChange,
                signature: Bytes96,
            }

            #[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
            struct DepositRequest {
                pubkey: Bytes48,
                withdrawal_credentials: Bytes32,
                amount: u64,
                signature: Bytes96,
                index: u64,
            }

            #[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
            struct WithdrawalRequest {
                source_address: ExecutionAddress,
                validator_pubkey: Bytes48,
                amount: u64,
            }

            #[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
            struct ConsolidationRequest {
                source_address: ExecutionAddress,
                source_pubkey: Bytes48,
                target_pubkey: Bytes48,
            }

            #[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
            struct ExecutionRequests {
                deposits: VariableList<DepositRequest, MaxDepositRequestsPerPayload>,
                withdrawals: VariableList<WithdrawalRequest, MaxWithdrawalRequestsPerPayload>,
                consolidations: VariableList<ConsolidationRequest, MaxConsolidationRequestsPerPayload>,
            }

            #[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
            struct BeaconBlockBodyElectra {
                randao_reveal: Bytes96,
                eth1_data: Eth1Data,
                graffiti: Bytes32,
                proposer_slashings: VariableList<ProposerSlashing, MaxProposerSlashings>,
                attester_slashings: VariableList<AttesterSlashingElectra, MaxAttesterSlashingsElectra>,
                attestations: VariableList<AttestationElectra, MaxAttestationsElectra>,
                deposits: VariableList<Deposit, MaxDeposits>,
                voluntary_exits: VariableList<SignedVoluntaryExit, MaxVoluntaryExits>,
                sync_aggregate: SyncAggregate,
                execution_payload: ExecutionPayloadV3,
                bls_to_execution_changes: VariableList<SignedBlsToExecutionChange, MaxBlsToExecutionChanges>,
                blob_kzg_commitments: VariableList<Bytes48, MaxBlobCommitmentsPerBlock>,
                execution_requests: ExecutionRequests,
            }

            #[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
            pub(super) struct BeaconBlockElectra {
                slot: u64,
                proposer_index: u64,
                parent_root: Bytes32,
                state_root: Bytes32,
                body: BeaconBlockBodyElectra,
            }

            pub(super) fn decode_block(ssz_bytes: &[u8]) -> Result<BeaconBlockElectra, ssz::DecodeError> {
                BeaconBlockElectra::from_ssz_bytes(ssz_bytes)
            }

            pub(super) fn slot(block: &BeaconBlockElectra) -> u64 { block.slot }
            pub(super) fn body_root_hex(block: &BeaconBlockElectra) -> String {
                format!("0x{}", hex::encode(block.body.tree_hash_root().0))
            }
            pub(super) fn encode(block: &BeaconBlockElectra) -> Vec<u8> { block.as_ssz_bytes() }
        }
    };
}

define_preset_module!(
    mainnet,
    U512,
    U64,
    U131072,
    U16,
    U1,
    U8,
    U16,
    U16,
    U16,
    U16,
    U4096,
    U8192,
    U16,
    U2,
    U1073741824,
    U1048576,
    U256,
    U32
);

define_preset_module!(
    gnosis,
    U512,
    U64,
    U131072,
    U16,
    U1,
    U8,
    U16,
    U16,
    U16,
    U8,
    U4096,
    U8192,
    U16,
    U2,
    U1073741824,
    U1048576,
    U256,
    U32
);

define_preset_module!(
    minimal,
    U32,
    U4,
    U8192,
    U16,
    U1,
    U8,
    U16,
    U16,
    U16,
    U4,
    U32,
    U4,
    U2,
    U2,
    U1073741824,
    U1048576,
    U256,
    U32
);

enum LighthouseBlockVariant {
    Mainnet(mainnet::BeaconBlockElectra),
    Gnosis(gnosis::BeaconBlockElectra),
    Minimal(minimal::BeaconBlockElectra),
}

#[pyclass]
struct LighthouseBeaconBlockElectra {
    inner: LighthouseBlockVariant,
}

#[pymethods]
impl LighthouseBeaconBlockElectra {
    #[staticmethod]
    #[pyo3(signature=(ssz_bytes, preset="mainnet"))]
    fn from_ssz_bytes(ssz_bytes: Vec<u8>, preset: &str) -> PyResult<Self> {
        let p = Preset::parse(preset)?;
        let inner = match p {
            Preset::Mainnet => LighthouseBlockVariant::Mainnet(
                mainnet::decode_block(&ssz_bytes).map_err(|e| {
                    PyValueError::new_err(format!("Failed to decode BeaconBlockElectra: {e:?}"))
                })?,
            ),
            Preset::Gnosis => LighthouseBlockVariant::Gnosis(
                gnosis::decode_block(&ssz_bytes).map_err(|e| {
                    PyValueError::new_err(format!("Failed to decode BeaconBlockElectra: {e:?}"))
                })?,
            ),
            Preset::Minimal => LighthouseBlockVariant::Minimal(
                minimal::decode_block(&ssz_bytes).map_err(|e| {
                    PyValueError::new_err(format!("Failed to decode BeaconBlockElectra: {e:?}"))
                })?,
            ),
        };
        Ok(Self { inner })
    }

    fn slot(&self) -> u64 {
        match &self.inner {
            LighthouseBlockVariant::Mainnet(b) => mainnet::slot(b),
            LighthouseBlockVariant::Gnosis(b) => gnosis::slot(b),
            LighthouseBlockVariant::Minimal(b) => minimal::slot(b),
        }
    }

    fn body_root_hex(&self) -> String {
        match &self.inner {
            LighthouseBlockVariant::Mainnet(b) => mainnet::body_root_hex(b),
            LighthouseBlockVariant::Gnosis(b) => gnosis::body_root_hex(b),
            LighthouseBlockVariant::Minimal(b) => minimal::body_root_hex(b),
        }
    }

    fn encode_ssz_bytes(&self) -> Vec<u8> {
        match &self.inner {
            LighthouseBlockVariant::Mainnet(b) => mainnet::encode(b),
            LighthouseBlockVariant::Gnosis(b) => gnosis::encode(b),
            LighthouseBlockVariant::Minimal(b) => minimal::encode(b),
        }
    }
}

#[pyclass]
struct LighthouseSszContext {
    preset: Preset,
}

#[pymethods]
impl LighthouseSszContext {
    #[staticmethod]
    fn from_preset(preset: &str) -> PyResult<Self> {
        Ok(Self {
            preset: Preset::parse(preset)?,
        })
    }

    fn preset(&self) -> &'static str {
        self.preset.as_str()
    }

    fn beacon_block_from_ssz_bytes(&self, ssz_bytes: Vec<u8>) -> PyResult<LighthouseBeaconBlockElectra> {
        LighthouseBeaconBlockElectra::from_ssz_bytes(ssz_bytes, self.preset.as_str())
    }
}

#[pyfunction]
#[pyo3(signature=(ssz_bytes, preset="mainnet"))]
fn beacon_block_decode_slot_from_ssz(ssz_bytes: Vec<u8>, preset: &str) -> PyResult<u64> {
    let block = LighthouseBeaconBlockElectra::from_ssz_bytes(ssz_bytes, preset)?;
    Ok(block.slot())
}

#[pyfunction]
#[pyo3(signature=(ssz_bytes, preset="mainnet"))]
fn beacon_block_body_root_hex_from_ssz(ssz_bytes: Vec<u8>, preset: &str) -> PyResult<String> {
    let block = LighthouseBeaconBlockElectra::from_ssz_bytes(ssz_bytes, preset)?;
    Ok(block.body_root_hex())
}

#[pyfunction]
#[pyo3(signature=(ssz_bytes, preset="mainnet"))]
fn beacon_block_reencode_from_ssz(ssz_bytes: Vec<u8>, preset: &str) -> PyResult<Vec<u8>> {
    let block = LighthouseBeaconBlockElectra::from_ssz_bytes(ssz_bytes, preset)?;
    Ok(block.encode_ssz_bytes())
}

#[pymodule]
fn vero_ssz_lighthouse_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<LighthouseBeaconBlockElectra>()?;
    m.add_class::<LighthouseSszContext>()?;
    m.add_function(wrap_pyfunction!(beacon_block_decode_slot_from_ssz, m)?)?;
    m.add_function(wrap_pyfunction!(beacon_block_body_root_hex_from_ssz, m)?)?;
    m.add_function(wrap_pyfunction!(beacon_block_reencode_from_ssz, m)?)?;
    Ok(())
}
