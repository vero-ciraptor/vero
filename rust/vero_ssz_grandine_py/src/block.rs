use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use ssz_grandine::{
    BitList, BitVector, ByteList, ByteVector, ContiguousList, Ssz, SszHash, SszReadDefault,
    SszWrite,
};
use typenum::{
    U1, U2, U4, U8, U16, U20, U32, U33, U48, U64, U96, U256, U512, U4096, U8192, U131072,
    U1048576, U1073741824,
};

use crate::preset::Preset;
use crate::shared_containers::AttestationData;

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

            type CommitteeBits = BitVector<MaxCommitteesPerSlot>;
            type AggregationBits = BitList<MaxAttestingIndices>;
            type Transaction = ByteList<MaxBytesPerTransaction>;

            #[derive(Clone, Debug, Ssz)]
            struct AttestationElectra {
                aggregation_bits: AggregationBits,
                data: AttestationData,
                signature: ByteVector<U96>,
                committee_bits: CommitteeBits,
            }

            #[derive(Clone, Debug, Ssz)]
            struct IndexedAttestationElectra {
                attesting_indices: ContiguousList<u64, MaxAttestingIndices>,
                data: AttestationData,
                signature: ByteVector<U96>,
            }

            #[derive(Clone, Debug, Ssz)]
            struct AttesterSlashingElectra {
                attestation_1: IndexedAttestationElectra,
                attestation_2: IndexedAttestationElectra,
            }

            #[derive(Clone, Debug, Ssz)]
            struct Eth1Data {
                deposit_root: ByteVector<U32>,
                deposit_count: u64,
                block_hash: ByteVector<U32>,
            }

            #[derive(Clone, Debug, Ssz)]
            struct DepositData {
                pubkey: ByteVector<U48>,
                withdrawal_credentials: ByteVector<U32>,
                amount: u64,
                signature: ByteVector<U96>,
            }

            #[derive(Clone, Debug, Ssz)]
            struct Deposit {
                proof: ContiguousList<ByteVector<U32>, U33>,
                data: DepositData,
            }

            #[derive(Clone, Debug, Ssz)]
            struct BeaconBlockHeader {
                slot: u64,
                proposer_index: u64,
                parent_root: ByteVector<U32>,
                state_root: ByteVector<U32>,
                body_root: ByteVector<U32>,
            }

            #[derive(Clone, Debug, Ssz)]
            struct SignedBeaconBlockHeader {
                message: BeaconBlockHeader,
                signature: ByteVector<U96>,
            }

            #[derive(Clone, Debug, Ssz)]
            struct ProposerSlashing {
                signed_header_1: SignedBeaconBlockHeader,
                signed_header_2: SignedBeaconBlockHeader,
            }

            #[derive(Clone, Debug, Ssz)]
            struct VoluntaryExit {
                epoch: u64,
                validator_index: u64,
            }

            #[derive(Clone, Debug, Ssz)]
            struct SignedVoluntaryExit {
                message: VoluntaryExit,
                signature: ByteVector<U96>,
            }

            #[derive(Clone, Debug, Ssz)]
            struct SyncAggregate {
                sync_committee_bits: BitVector<SyncCommitteeSize>,
                sync_committee_signature: ByteVector<U96>,
            }

            #[derive(Clone, Debug, Ssz)]
            struct Withdrawal {
                index: u64,
                validator_index: u64,
                address: ByteVector<U20>,
                amount: u64,
            }

            #[derive(Clone, Debug, Ssz)]
            struct ExecutionPayloadV3 {
                parent_hash: ByteVector<U32>,
                fee_recipient: ByteVector<U20>,
                state_root: ByteVector<U32>,
                receipts_root: ByteVector<U32>,
                logs_bloom: ByteVector<BytesPerLogsBloom>,
                prev_randao: ByteVector<U32>,
                block_number: u64,
                gas_limit: u64,
                gas_used: u64,
                timestamp: u64,
                extra_data: ByteList<MaxExtraDataBytes>,
                base_fee_per_gas: ByteVector<U32>,
                block_hash: ByteVector<U32>,
                transactions: ContiguousList<Transaction, MaxTransactionsPerPayload>,
                withdrawals: ContiguousList<Withdrawal, MaxWithdrawalsPerPayload>,
                blob_gas_used: u64,
                excess_blob_gas: u64,
            }

            #[derive(Clone, Debug, Ssz)]
            struct BlsToExecutionChange {
                validator_index: u64,
                from_bls_pubkey: ByteVector<U48>,
                to_execution_address: ByteVector<U20>,
            }

            #[derive(Clone, Debug, Ssz)]
            struct SignedBlsToExecutionChange {
                message: BlsToExecutionChange,
                signature: ByteVector<U96>,
            }

            #[derive(Clone, Debug, Ssz)]
            struct DepositRequest {
                pubkey: ByteVector<U48>,
                withdrawal_credentials: ByteVector<U32>,
                amount: u64,
                signature: ByteVector<U96>,
                index: u64,
            }

            #[derive(Clone, Debug, Ssz)]
            struct WithdrawalRequest {
                source_address: ByteVector<U20>,
                validator_pubkey: ByteVector<U48>,
                amount: u64,
            }

            #[derive(Clone, Debug, Ssz)]
            struct ConsolidationRequest {
                source_address: ByteVector<U20>,
                source_pubkey: ByteVector<U48>,
                target_pubkey: ByteVector<U48>,
            }

            #[derive(Clone, Debug, Ssz)]
            struct ExecutionRequests {
                deposits: ContiguousList<DepositRequest, MaxDepositRequestsPerPayload>,
                withdrawals: ContiguousList<WithdrawalRequest, MaxWithdrawalRequestsPerPayload>,
                consolidations: ContiguousList<ConsolidationRequest, MaxConsolidationRequestsPerPayload>,
            }

            #[derive(Clone, Debug, Ssz)]
            struct BeaconBlockBodyElectra {
                randao_reveal: ByteVector<U96>,
                eth1_data: Eth1Data,
                graffiti: ByteVector<U32>,
                proposer_slashings: ContiguousList<ProposerSlashing, MaxProposerSlashings>,
                attester_slashings: ContiguousList<AttesterSlashingElectra, MaxAttesterSlashingsElectra>,
                attestations: ContiguousList<AttestationElectra, MaxAttestationsElectra>,
                deposits: ContiguousList<Deposit, MaxDeposits>,
                voluntary_exits: ContiguousList<SignedVoluntaryExit, MaxVoluntaryExits>,
                sync_aggregate: SyncAggregate,
                execution_payload: ExecutionPayloadV3,
                bls_to_execution_changes: ContiguousList<SignedBlsToExecutionChange, MaxBlsToExecutionChanges>,
                blob_kzg_commitments: ContiguousList<ByteVector<U48>, MaxBlobCommitmentsPerBlock>,
                execution_requests: ExecutionRequests,
            }

            #[derive(Clone, Debug, Ssz)]
            pub(super) struct BeaconBlockElectra {
                slot: u64,
                proposer_index: u64,
                parent_root: ByteVector<U32>,
                state_root: ByteVector<U32>,
                body: BeaconBlockBodyElectra,
            }

            pub(super) fn decode_block(ssz_bytes: &[u8]) -> Result<BeaconBlockElectra, ssz_grandine::ReadError> {
                BeaconBlockElectra::from_ssz_default(ssz_bytes)
            }

            pub(super) fn slot(block: &BeaconBlockElectra) -> u64 { block.slot }
            pub(super) fn body_root_hex(block: &BeaconBlockElectra) -> String {
                format!("0x{}", hex::encode(block.body.hash_tree_root().as_bytes()))
            }
            pub(super) fn encode(block: &BeaconBlockElectra) -> Result<Vec<u8>, ssz_grandine::WriteError> {
                block.to_ssz()
            }
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

enum GrandineBlockVariant {
    Mainnet(mainnet::BeaconBlockElectra),
    Gnosis(gnosis::BeaconBlockElectra),
    Minimal(minimal::BeaconBlockElectra),
}

#[pyclass]
struct GrandineBeaconBlockElectra {
    inner: GrandineBlockVariant,
}

#[pymethods]
impl GrandineBeaconBlockElectra {
    #[staticmethod]
    #[pyo3(signature=(ssz_bytes, preset="mainnet"))]
    fn from_ssz_bytes(ssz_bytes: Vec<u8>, preset: &str) -> PyResult<Self> {
        let p = Preset::parse(preset)?;
        let inner = match p {
            Preset::Mainnet => GrandineBlockVariant::Mainnet(
                mainnet::decode_block(&ssz_bytes)
                    .map_err(|e| PyValueError::new_err(format!("Failed to decode BeaconBlockElectra: {e:?}")))?,
            ),
            Preset::Gnosis => GrandineBlockVariant::Gnosis(
                gnosis::decode_block(&ssz_bytes)
                    .map_err(|e| PyValueError::new_err(format!("Failed to decode BeaconBlockElectra: {e:?}")))?,
            ),
            Preset::Minimal => GrandineBlockVariant::Minimal(
                minimal::decode_block(&ssz_bytes)
                    .map_err(|e| PyValueError::new_err(format!("Failed to decode BeaconBlockElectra: {e:?}")))?,
            ),
        };
        Ok(Self { inner })
    }

    fn slot(&self) -> u64 {
        match &self.inner {
            GrandineBlockVariant::Mainnet(b) => mainnet::slot(b),
            GrandineBlockVariant::Gnosis(b) => gnosis::slot(b),
            GrandineBlockVariant::Minimal(b) => minimal::slot(b),
        }
    }

    fn body_root_hex(&self) -> String {
        match &self.inner {
            GrandineBlockVariant::Mainnet(b) => mainnet::body_root_hex(b),
            GrandineBlockVariant::Gnosis(b) => gnosis::body_root_hex(b),
            GrandineBlockVariant::Minimal(b) => minimal::body_root_hex(b),
        }
    }

    fn encode_ssz_bytes(&self) -> PyResult<Vec<u8>> {
        match &self.inner {
            GrandineBlockVariant::Mainnet(b) => mainnet::encode(b),
            GrandineBlockVariant::Gnosis(b) => gnosis::encode(b),
            GrandineBlockVariant::Minimal(b) => minimal::encode(b),
        }
        .map_err(|e| PyValueError::new_err(format!("Failed to encode BeaconBlockElectra: {e:?}")))
    }
}

#[pyclass]
struct GrandineSszContext {
    preset: Preset,
}

#[pymethods]
impl GrandineSszContext {
    #[staticmethod]
    fn from_preset(preset: &str) -> PyResult<Self> {
        Ok(Self {
            preset: Preset::parse(preset)?,
        })
    }

    fn preset(&self) -> &'static str {
        self.preset.as_str()
    }

    fn beacon_block_from_ssz_bytes(&self, ssz_bytes: Vec<u8>) -> PyResult<GrandineBeaconBlockElectra> {
        GrandineBeaconBlockElectra::from_ssz_bytes(ssz_bytes, self.preset.as_str())
    }
}

#[pyfunction]
#[pyo3(signature=(ssz_bytes, preset="mainnet"))]
fn beacon_block_decode_slot_from_ssz(ssz_bytes: Vec<u8>, preset: &str) -> PyResult<u64> {
    Ok(GrandineBeaconBlockElectra::from_ssz_bytes(ssz_bytes, preset)?.slot())
}

#[pyfunction]
#[pyo3(signature=(ssz_bytes, preset="mainnet"))]
fn beacon_block_body_root_hex_from_ssz(ssz_bytes: Vec<u8>, preset: &str) -> PyResult<String> {
    Ok(GrandineBeaconBlockElectra::from_ssz_bytes(ssz_bytes, preset)?.body_root_hex())
}

#[pyfunction]
#[pyo3(signature=(ssz_bytes, preset="mainnet"))]
fn beacon_block_reencode_from_ssz(ssz_bytes: Vec<u8>, preset: &str) -> PyResult<Vec<u8>> {
    GrandineBeaconBlockElectra::from_ssz_bytes(ssz_bytes, preset)?.encode_ssz_bytes()
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<GrandineBeaconBlockElectra>()?;
    m.add_class::<GrandineSszContext>()?;
    m.add_function(wrap_pyfunction!(beacon_block_decode_slot_from_ssz, m)?)?;
    m.add_function(wrap_pyfunction!(beacon_block_body_root_hex_from_ssz, m)?)?;
    m.add_function(wrap_pyfunction!(beacon_block_reencode_from_ssz, m)?)?;
    Ok(())
}
