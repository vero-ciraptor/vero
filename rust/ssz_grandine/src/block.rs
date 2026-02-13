use std::sync::RwLock;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde::de::DeserializeOwned;
use serde::Deserialize;
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

            #[derive(Clone, Debug, Ssz, Deserialize)]
            struct AttestationElectra {
                aggregation_bits: AggregationBits,
                data: AttestationData,
                signature: ByteVector<U96>,
                committee_bits: CommitteeBits,
            }

            #[derive(Clone, Debug, Ssz, Deserialize)]
            struct IndexedAttestationElectra {
                attesting_indices: ContiguousList<u64, MaxAttestingIndices>,
                data: AttestationData,
                signature: ByteVector<U96>,
            }

            #[derive(Clone, Debug, Ssz, Deserialize)]
            struct AttesterSlashingElectra {
                attestation_1: IndexedAttestationElectra,
                attestation_2: IndexedAttestationElectra,
            }

            #[derive(Clone, Debug, Ssz, Deserialize)]
            struct Eth1Data {
                deposit_root: ByteVector<U32>,
                deposit_count: u64,
                block_hash: ByteVector<U32>,
            }

            #[derive(Clone, Debug, Ssz, Deserialize)]
            struct DepositData {
                pubkey: ByteVector<U48>,
                withdrawal_credentials: ByteVector<U32>,
                amount: u64,
                signature: ByteVector<U96>,
            }

            #[derive(Clone, Debug, Ssz, Deserialize)]
            struct Deposit {
                proof: ContiguousList<ByteVector<U32>, U33>,
                data: DepositData,
            }

            #[derive(Clone, Debug, Ssz, Deserialize)]
            struct BeaconBlockHeader {
                slot: u64,
                proposer_index: u64,
                parent_root: ByteVector<U32>,
                state_root: ByteVector<U32>,
                body_root: ByteVector<U32>,
            }

            #[derive(Clone, Debug, Ssz, Deserialize)]
            struct SignedBeaconBlockHeader {
                message: BeaconBlockHeader,
                signature: ByteVector<U96>,
            }

            #[derive(Clone, Debug, Ssz, Deserialize)]
            struct ProposerSlashing {
                signed_header_1: SignedBeaconBlockHeader,
                signed_header_2: SignedBeaconBlockHeader,
            }

            #[derive(Clone, Debug, Ssz, Deserialize)]
            struct VoluntaryExit {
                epoch: u64,
                validator_index: u64,
            }

            #[derive(Clone, Debug, Ssz, Deserialize)]
            struct SignedVoluntaryExit {
                message: VoluntaryExit,
                signature: ByteVector<U96>,
            }

            #[derive(Clone, Debug, Ssz, Deserialize)]
            struct SyncAggregate {
                sync_committee_bits: BitVector<SyncCommitteeSize>,
                sync_committee_signature: ByteVector<U96>,
            }

            #[derive(Clone, Debug, Ssz, Deserialize)]
            struct Withdrawal {
                index: u64,
                validator_index: u64,
                address: ByteVector<U20>,
                amount: u64,
            }

            #[derive(Clone, Debug, Ssz, Deserialize)]
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

            #[derive(Clone, Debug, Ssz, Deserialize)]
            struct BlsToExecutionChange {
                validator_index: u64,
                from_bls_pubkey: ByteVector<U48>,
                to_execution_address: ByteVector<U20>,
            }

            #[derive(Clone, Debug, Ssz, Deserialize)]
            struct SignedBlsToExecutionChange {
                message: BlsToExecutionChange,
                signature: ByteVector<U96>,
            }

            #[derive(Clone, Debug, Ssz, Deserialize)]
            struct DepositRequest {
                pubkey: ByteVector<U48>,
                withdrawal_credentials: ByteVector<U32>,
                amount: u64,
                signature: ByteVector<U96>,
                index: u64,
            }

            #[derive(Clone, Debug, Ssz, Deserialize)]
            struct WithdrawalRequest {
                source_address: ByteVector<U20>,
                validator_pubkey: ByteVector<U48>,
                amount: u64,
            }

            #[derive(Clone, Debug, Ssz, Deserialize)]
            struct ConsolidationRequest {
                source_address: ByteVector<U20>,
                source_pubkey: ByteVector<U48>,
                target_pubkey: ByteVector<U48>,
            }

            #[derive(Clone, Debug, Ssz, Deserialize)]
            struct ExecutionRequests {
                deposits: ContiguousList<DepositRequest, MaxDepositRequestsPerPayload>,
                withdrawals: ContiguousList<WithdrawalRequest, MaxWithdrawalRequestsPerPayload>,
                consolidations: ContiguousList<ConsolidationRequest, MaxConsolidationRequestsPerPayload>,
            }

            #[derive(Clone, Debug, Ssz, Deserialize)]
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

            #[derive(Clone, Debug, Ssz, Deserialize)]
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

            #[derive(Clone, Debug, Ssz, Deserialize)]
            pub(super) struct BeaconBlockContentsElectra {
                block: BeaconBlockElectra,
                kzg_proofs: ContiguousList<ByteVector<U48>, MaxBlobCommitmentsPerBlock>,
                blobs: ContiguousList<ByteVector<U131072>, MaxBlobCommitmentsPerBlock>,
            }

            pub(super) fn decode_block_contents(ssz_bytes: &[u8]) -> Result<BeaconBlockContentsElectra, ssz_grandine::ReadError> {
                BeaconBlockContentsElectra::from_ssz_default(ssz_bytes)
            }

            #[derive(Clone, Debug, Ssz, Deserialize)]
            pub(super) struct SignedBeaconBlockElectra {
                message: BeaconBlockElectra,
                signature: ByteVector<U96>,
            }

            #[derive(Clone, Debug, Ssz, Deserialize)]
            pub(super) struct SignedBeaconBlockContentsElectra {
                signed_block: SignedBeaconBlockElectra,
                kzg_proofs: ContiguousList<ByteVector<U48>, MaxBlobCommitmentsPerBlock>,
                blobs: ContiguousList<ByteVector<U131072>, MaxBlobCommitmentsPerBlock>,
            }

            pub(super) fn slot(contents: &BeaconBlockContentsElectra) -> u64 { contents.block.slot }
            pub(super) fn proposer_index(contents: &BeaconBlockContentsElectra) -> u64 { contents.block.proposer_index }
            pub(super) fn parent_root_hex(contents: &BeaconBlockContentsElectra) -> String {
                let bytes = contents.block.parent_root.to_ssz().unwrap_or_default();
                format!("0x{}", hex::encode(bytes))
            }
            pub(super) fn state_root_hex(contents: &BeaconBlockContentsElectra) -> String {
                let bytes = contents.block.state_root.to_ssz().unwrap_or_default();
                format!("0x{}", hex::encode(bytes))
            }
            pub(super) fn hash_tree_root_hex(contents: &BeaconBlockContentsElectra) -> String {
                format!("0x{}", hex::encode(contents.block.hash_tree_root().as_bytes()))
            }
            pub(super) fn body_root_hex(contents: &BeaconBlockContentsElectra) -> String {
                format!("0x{}", hex::encode(contents.block.body.hash_tree_root().as_bytes()))
            }
            pub(super) fn encode(contents: &BeaconBlockContentsElectra) -> Result<Vec<u8>, ssz_grandine::WriteError> {
                contents.to_ssz()
            }
            pub(super) fn sign_block(
                block: BeaconBlockElectra,
                signature: ByteVector<U96>,
            ) -> SignedBeaconBlockElectra {
                SignedBeaconBlockElectra { message: block, signature }
            }
            pub(super) fn encode_signed_block(
                block: &SignedBeaconBlockElectra,
            ) -> Result<Vec<u8>, ssz_grandine::WriteError> {
                block.to_ssz()
            }
            pub(super) fn block_from_contents(contents: BeaconBlockContentsElectra) -> BeaconBlockElectra {
                contents.block
            }

            pub(super) fn sign_block_contents(
                contents: BeaconBlockContentsElectra,
                signature: ByteVector<U96>,
            ) -> SignedBeaconBlockContentsElectra {
                SignedBeaconBlockContentsElectra {
                    signed_block: SignedBeaconBlockElectra {
                        message: contents.block,
                        signature,
                    },
                    kzg_proofs: contents.kzg_proofs,
                    blobs: contents.blobs,
                }
            }

            pub(super) fn encode_signed_block_contents(
                contents: &SignedBeaconBlockContentsElectra,
            ) -> Result<Vec<u8>, ssz_grandine::WriteError> {
                contents.to_ssz()
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

fn normalize_json_decimal_strings(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for v in map.values_mut() {
                normalize_json_decimal_strings(v);
            }
        }
        serde_json::Value::Array(items) => {
            for v in items {
                normalize_json_decimal_strings(v);
            }
        }
        serde_json::Value::String(s) => {
            if s.as_bytes().iter().all(u8::is_ascii_digit) {
                if let Ok(parsed) = s.parse::<u64>() {
                    *value = serde_json::Value::Number(parsed.into());
                }
            }
        }
        _ => {}
    }
}

fn decode_json_with_rust<T: DeserializeOwned>(json_bytes: &[u8], class_name: &str) -> PyResult<T> {
    let mut value: serde_json::Value = serde_json::from_slice(json_bytes)
        .map_err(|e| PyValueError::new_err(format!("Invalid JSON payload for {class_name}: {e}")))?;
    normalize_json_decimal_strings(&mut value);
    serde_json::from_value::<T>(value).map_err(|e| {
        PyValueError::new_err(format!(
            "Failed to decode {class_name} from JSON with Grandine Rust deserializer: {e}"
        ))
    })
}

static ACTIVE_PRESET: RwLock<Option<Preset>> = RwLock::new(None);


enum BeaconBlockContentsElectraVariant {
    Mainnet(mainnet::BeaconBlockContentsElectra),
    Gnosis(gnosis::BeaconBlockContentsElectra),
    Minimal(minimal::BeaconBlockContentsElectra),
}

#[pyclass]
struct BeaconBlockContentsElectra {
    inner: BeaconBlockContentsElectraVariant,
}

#[pymethods]
impl BeaconBlockContentsElectra {
    #[staticmethod]
    #[pyo3(signature=(ssz_bytes))]
    fn from_ssz(ssz_bytes: Vec<u8>) -> PyResult<Self> {
        let p = get_active_preset()?;
        let inner = match p {
            Preset::Mainnet => BeaconBlockContentsElectraVariant::Mainnet(
                mainnet::decode_block_contents(&ssz_bytes)
                    .map_err(|e| PyValueError::new_err(format!("Failed to decode BeaconBlockContentsElectra: {e:?}")))?,
            ),
            Preset::Gnosis => BeaconBlockContentsElectraVariant::Gnosis(
                gnosis::decode_block_contents(&ssz_bytes)
                    .map_err(|e| PyValueError::new_err(format!("Failed to decode BeaconBlockContentsElectra: {e:?}")))?,
            ),
            Preset::Minimal => BeaconBlockContentsElectraVariant::Minimal(
                minimal::decode_block_contents(&ssz_bytes)
                    .map_err(|e| PyValueError::new_err(format!("Failed to decode BeaconBlockContentsElectra: {e:?}")))?,
            ),
        };
        Ok(Self { inner })
    }

    #[staticmethod]
    #[pyo3(signature=(json_bytes))]
    fn from_json(json_bytes: &[u8]) -> PyResult<Self> {
        let p = get_active_preset()?;
        let inner = match p {
            Preset::Mainnet => BeaconBlockContentsElectraVariant::Mainnet(
                decode_json_with_rust::<mainnet::BeaconBlockContentsElectra>(json_bytes, "ElectraBlock")?,
            ),
            Preset::Gnosis => BeaconBlockContentsElectraVariant::Gnosis(
                decode_json_with_rust::<gnosis::BeaconBlockContentsElectra>(json_bytes, "ElectraBlock")?,
            ),
            Preset::Minimal => BeaconBlockContentsElectraVariant::Minimal(
                decode_json_with_rust::<minimal::BeaconBlockContentsElectra>(json_bytes, "ElectraBlock")?,
            ),
        };
        Ok(Self { inner })
    }

    fn slot(&self) -> u64 {
        match &self.inner {
            BeaconBlockContentsElectraVariant::Mainnet(b) => mainnet::slot(b),
            BeaconBlockContentsElectraVariant::Gnosis(b) => gnosis::slot(b),
            BeaconBlockContentsElectraVariant::Minimal(b) => minimal::slot(b),
        }
    }

    fn proposer_index(&self) -> u64 {
        match &self.inner {
            BeaconBlockContentsElectraVariant::Mainnet(b) => mainnet::proposer_index(b),
            BeaconBlockContentsElectraVariant::Gnosis(b) => gnosis::proposer_index(b),
            BeaconBlockContentsElectraVariant::Minimal(b) => minimal::proposer_index(b),
        }
    }

    fn parent_root_hex(&self) -> String {
        match &self.inner {
            BeaconBlockContentsElectraVariant::Mainnet(b) => mainnet::parent_root_hex(b),
            BeaconBlockContentsElectraVariant::Gnosis(b) => gnosis::parent_root_hex(b),
            BeaconBlockContentsElectraVariant::Minimal(b) => minimal::parent_root_hex(b),
        }
    }

    fn state_root_hex(&self) -> String {
        match &self.inner {
            BeaconBlockContentsElectraVariant::Mainnet(b) => mainnet::state_root_hex(b),
            BeaconBlockContentsElectraVariant::Gnosis(b) => gnosis::state_root_hex(b),
            BeaconBlockContentsElectraVariant::Minimal(b) => minimal::state_root_hex(b),
        }
    }

    fn hash_tree_root_hex(&self) -> String {
        match &self.inner {
            BeaconBlockContentsElectraVariant::Mainnet(b) => mainnet::hash_tree_root_hex(b),
            BeaconBlockContentsElectraVariant::Gnosis(b) => gnosis::hash_tree_root_hex(b),
            BeaconBlockContentsElectraVariant::Minimal(b) => minimal::hash_tree_root_hex(b),
        }
    }

    fn body_root_hex(&self) -> String {
        match &self.inner {
            BeaconBlockContentsElectraVariant::Mainnet(b) => mainnet::body_root_hex(b),
            BeaconBlockContentsElectraVariant::Gnosis(b) => gnosis::body_root_hex(b),
            BeaconBlockContentsElectraVariant::Minimal(b) => minimal::body_root_hex(b),
        }
    }

    fn encode_ssz_bytes(&self) -> PyResult<Vec<u8>> {
        match &self.inner {
            BeaconBlockContentsElectraVariant::Mainnet(b) => mainnet::encode(b),
            BeaconBlockContentsElectraVariant::Gnosis(b) => gnosis::encode(b),
            BeaconBlockContentsElectraVariant::Minimal(b) => minimal::encode(b),
        }
        .map_err(|e| PyValueError::new_err(format!("Failed to encode BeaconBlockContentsElectra: {e:?}")))
    }

    #[pyo3(name = "get_signed_block_contents_ssz")]
    fn signed_block_contents_ssz(&self, signature: &str) -> PyResult<Vec<u8>> {
        let signature_clean = signature.trim_start_matches("0x");
        let signature_bytes = hex::decode(signature_clean)
            .map_err(|e| PyValueError::new_err(format!("Invalid signature hex: {e}")))?;

        match &self.inner {
            BeaconBlockContentsElectraVariant::Mainnet(contents) => {
                let signature = ByteVector::<U96>::from_ssz_default(&signature_bytes)
                    .map_err(|e| PyValueError::new_err(format!("Invalid signature bytes: {e:?}")))?;
                let signed = mainnet::sign_block_contents(contents.clone(), signature);
                mainnet::encode_signed_block_contents(&signed)
                    .map_err(|e| PyValueError::new_err(format!("Failed to encode SignedBeaconBlockContentsElectra: {e:?}")))
            }
            BeaconBlockContentsElectraVariant::Gnosis(contents) => {
                let signature = ByteVector::<U96>::from_ssz_default(&signature_bytes)
                    .map_err(|e| PyValueError::new_err(format!("Invalid signature bytes: {e:?}")))?;
                let signed = gnosis::sign_block_contents(contents.clone(), signature);
                gnosis::encode_signed_block_contents(&signed)
                    .map_err(|e| PyValueError::new_err(format!("Failed to encode SignedBeaconBlockContentsElectra: {e:?}")))
            }
            BeaconBlockContentsElectraVariant::Minimal(contents) => {
                let signature = ByteVector::<U96>::from_ssz_default(&signature_bytes)
                    .map_err(|e| PyValueError::new_err(format!("Invalid signature bytes: {e:?}")))?;
                let signed = minimal::sign_block_contents(contents.clone(), signature);
                minimal::encode_signed_block_contents(&signed)
                    .map_err(|e| PyValueError::new_err(format!("Failed to encode SignedBeaconBlockContentsElectra: {e:?}")))
            }
        }
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

}

fn get_active_preset() -> PyResult<Preset> {
    let guard = ACTIVE_PRESET
        .read()
        .map_err(|_| PyValueError::new_err("Failed to read active preset"))?;
    guard.ok_or_else(|| {
        PyValueError::new_err(
            "Active preset not initialized. Call initialize_rust_lib(preset) once at startup.",
        )
    })
}

#[pyfunction]
fn initialize_rust_lib(preset: &str) -> PyResult<()> {
    let parsed = Preset::parse(preset)?;
    let mut guard = ACTIVE_PRESET
        .write()
        .map_err(|_| PyValueError::new_err("Failed to set active preset"))?;
    *guard = Some(parsed);
    Ok(())
}

#[pyfunction]
fn active_preset() -> PyResult<Option<String>> {
    let guard = ACTIVE_PRESET
        .read()
        .map_err(|_| PyValueError::new_err("Failed to read active preset"))?;
    Ok((*guard).map(|p| p.as_str().to_string()))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<BeaconBlockContentsElectra>()?;
    m.add_class::<GrandineSszContext>()?;
    m.add_function(wrap_pyfunction!(initialize_rust_lib, m)?)?;
    Ok(())
}
