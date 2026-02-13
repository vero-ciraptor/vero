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

            pub(super) fn decode_block_contents(ssz_bytes: &[u8]) -> Result<BeaconBlockContentsElectra, ssz_grandine::ReadError> {
                BeaconBlockContentsElectra::from_ssz_default(ssz_bytes)
            }

            pub(super) fn slot(block: &BeaconBlockElectra) -> u64 { block.slot }
            pub(super) fn proposer_index(block: &BeaconBlockElectra) -> u64 { block.proposer_index }
            pub(super) fn parent_root_hex(block: &BeaconBlockElectra) -> String {
                let bytes = block.parent_root.to_ssz().unwrap_or_default();
                format!("0x{}", hex::encode(bytes))
            }
            pub(super) fn state_root_hex(block: &BeaconBlockElectra) -> String {
                let bytes = block.state_root.to_ssz().unwrap_or_default();
                format!("0x{}", hex::encode(bytes))
            }
            pub(super) fn hash_tree_root_hex(block: &BeaconBlockElectra) -> String {
                format!("0x{}", hex::encode(block.hash_tree_root().as_bytes()))
            }
            pub(super) fn body_root_hex(block: &BeaconBlockElectra) -> String {
                format!("0x{}", hex::encode(block.body.hash_tree_root().as_bytes()))
            }
            pub(super) fn encode(block: &BeaconBlockElectra) -> Result<Vec<u8>, ssz_grandine::WriteError> {
                block.to_ssz()
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

    #[staticmethod]
    #[pyo3(signature=(json_bytes, preset="mainnet"))]
    fn from_json_bytes(json_bytes: &[u8], preset: &str) -> PyResult<Self> {
        let p = Preset::parse(preset)?;
        let inner = match p {
            Preset::Mainnet => GrandineBlockVariant::Mainnet(
                decode_json_with_rust::<mainnet::BeaconBlockElectra>(json_bytes, "ElectraBlock")?,
            ),
            Preset::Gnosis => GrandineBlockVariant::Gnosis(
                decode_json_with_rust::<gnosis::BeaconBlockElectra>(json_bytes, "ElectraBlock")?,
            ),
            Preset::Minimal => GrandineBlockVariant::Minimal(
                decode_json_with_rust::<minimal::BeaconBlockElectra>(json_bytes, "ElectraBlock")?,
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

    fn proposer_index(&self) -> u64 {
        match &self.inner {
            GrandineBlockVariant::Mainnet(b) => mainnet::proposer_index(b),
            GrandineBlockVariant::Gnosis(b) => gnosis::proposer_index(b),
            GrandineBlockVariant::Minimal(b) => minimal::proposer_index(b),
        }
    }

    fn parent_root_hex(&self) -> String {
        match &self.inner {
            GrandineBlockVariant::Mainnet(b) => mainnet::parent_root_hex(b),
            GrandineBlockVariant::Gnosis(b) => gnosis::parent_root_hex(b),
            GrandineBlockVariant::Minimal(b) => minimal::parent_root_hex(b),
        }
    }

    fn state_root_hex(&self) -> String {
        match &self.inner {
            GrandineBlockVariant::Mainnet(b) => mainnet::state_root_hex(b),
            GrandineBlockVariant::Gnosis(b) => gnosis::state_root_hex(b),
            GrandineBlockVariant::Minimal(b) => minimal::state_root_hex(b),
        }
    }

    fn hash_tree_root_hex(&self) -> String {
        match &self.inner {
            GrandineBlockVariant::Mainnet(b) => mainnet::hash_tree_root_hex(b),
            GrandineBlockVariant::Gnosis(b) => gnosis::hash_tree_root_hex(b),
            GrandineBlockVariant::Minimal(b) => minimal::hash_tree_root_hex(b),
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

    fn beacon_block_from_contents_json_bytes(
        &self,
        json_bytes: &[u8],
    ) -> PyResult<GrandineBeaconBlockElectra> {
        match self.preset {
            Preset::Mainnet => Ok(GrandineBeaconBlockElectra {
                inner: GrandineBlockVariant::Mainnet(mainnet::block_from_contents(
                    decode_json_with_rust::<mainnet::BeaconBlockContentsElectra>(
                        json_bytes,
                        "ElectraBlockContents",
                    )?,
                )),
            }),
            Preset::Gnosis => Ok(GrandineBeaconBlockElectra {
                inner: GrandineBlockVariant::Gnosis(gnosis::block_from_contents(
                    decode_json_with_rust::<gnosis::BeaconBlockContentsElectra>(
                        json_bytes,
                        "ElectraBlockContents",
                    )?,
                )),
            }),
            Preset::Minimal => Ok(GrandineBeaconBlockElectra {
                inner: GrandineBlockVariant::Minimal(minimal::block_from_contents(
                    decode_json_with_rust::<minimal::BeaconBlockContentsElectra>(
                        json_bytes,
                        "ElectraBlockContents",
                    )?,
                )),
            }),
        }
    }
}

fn get_active_preset() -> PyResult<Preset> {
    let guard = ACTIVE_PRESET
        .read()
        .map_err(|_| PyValueError::new_err("Failed to read active preset"))?;
    guard.ok_or_else(|| {
        PyValueError::new_err(
            "Active preset not initialized. Call initialize_active_preset(preset) once at startup.",
        )
    })
}

#[pyfunction]
fn initialize_active_preset(preset: &str) -> PyResult<()> {
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
fn beacon_block_body_root_hex_from_ssz_active(ssz_bytes: Vec<u8>) -> PyResult<String> {
    let preset = get_active_preset()?;
    Ok(GrandineBeaconBlockElectra::from_ssz_bytes(ssz_bytes, preset.as_str())?.body_root_hex())
}

#[pyfunction]
fn beacon_block_from_contents_ssz_active(ssz_bytes: Vec<u8>) -> PyResult<GrandineBeaconBlockElectra> {
    let preset = get_active_preset()?;
    let inner = match preset {
        Preset::Mainnet => GrandineBlockVariant::Mainnet(
            mainnet::block_from_contents(
                mainnet::decode_block_contents(&ssz_bytes)
                    .map_err(|e| PyValueError::new_err(format!("Failed to decode BeaconBlockContentsElectra: {e:?}")))?,
            ),
        ),
        Preset::Gnosis => GrandineBlockVariant::Gnosis(
            gnosis::block_from_contents(
                gnosis::decode_block_contents(&ssz_bytes)
                    .map_err(|e| PyValueError::new_err(format!("Failed to decode BeaconBlockContentsElectra: {e:?}")))?,
            ),
        ),
        Preset::Minimal => GrandineBlockVariant::Minimal(
            minimal::block_from_contents(
                minimal::decode_block_contents(&ssz_bytes)
                    .map_err(|e| PyValueError::new_err(format!("Failed to decode BeaconBlockContentsElectra: {e:?}")))?,
            ),
        ),
    };
    Ok(GrandineBeaconBlockElectra { inner })
}

#[pyfunction]
fn beacon_block_from_contents_json_active(json_bytes: &[u8]) -> PyResult<GrandineBeaconBlockElectra> {
    let preset = get_active_preset()?;
    GrandineSszContext { preset }.beacon_block_from_contents_json_bytes(json_bytes)
}

fn parse_signature_bytes(signature: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if let Ok(signature_hex) = signature.extract::<String>() {
        let signature_clean = signature_hex.trim_start_matches("0x");
        return hex::decode(signature_clean)
            .map_err(|e| PyValueError::new_err(format!("Invalid signature hex: {e}")));
    }

    if let Ok(signature_bytes) = signature.extract::<Vec<u8>>() {
        return Ok(signature_bytes);
    }

    Err(PyValueError::new_err(
        "signature must be hex string (0x...) or 96-byte bytes-like",
    ))
}

#[pyfunction]
fn sign_block_contents_ssz_active(
    ssz_bytes: Vec<u8>,
    signature: &Bound<'_, PyAny>,
) -> PyResult<Vec<u8>> {
    let signature_bytes = parse_signature_bytes(signature)?;
    let preset = get_active_preset()?;
    match preset {
        Preset::Mainnet => {
            let signature = ByteVector::<U96>::from_ssz_default(&signature_bytes)
                .map_err(|e| PyValueError::new_err(format!("Invalid signature bytes: {e:?}")))?;
            let contents = mainnet::decode_block_contents(&ssz_bytes)
                .map_err(|e| PyValueError::new_err(format!("Failed to decode BeaconBlockContentsElectra: {e:?}")))?;
            let signed = mainnet::sign_block_contents(contents, signature);
            mainnet::encode_signed_block_contents(&signed)
                .map_err(|e| PyValueError::new_err(format!("Failed to encode SignedBeaconBlockContentsElectra: {e:?}")))
        }
        Preset::Gnosis => {
            let signature = ByteVector::<U96>::from_ssz_default(&signature_bytes)
                .map_err(|e| PyValueError::new_err(format!("Invalid signature bytes: {e:?}")))?;
            let contents = gnosis::decode_block_contents(&ssz_bytes)
                .map_err(|e| PyValueError::new_err(format!("Failed to decode BeaconBlockContentsElectra: {e:?}")))?;
            let signed = gnosis::sign_block_contents(contents, signature);
            gnosis::encode_signed_block_contents(&signed)
                .map_err(|e| PyValueError::new_err(format!("Failed to encode SignedBeaconBlockContentsElectra: {e:?}")))
        }
        Preset::Minimal => {
            let signature = ByteVector::<U96>::from_ssz_default(&signature_bytes)
                .map_err(|e| PyValueError::new_err(format!("Invalid signature bytes: {e:?}")))?;
            let contents = minimal::decode_block_contents(&ssz_bytes)
                .map_err(|e| PyValueError::new_err(format!("Failed to decode BeaconBlockContentsElectra: {e:?}")))?;
            let signed = minimal::sign_block_contents(contents, signature);
            minimal::encode_signed_block_contents(&signed)
                .map_err(|e| PyValueError::new_err(format!("Failed to encode SignedBeaconBlockContentsElectra: {e:?}")))
        }
    }
}

#[pyfunction]
#[pyo3(signature=(ssz_bytes, preset="mainnet"))]
fn beacon_block_reencode_from_ssz(ssz_bytes: Vec<u8>, preset: &str) -> PyResult<Vec<u8>> {
    GrandineBeaconBlockElectra::from_ssz_bytes(ssz_bytes, preset)?.encode_ssz_bytes()
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<GrandineBeaconBlockElectra>()?;
    m.add_class::<GrandineSszContext>()?;
    m.add_function(wrap_pyfunction!(initialize_active_preset, m)?)?;
    m.add_function(wrap_pyfunction!(active_preset, m)?)?;
    m.add_function(wrap_pyfunction!(beacon_block_decode_slot_from_ssz, m)?)?;
    m.add_function(wrap_pyfunction!(beacon_block_body_root_hex_from_ssz, m)?)?;
    m.add_function(wrap_pyfunction!(beacon_block_body_root_hex_from_ssz_active, m)?)?;
    m.add_function(wrap_pyfunction!(beacon_block_from_contents_ssz_active, m)?)?;
    m.add_function(wrap_pyfunction!(beacon_block_from_contents_json_active, m)?)?;
    m.add_function(wrap_pyfunction!(sign_block_contents_ssz_active, m)?)?;
    m.add_function(wrap_pyfunction!(beacon_block_reencode_from_ssz, m)?)?;
    Ok(())
}
