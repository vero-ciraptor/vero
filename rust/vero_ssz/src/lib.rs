use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use ssz_rs::prelude::*;

const DEPOSIT_CONTRACT_TREE_DEPTH_PLUS_ONE: usize = 33;

fn to_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn json_get_str<'a>(value: &'a serde_json::Value, key: &str) -> PyResult<&'a str> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| PyValueError::new_err(format!("Missing/invalid string field: {key}")))
}

fn parse_u64_dec(field: &str, value: &serde_json::Value) -> PyResult<u64> {
    json_get_str(value, field)?
        .parse::<u64>()
        .map_err(|e| PyValueError::new_err(format!("Invalid decimal for {field}: {e}")))
}

fn parse_bytes32_hex(field: &str, value: &serde_json::Value) -> PyResult<Vector<u8, 32>> {
    let s = json_get_str(value, field)?;
    let raw = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(raw)
        .map_err(|e| PyValueError::new_err(format!("Invalid hex for {field}: {e}")))?;
    if bytes.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "Invalid length for {field}: expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    Vector::<u8, 32>::try_from(bytes)
        .map_err(|e| PyValueError::new_err(format!("Failed bytes32 conversion for {field}: {e:?}")))
}

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
            _ => Err(PyValueError::new_err(format!(
                "Unsupported preset '{preset}'. Expected one of: mainnet, gnosis, minimal"
            ))),
        }
    }
}

macro_rules! define_preset_module {
    (
        $mod_name:ident,
        $sync_committee_size:expr,
        $max_committees_per_slot:expr,
        $max_validators_per_committee:expr,
        $max_proposer_slashings:expr,
        $max_attester_slashings_electra:expr,
        $max_attestations_electra:expr,
        $max_deposits:expr,
        $max_voluntary_exits:expr,
        $max_bls_to_execution_changes:expr,
        $max_withdrawals_per_payload:expr,
        $max_blob_commitments_per_block:expr,
        $max_deposit_requests_per_payload:expr,
        $max_withdrawal_requests_per_payload:expr,
        $max_consolidation_requests_per_payload:expr,
        $max_bytes_per_transaction:expr,
        $max_transactions_per_payload:expr,
        $bytes_per_logs_bloom:expr,
        $max_extra_data_bytes:expr
    ) => {
        mod $mod_name {
            use super::*;

            const SYNC_COMMITTEE_SIZE: usize = $sync_committee_size;
            const MAX_COMMITTEES_PER_SLOT: usize = $max_committees_per_slot;
            const MAX_VALIDATORS_PER_COMMITTEE: usize = $max_validators_per_committee;
            const MAX_PROPOSER_SLASHINGS: usize = $max_proposer_slashings;
            const MAX_ATTESTER_SLASHINGS_ELECTRA: usize = $max_attester_slashings_electra;
            const MAX_ATTESTATIONS_ELECTRA: usize = $max_attestations_electra;
            const MAX_DEPOSITS: usize = $max_deposits;
            const MAX_VOLUNTARY_EXITS: usize = $max_voluntary_exits;
            const MAX_BLS_TO_EXECUTION_CHANGES: usize = $max_bls_to_execution_changes;
            const MAX_WITHDRAWALS_PER_PAYLOAD: usize = $max_withdrawals_per_payload;
            const MAX_BLOB_COMMITMENTS_PER_BLOCK: usize = $max_blob_commitments_per_block;
            const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: usize = $max_deposit_requests_per_payload;
            const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: usize = $max_withdrawal_requests_per_payload;
            const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: usize = $max_consolidation_requests_per_payload;
            const MAX_BYTES_PER_TRANSACTION: usize = $max_bytes_per_transaction;
            const MAX_TRANSACTIONS_PER_PAYLOAD: usize = $max_transactions_per_payload;
            const BYTES_PER_LOGS_BLOOM: usize = $bytes_per_logs_bloom;
            const MAX_EXTRA_DATA_BYTES: usize = $max_extra_data_bytes;
            const MAX_ATTESTING_INDICES: usize = MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT;

            type Bytes32 = Vector<u8, 32>;
            type Bytes48 = Vector<u8, 48>;
            type Bytes96 = Vector<u8, 96>;
            type ExecutionAddress = Vector<u8, 20>;
            type U256Bytes = Vector<u8, 32>;
            type Transaction = List<u8, MAX_BYTES_PER_TRANSACTION>;
            type CommitteeBits = Bitvector<MAX_COMMITTEES_PER_SLOT>;
            type AggregationBits = Bitlist<MAX_ATTESTING_INDICES>;

            #[derive(Debug, Default, SimpleSerialize)]
            struct Checkpoint {
                epoch: u64,
                root: Bytes32,
            }

            #[derive(Debug, Default, SimpleSerialize)]
            struct AttestationData {
                slot: u64,
                index: u64,
                beacon_block_root: Bytes32,
                source: Checkpoint,
                target: Checkpoint,
            }

            #[derive(Debug, Default, SimpleSerialize)]
            struct AttestationElectra {
                aggregation_bits: AggregationBits,
                data: AttestationData,
                signature: Bytes96,
                committee_bits: CommitteeBits,
            }

            #[derive(Debug, Default, SimpleSerialize)]
            struct IndexedAttestationElectra {
                attesting_indices: List<u64, MAX_ATTESTING_INDICES>,
                data: AttestationData,
                signature: Bytes96,
            }

            #[derive(Debug, Default, SimpleSerialize)]
            struct AttesterSlashingElectra {
                attestation_1: IndexedAttestationElectra,
                attestation_2: IndexedAttestationElectra,
            }

            #[derive(Debug, Default, SimpleSerialize)]
            struct Eth1Data {
                deposit_root: Bytes32,
                deposit_count: u64,
                block_hash: Bytes32,
            }

            #[derive(Debug, Default, SimpleSerialize)]
            struct DepositData {
                pubkey: Bytes48,
                withdrawal_credentials: Bytes32,
                amount: u64,
                signature: Bytes96,
            }

            #[derive(Debug, Default, SimpleSerialize)]
            struct Deposit {
                proof: Vector<Bytes32, DEPOSIT_CONTRACT_TREE_DEPTH_PLUS_ONE>,
                data: DepositData,
            }

            #[derive(Debug, Default, SimpleSerialize)]
            struct BeaconBlockHeader {
                slot: u64,
                proposer_index: u64,
                parent_root: Bytes32,
                state_root: Bytes32,
                body_root: Bytes32,
            }

            #[derive(Debug, Default, SimpleSerialize)]
            struct SignedBeaconBlockHeader {
                message: BeaconBlockHeader,
                signature: Bytes96,
            }

            #[derive(Debug, Default, SimpleSerialize)]
            struct ProposerSlashing {
                signed_header_1: SignedBeaconBlockHeader,
                signed_header_2: SignedBeaconBlockHeader,
            }

            #[derive(Debug, Default, SimpleSerialize)]
            struct VoluntaryExit {
                epoch: u64,
                validator_index: u64,
            }

            #[derive(Debug, Default, SimpleSerialize)]
            struct SignedVoluntaryExit {
                message: VoluntaryExit,
                signature: Bytes96,
            }

            #[derive(Debug, Default, SimpleSerialize)]
            struct SyncAggregate {
                sync_committee_bits: Bitvector<SYNC_COMMITTEE_SIZE>,
                sync_committee_signature: Bytes96,
            }

            #[derive(Debug, Default, SimpleSerialize)]
            struct Withdrawal {
                index: u64,
                validator_index: u64,
                address: ExecutionAddress,
                amount: u64,
            }

            #[derive(Debug, Default, SimpleSerialize)]
            struct ExecutionPayloadV3 {
                parent_hash: Bytes32,
                fee_recipient: ExecutionAddress,
                state_root: Bytes32,
                receipts_root: Bytes32,
                logs_bloom: Vector<u8, BYTES_PER_LOGS_BLOOM>,
                prev_randao: Bytes32,
                block_number: u64,
                gas_limit: u64,
                gas_used: u64,
                timestamp: u64,
                extra_data: List<u8, MAX_EXTRA_DATA_BYTES>,
                base_fee_per_gas: U256Bytes,
                block_hash: Bytes32,
                transactions: List<Transaction, MAX_TRANSACTIONS_PER_PAYLOAD>,
                withdrawals: List<Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD>,
                blob_gas_used: u64,
                excess_blob_gas: u64,
            }

            #[derive(Debug, Default, SimpleSerialize)]
            struct BlsToExecutionChange {
                validator_index: u64,
                from_bls_pubkey: Bytes48,
                to_execution_address: ExecutionAddress,
            }

            #[derive(Debug, Default, SimpleSerialize)]
            struct SignedBlsToExecutionChange {
                message: BlsToExecutionChange,
                signature: Bytes96,
            }

            #[derive(Debug, Default, SimpleSerialize)]
            struct DepositRequest {
                pubkey: Bytes48,
                withdrawal_credentials: Bytes32,
                amount: u64,
                signature: Bytes96,
                index: u64,
            }

            #[derive(Debug, Default, SimpleSerialize)]
            struct WithdrawalRequest {
                source_address: ExecutionAddress,
                validator_pubkey: Bytes48,
                amount: u64,
            }

            #[derive(Debug, Default, SimpleSerialize)]
            struct ConsolidationRequest {
                source_address: ExecutionAddress,
                source_pubkey: Bytes48,
                target_pubkey: Bytes48,
            }

            #[derive(Debug, Default, SimpleSerialize)]
            struct ExecutionRequests {
                deposits: List<DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD>,
                withdrawals: List<WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD>,
                consolidations: List<ConsolidationRequest, MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD>,
            }

            #[derive(Debug, Default, SimpleSerialize)]
            struct BeaconBlockBodyElectra {
                randao_reveal: Bytes96,
                eth1_data: Eth1Data,
                graffiti: Bytes32,
                proposer_slashings: List<ProposerSlashing, MAX_PROPOSER_SLASHINGS>,
                attester_slashings: List<AttesterSlashingElectra, MAX_ATTESTER_SLASHINGS_ELECTRA>,
                attestations: List<AttestationElectra, MAX_ATTESTATIONS_ELECTRA>,
                deposits: List<Deposit, MAX_DEPOSITS>,
                voluntary_exits: List<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>,
                sync_aggregate: SyncAggregate,
                execution_payload: ExecutionPayloadV3,
                bls_to_execution_changes: List<SignedBlsToExecutionChange, MAX_BLS_TO_EXECUTION_CHANGES>,
                blob_kzg_commitments: List<Bytes48, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
                execution_requests: ExecutionRequests,
            }

            #[derive(Debug, Default, SimpleSerialize)]
            pub(super) struct BeaconBlockElectra {
                slot: u64,
                proposer_index: u64,
                parent_root: Bytes32,
                state_root: Bytes32,
                body: BeaconBlockBodyElectra,
            }

            pub(super) fn decode_beacon_block(ssz_bytes: &[u8]) -> Result<BeaconBlockElectra, ssz_rs::DeserializeError> {
                BeaconBlockElectra::deserialize(ssz_bytes)
            }

            pub(super) fn beacon_block_root(block: &mut BeaconBlockElectra) -> Result<Node, ssz_rs::MerkleizationError> {
                block.hash_tree_root()
            }

            pub(super) fn beacon_body_root(block: &mut BeaconBlockElectra) -> Result<Node, ssz_rs::MerkleizationError> {
                block.body.hash_tree_root()
            }

            pub(super) fn slot(block: &BeaconBlockElectra) -> u64 { block.slot }
            pub(super) fn proposer_index(block: &BeaconBlockElectra) -> u64 { block.proposer_index }
            pub(super) fn parent_root_hex(block: &BeaconBlockElectra) -> String { to_hex(block.parent_root.as_ref()) }
            pub(super) fn state_root_hex(block: &BeaconBlockElectra) -> String { to_hex(block.state_root.as_ref()) }
        }
    };
}

define_preset_module!(
    mainnet,
    512,
    64,
    2048,
    16,
    1,
    8,
    16,
    16,
    16,
    16,
    4096,
    8192,
    16,
    2,
    1_073_741_824,
    1_048_576,
    256,
    32
);

define_preset_module!(
    gnosis,
    512,
    64,
    2048,
    16,
    1,
    8,
    16,
    16,
    16,
    8,
    4096,
    8192,
    16,
    2,
    1_073_741_824,
    1_048_576,
    256,
    32
);

define_preset_module!(
    minimal,
    32,
    4,
    2048,
    16,
    1,
    8,
    16,
    16,
    16,
    4,
    32,
    4,
    2,
    2,
    1_073_741_824,
    1_048_576,
    256,
    32
);

enum BeaconBlockVariant {
    Mainnet(mainnet::BeaconBlockElectra),
    Gnosis(gnosis::BeaconBlockElectra),
    Minimal(minimal::BeaconBlockElectra),
}

#[pyclass]
struct RustBeaconBlockElectra {
    inner: BeaconBlockVariant,
}

#[pymethods]
impl RustBeaconBlockElectra {
    #[staticmethod]
    #[pyo3(signature=(ssz_bytes, preset="mainnet"))]
    fn from_ssz_bytes(ssz_bytes: Vec<u8>, preset: &str) -> PyResult<Self> {
        let p = Preset::parse(preset)?;
        let inner = match p {
            Preset::Mainnet => BeaconBlockVariant::Mainnet(
                mainnet::decode_beacon_block(&ssz_bytes).map_err(|e| {
                    PyValueError::new_err(format!("Failed to decode BeaconBlockElectra SSZ bytes: {e}"))
                })?,
            ),
            Preset::Gnosis => BeaconBlockVariant::Gnosis(
                gnosis::decode_beacon_block(&ssz_bytes).map_err(|e| {
                    PyValueError::new_err(format!("Failed to decode BeaconBlockElectra SSZ bytes: {e}"))
                })?,
            ),
            Preset::Minimal => BeaconBlockVariant::Minimal(
                minimal::decode_beacon_block(&ssz_bytes).map_err(|e| {
                    PyValueError::new_err(format!("Failed to decode BeaconBlockElectra SSZ bytes: {e}"))
                })?,
            ),
        };

        Ok(Self { inner })
    }

    fn slot(&self) -> u64 {
        match &self.inner {
            BeaconBlockVariant::Mainnet(b) => mainnet::slot(b),
            BeaconBlockVariant::Gnosis(b) => gnosis::slot(b),
            BeaconBlockVariant::Minimal(b) => minimal::slot(b),
        }
    }

    fn proposer_index(&self) -> u64 {
        match &self.inner {
            BeaconBlockVariant::Mainnet(b) => mainnet::proposer_index(b),
            BeaconBlockVariant::Gnosis(b) => gnosis::proposer_index(b),
            BeaconBlockVariant::Minimal(b) => minimal::proposer_index(b),
        }
    }

    fn parent_root_hex(&self) -> String {
        match &self.inner {
            BeaconBlockVariant::Mainnet(b) => mainnet::parent_root_hex(b),
            BeaconBlockVariant::Gnosis(b) => gnosis::parent_root_hex(b),
            BeaconBlockVariant::Minimal(b) => minimal::parent_root_hex(b),
        }
    }

    fn state_root_hex(&self) -> String {
        match &self.inner {
            BeaconBlockVariant::Mainnet(b) => mainnet::state_root_hex(b),
            BeaconBlockVariant::Gnosis(b) => gnosis::state_root_hex(b),
            BeaconBlockVariant::Minimal(b) => minimal::state_root_hex(b),
        }
    }

    fn body_root_hex(&mut self) -> PyResult<String> {
        let root = match &mut self.inner {
            BeaconBlockVariant::Mainnet(b) => mainnet::beacon_body_root(b),
            BeaconBlockVariant::Gnosis(b) => gnosis::beacon_body_root(b),
            BeaconBlockVariant::Minimal(b) => minimal::beacon_body_root(b),
        }
        .map_err(|e| PyValueError::new_err(format!("Failed to compute body root: {e}")))?;

        Ok(to_hex(root.as_ref()))
    }

    fn block_root_hex(&mut self) -> PyResult<String> {
        let root = match &mut self.inner {
            BeaconBlockVariant::Mainnet(b) => mainnet::beacon_block_root(b),
            BeaconBlockVariant::Gnosis(b) => gnosis::beacon_block_root(b),
            BeaconBlockVariant::Minimal(b) => minimal::beacon_block_root(b),
        }
        .map_err(|e| PyValueError::new_err(format!("Failed to compute block root: {e}")))?;

        Ok(to_hex(root.as_ref()))
    }

    fn to_header_dict(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let d = pyo3::types::PyDict::new_bound(py);
        d.set_item("slot", self.slot().to_string())?;
        d.set_item("proposer_index", self.proposer_index().to_string())?;
        d.set_item("parent_root", self.parent_root_hex())?;
        d.set_item("state_root", self.state_root_hex())?;
        d.set_item("body_root", self.body_root_hex()?)?;
        Ok(d.into())
    }

    fn encode_ssz_bytes(&self) -> PyResult<Vec<u8>> {
        let mut out = Vec::new();
        match &self.inner {
            BeaconBlockVariant::Mainnet(b) => b.serialize(&mut out),
            BeaconBlockVariant::Gnosis(b) => b.serialize(&mut out),
            BeaconBlockVariant::Minimal(b) => b.serialize(&mut out),
        }
        .map_err(|e| PyValueError::new_err(format!("Failed to encode BeaconBlockElectra: {e}")))?;

        Ok(out)
    }
}

#[pyclass]
struct RustSszContext {
    preset: Preset,
}

#[pymethods]
impl RustSszContext {
    #[staticmethod]
    fn from_preset(preset: &str) -> PyResult<Self> {
        Ok(Self {
            preset: Preset::parse(preset)?,
        })
    }

    fn preset(&self) -> &'static str {
        match self.preset {
            Preset::Mainnet => "mainnet",
            Preset::Gnosis => "gnosis",
            Preset::Minimal => "minimal",
        }
    }

    fn beacon_block_from_ssz_bytes(&self, ssz_bytes: Vec<u8>) -> PyResult<RustBeaconBlockElectra> {
        let preset = self.preset();
        RustBeaconBlockElectra::from_ssz_bytes(ssz_bytes, preset)
    }
}

#[pyfunction]
fn attestation_data_hash_tree_root_from_ssz(ssz_bytes: Vec<u8>) -> PyResult<Vec<u8>> {
    #[derive(Debug, Default, SimpleSerialize)]
    struct Checkpoint {
        epoch: u64,
        root: Vector<u8, 32>,
    }
    #[derive(Debug, Default, SimpleSerialize)]
    struct AttestationData {
        slot: u64,
        index: u64,
        beacon_block_root: Vector<u8, 32>,
        source: Checkpoint,
        target: Checkpoint,
    }

    let mut attestation_data = AttestationData::deserialize(&ssz_bytes).map_err(|e| {
        PyValueError::new_err(format!("Failed to decode AttestationData SSZ bytes: {e}"))
    })?;

    let root = attestation_data
        .hash_tree_root()
        .map_err(|e| PyValueError::new_err(format!("Failed to compute hash_tree_root: {e}")))?;

    Ok(root.as_ref().to_vec())
}

#[pyclass]
struct RustAttestationDataFromResponseJson {
    slot: u64,
    index: u64,
    beacon_block_root: Vector<u8, 32>,
    source_epoch: u64,
    source_root: Vector<u8, 32>,
    target_epoch: u64,
    target_root: Vector<u8, 32>,
}

#[pymethods]
impl RustAttestationDataFromResponseJson {
    #[staticmethod]
    fn from_response_json_bytes(json_bytes: &[u8]) -> PyResult<Self> {
        let parsed: serde_json::Value = serde_json::from_slice(json_bytes)
            .map_err(|e| PyValueError::new_err(format!("Invalid response JSON: {e}")))?;

        let data = parsed
            .get("data")
            .ok_or_else(|| PyValueError::new_err("Missing object field: data"))?;
        let source = data
            .get("source")
            .ok_or_else(|| PyValueError::new_err("Missing object field: data.source"))?;
        let target = data
            .get("target")
            .ok_or_else(|| PyValueError::new_err("Missing object field: data.target"))?;

        Ok(Self {
            slot: parse_u64_dec("slot", data)?,
            index: parse_u64_dec("index", data)?,
            beacon_block_root: parse_bytes32_hex("beacon_block_root", data)?,
            source_epoch: parse_u64_dec("epoch", source)?,
            source_root: parse_bytes32_hex("root", source)?,
            target_epoch: parse_u64_dec("epoch", target)?,
            target_root: parse_bytes32_hex("root", target)?,
        })
    }

    fn hash_tree_root(&self) -> PyResult<Vec<u8>> {
        #[derive(Debug, Default, SimpleSerialize)]
        struct Checkpoint {
            epoch: u64,
            root: Vector<u8, 32>,
        }
        #[derive(Debug, Default, SimpleSerialize)]
        struct AttestationData {
            slot: u64,
            index: u64,
            beacon_block_root: Vector<u8, 32>,
            source: Checkpoint,
            target: Checkpoint,
        }

        let mut att = AttestationData {
            slot: self.slot,
            index: self.index,
            beacon_block_root: self.beacon_block_root.clone(),
            source: Checkpoint {
                epoch: self.source_epoch,
                root: self.source_root.clone(),
            },
            target: Checkpoint {
                epoch: self.target_epoch,
                root: self.target_root.clone(),
            },
        };

        let root = att
            .hash_tree_root()
            .map_err(|e| PyValueError::new_err(format!("Failed to compute hash_tree_root: {e}")))?;
        Ok(root.as_ref().to_vec())
    }

    fn hash_tree_root_hex(&self) -> PyResult<String> {
        Ok(to_hex(&self.hash_tree_root()?))
    }
}

#[pyfunction]
fn attestation_data_hash_tree_root_from_response_json(json_bytes: &[u8]) -> PyResult<Vec<u8>> {
    RustAttestationDataFromResponseJson::from_response_json_bytes(json_bytes)?.hash_tree_root()
}

#[pyfunction]
#[pyo3(signature=(ssz_bytes, preset="mainnet"))]
fn beacon_block_electra_hash_tree_root_from_ssz(ssz_bytes: Vec<u8>, preset: &str) -> PyResult<Vec<u8>> {
    let mut block = RustBeaconBlockElectra::from_ssz_bytes(ssz_bytes, preset)?;
    let hex = block.block_root_hex()?;
    let raw = hex::decode(hex.trim_start_matches("0x"))
        .map_err(|e| PyValueError::new_err(format!("Failed to decode root hex: {e}")))?;
    Ok(raw)
}

#[pymodule]
fn vero_ssz(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<RustBeaconBlockElectra>()?;
    m.add_class::<RustSszContext>()?;
    m.add_class::<RustAttestationDataFromResponseJson>()?;
    m.add_function(wrap_pyfunction!(attestation_data_hash_tree_root_from_ssz, m)?)?;
    m.add_function(wrap_pyfunction!(attestation_data_hash_tree_root_from_response_json, m)?)?;
    m.add_function(wrap_pyfunction!(beacon_block_electra_hash_tree_root_from_ssz, m)?)?;
    Ok(())
}
