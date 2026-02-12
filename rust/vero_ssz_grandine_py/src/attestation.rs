use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use ssz_grandine::{ByteVector, Ssz, SszHash, SszReadDefault};
use typenum::U32;

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

fn parse_bytes32_hex(field: &str, value: &serde_json::Value) -> PyResult<ByteVector<U32>> {
    let s = json_get_str(value, field)?;
    let raw = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(raw)
        .map_err(|e| PyValueError::new_err(format!("Invalid hex for {field}: {e}")))?;
    ByteVector::<U32>::try_from(bytes.as_slice())
        .map_err(|e| PyValueError::new_err(format!("Invalid bytes32 for {field}: {e:?}")))
}

#[derive(Clone, Debug, Ssz)]
struct AttestationCheckpoint {
    epoch: u64,
    root: ByteVector<U32>,
}

#[derive(Clone, Debug, Ssz)]
struct AttestationDataSimple {
    slot: u64,
    index: u64,
    beacon_block_root: ByteVector<U32>,
    source: AttestationCheckpoint,
    target: AttestationCheckpoint,
}

#[pyclass]
struct RustAttestationDataFromResponseJson {
    inner: AttestationDataSimple,
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
            inner: AttestationDataSimple {
                slot: parse_u64_dec("slot", data)?,
                index: parse_u64_dec("index", data)?,
                beacon_block_root: parse_bytes32_hex("beacon_block_root", data)?,
                source: AttestationCheckpoint {
                    epoch: parse_u64_dec("epoch", source)?,
                    root: parse_bytes32_hex("root", source)?,
                },
                target: AttestationCheckpoint {
                    epoch: parse_u64_dec("epoch", target)?,
                    root: parse_bytes32_hex("root", target)?,
                },
            },
        })
    }

    fn hash_tree_root(&self) -> PyResult<Vec<u8>> {
        Ok(self.inner.hash_tree_root().as_bytes().to_vec())
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
fn attestation_data_hash_tree_root_from_ssz(ssz_bytes: Vec<u8>) -> PyResult<Vec<u8>> {
    let att = AttestationDataSimple::from_ssz_default(&ssz_bytes)
        .map_err(|e| PyValueError::new_err(format!("Failed to decode AttestationData SSZ bytes: {e:?}")))?;
    Ok(att.hash_tree_root().as_bytes().to_vec())
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<RustAttestationDataFromResponseJson>()?;
    m.add_function(wrap_pyfunction!(attestation_data_hash_tree_root_from_response_json, m)?)?;
    m.add_function(wrap_pyfunction!(attestation_data_hash_tree_root_from_ssz, m)?)?;
    Ok(())
}
