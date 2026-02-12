use pyo3::prelude::*;

mod attestation;
mod block;
mod preset;

#[pymodule]
fn vero_ssz_grandine_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    block::register(m)?;
    attestation::register(m)?;
    Ok(())
}
