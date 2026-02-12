use pyo3::prelude::*;

mod attestation;
mod block;
mod preset;
mod shared_containers;

#[pymodule]
fn vero_ssz_grandine_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    block::register(m)?;
    attestation::register(m)?;
    Ok(())
}
