use pyo3::prelude::*;

mod block;
mod preset;
mod shared_containers;

#[pymodule]
fn ssz_grandine(m: &Bound<'_, PyModule>) -> PyResult<()> {
    block::register(m)?;
    Ok(())
}
