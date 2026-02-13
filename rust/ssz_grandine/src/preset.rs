use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[derive(Clone, Copy)]
pub enum Preset {
    Mainnet,
    Gnosis,
    Minimal,
}

impl Preset {
    pub fn parse(preset: &str) -> PyResult<Self> {
        match preset.to_ascii_lowercase().as_str() {
            "mainnet" => Ok(Self::Mainnet),
            "gnosis" => Ok(Self::Gnosis),
            "minimal" => Ok(Self::Minimal),
            _ => Err(PyValueError::new_err(
                "Unsupported preset. Expected one of: mainnet, gnosis, minimal",
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Gnosis => "gnosis",
            Self::Minimal => "minimal",
        }
    }
}
