#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid CIDR")]
    InvalidCidr,
    #[error("invalid storage limit")]
    InvalidStorageLimit,
    #[error("host address inventory is empty")]
    EmptyHostInventory,
    #[error("network policy evidence does not match")]
    PolicyMismatch,
    #[error("negative probe allowed a forbidden connection")]
    ProbeAllowedForbidden,
    #[error("network probe was inconclusive")]
    ProbeInconclusive,
    #[error("network probe I/O error")]
    Io,
}
