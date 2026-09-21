#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("capability descriptor does not match the attempt")]
    CapabilityMismatch,
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
    #[error("storage probe is unsupported for this mechanism")]
    UnsupportedStorageProbe,
    #[error("sandbox storage probe is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("storage bound or identity does not match")]
    StorageBoundMismatch,
    #[error("storage probe is inconclusive")]
    StorageProbeInconclusive,
}
