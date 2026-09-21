#[derive(thiserror::Error)]
pub enum PolicyError {
    #[error("capability descriptor does not match the attempt")]
    CapabilityMismatch,
    #[error("invalid CIDR")]
    InvalidCidr,
    #[error("invalid storage limit")]
    InvalidStorageLimit,
    #[error("missing sandbox policy: {0}")]
    MissingPolicy(&'static str),
    #[error("invalid sandbox policy service")]
    InvalidService,
    #[error("invalid sandbox policy observation: {0}")]
    InvalidObservation(&'static str),
    #[error("network policy evidence does not match")]
    PolicyMismatch,
    #[error("negative probe allowed a forbidden connection")]
    ProbeAllowedForbidden,
    #[error("network probe was inconclusive")]
    ProbeInconclusive,
    #[error("sandbox policy I/O error")]
    Io(std::io::Error),
    #[error("storage probe is unsupported for this mechanism")]
    UnsupportedStorageProbe,
    #[error("sandbox storage probe is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("sandbox storage is not bounded")]
    StorageUnbounded,
    #[error("sandbox storage identity changed")]
    StorageIdentityChanged,
    #[error("sandbox capability is unsupported")]
    UnsupportedCapability,
}

// Keep Debug safe for error reporters too; the I/O payload is available by matching.
impl std::fmt::Debug for PolicyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, formatter)
    }
}
