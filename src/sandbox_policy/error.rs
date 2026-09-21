#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid CIDR")]
    InvalidCidr,
    #[error("invalid storage limit")]
    InvalidStorageLimit,
}
