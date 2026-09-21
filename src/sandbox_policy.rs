mod capability;
mod doctor;
mod error;
mod install;
mod network;
mod probe;
mod storage;

#[cfg(test)]
#[path = "sandbox_policy/capability_test.rs"]
mod capability_test;

pub use capability::{
    CacheCapabilityBinding, CapabilityDescriptor, CapabilityService, validate_descriptor,
};
pub use doctor::{CheckStatus, DoctorCheck, DoctorReport, inspect_install_plan, inspect_policy};
pub use error::PolicyError;
pub use install::{InstallPlan, render_install_plan};
pub use network::{
    AppliedNetworkPolicy, ProbeBatch, SentinelObservation, ServiceGeneration,
    validate_network_evidence,
};
pub use network::{HostAddresses, NetworkPolicy, compile_network};
pub use probe::{ConnectOutcome, probe_connect};
pub use storage::{
    StorageBoundEvidence, StorageIdentity, StorageObservation, probe_storage,
    revalidate_storage_identity, validate_storage_bound,
};
