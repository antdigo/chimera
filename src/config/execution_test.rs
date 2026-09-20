use std::num::NonZeroUsize;

use super::{ExecutionConfig, ExecutionProfile};

#[test]
fn defaults_to_trusted_host_with_one_reserved_slot() {
    let config = ExecutionConfig::default();
    assert_eq!(config.profile, ExecutionProfile::TrustedHost);
    assert_eq!(config.max_active_domains, NonZeroUsize::new(1).unwrap());
}

#[test]
fn parses_sandboxed_capacity() {
    let config: ExecutionConfig =
        toml::from_str("profile = 'sandboxed'\nmax_active_domains = 40\n").unwrap();
    assert_eq!(config.profile, ExecutionProfile::Sandboxed);
    assert_eq!(config.max_active_domains.get(), 40);
}

#[test]
fn rejects_unknown_profile() {
    let error =
        toml::from_str::<ExecutionConfig>("profile = 'isolated'\nmax_active_domains = 20\n")
            .unwrap_err();
    assert!(error.to_string().contains("unknown variant"));
}

#[test]
fn rejects_zero_capacity() {
    let error =
        toml::from_str::<ExecutionConfig>("profile = 'sandboxed'\nmax_active_domains = 0\n")
            .unwrap_err();
    assert!(error.to_string().contains("nonzero"));
}
