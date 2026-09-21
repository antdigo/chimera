use std::num::NonZeroUsize;

use super::{ExecutionConfig, ExecutionProfile};
use crate::config::resources::{ExecutionResources, ResourceLimits};

#[test]
fn defaults_to_trusted_host_with_one_reserved_slot() {
    let config = ExecutionConfig::default();
    assert_eq!(config.profile, ExecutionProfile::TrustedHost);
    assert_eq!(config.max_active_domains, NonZeroUsize::new(1).unwrap());
    assert!(config.resources.is_none());
}

#[test]
fn absent_resources_preserve_trusted_host_configuration() {
    let config: ExecutionConfig =
        toml::from_str("profile = 'trusted-host'\nmax_active_domains = 2\n").unwrap();

    assert_eq!(config.profile, ExecutionProfile::TrustedHost);
    assert!(config.resources.is_none());
    assert!(!toml::to_string(&config).unwrap().contains("resources"));
}

#[test]
fn parses_explicit_global_and_attempt_resources() {
    let text = r#"
profile = "sandboxed"
max_active_domains = 20

[resources.global]
memory_high = "256 MiB"
memory_max = "512 MiB"
memory_swap_max = "0"
cpu_quota = "150%"
cpu_weight = 100
pids_max = "256"
io_weight = 100

[resources.attempt]
memory_high = "256 MiB"
memory_max = "512 MiB"
memory_swap_max = "0"
cpu_quota = "150%"
cpu_weight = 100
pids_max = "256"
io_weight = 100
"#;

    let config: ExecutionConfig = toml::from_str(text).unwrap();

    assert!(config.resources.is_some());
    assert!(config.resources.unwrap().attempt.validate().is_ok());
}

#[test]
fn incomplete_resources_are_not_filled_with_defaults() {
    let error = toml::from_str::<ExecutionConfig>(
        "profile = 'trusted-host'\n[resources]\n[resources.global]\nmemory_high = '1 MiB'\n",
    )
    .unwrap_err();

    assert!(error.to_string().contains("missing field"));
}

fn invalid_limits() -> ResourceLimits {
    ResourceLimits {
        memory_high: "2 MiB".into(),
        memory_max: "1 MiB".into(),
        memory_swap_max: "0".into(),
        cpu_quota: "100%".into(),
        cpu_weight: 100,
        pids_max: "10".into(),
        io_weight: 100,
        io_max: Vec::new(),
    }
}

#[test]
fn explicit_resource_types_round_trip_through_execution_config() {
    let limits = invalid_limits();
    let config = ExecutionConfig {
        resources: Some(ExecutionResources {
            global: limits.clone(),
            attempt: limits,
        }),
        ..Default::default()
    };

    let serialized = toml::to_string(&config).unwrap();
    let reparsed: ExecutionConfig = toml::from_str(&serialized).unwrap();

    assert_eq!(reparsed, config);
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

#[test]
fn optional_policy_preserves_trusted_defaults() {
    let config: ExecutionConfig = toml::from_str("").unwrap();
    assert_eq!(config.profile, ExecutionProfile::TrustedHost);
    assert!(config.network.is_none());
    assert!(config.storage.is_none());
}

#[test]
fn sandboxed_without_policy_still_parses() {
    let config: ExecutionConfig = toml::from_str("profile = 'sandboxed'").unwrap();
    assert_eq!(config.profile, ExecutionProfile::Sandboxed);
    assert!(config.network.is_none());
    assert!(config.storage.is_none());
}

#[test]
fn policy_tables_round_trip() {
    let text = "[network]\nproduction_cidrs = ['10.2.0.0/16']\n[storage]\nmechanism = 'project-quota'\nmax_bytes = '64GiB'\n";
    let config: ExecutionConfig = toml::from_str(text).unwrap();
    assert_eq!(config.network.as_ref().unwrap().production_cidrs.len(), 1);
    assert_eq!(
        config.storage.as_ref().unwrap().max_bytes.get(),
        68_719_476_736
    );
    let encoded = toml::to_string(&config).unwrap();
    assert!(encoded.contains("68719476736B"));
    assert_eq!(toml::from_str::<ExecutionConfig>(&encoded).unwrap(), config);
    let empty: ExecutionConfig = toml::from_str("[network]\nproduction_cidrs = []").unwrap();
    assert_eq!(empty.network.unwrap().production_cidrs.len(), 0);
}

#[test]
fn unknown_policy_fields_fail() {
    for text in [
        "[network]\nproduction_cidrs = []\nunknown = true",
        "[storage]\nmechanism = 'btrfs-quota'\nmax_bytes = '1B'\nunknown = true",
        "[network]",
        "[storage]",
    ] {
        assert!(
            toml::from_str::<ExecutionConfig>(text).is_err(),
            "accepted {text:?}"
        );
    }
}
