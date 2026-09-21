use std::net::IpAddr;

use super::{HostAddresses, compile_network};
use crate::config::NetworkPolicyConfig;
use crate::sandbox_policy::{
    AppliedNetworkPolicy, ConnectOutcome, PolicyError, ProbeBatch, SentinelObservation,
    ServiceGeneration, validate_network_evidence,
};
use std::net::SocketAddr;

fn evidence() -> (super::NetworkPolicy, AppliedNetworkPolicy, ProbeBatch) {
    let policy = compile_network(
        &NetworkPolicyConfig {
            production_cidrs: vec!["198.51.100.0/24".parse().unwrap()],
        },
        &HostAddresses {
            addresses: vec!["203.0.113.9".parse().unwrap()],
        },
    )
    .unwrap();
    let generation = ServiceGeneration {
        boot_id: uuid::Uuid::new_v4(),
        invocation_id: "0123456789abcdef0123456789abcdef".into(),
        control_group: "/system.slice/chimera.service".into(),
    };
    let sentinel = |address: &str| SentinelObservation {
        address: address.parse::<SocketAddr>().unwrap(),
        control_before: true,
        control_after: true,
        observed: ConnectOutcome::Denied,
    };
    let applied = AppliedNetworkPolicy {
        generation: generation.clone(),
        denied: policy.denied().to_vec(),
        allowed: vec![],
        bpf_attached: true,
    };
    let probes = ProbeBatch {
        generation,
        negative: vec![
            sentinel("127.0.0.1:443"),
            sentinel("203.0.113.9:443"),
            sentinel("198.51.100.1:443"),
        ],
        public_registry_ok: true,
    };
    (policy, applied, probes)
}

#[test]
fn valid_evidence_requires_real_denial_across_all_classes() {
    let (policy, applied, probes) = evidence();
    assert!(matches!(
        validate_network_evidence(&policy, &applied, &probes),
        Ok(())
    ));
}

#[test]
fn ambiguous_and_allowed_negative_probes_are_rejected() {
    for (outcome, expected) in [
        (
            ConnectOutcome::Connected,
            PolicyError::ProbeAllowedForbidden,
        ),
        (ConnectOutcome::Refused, PolicyError::ProbeInconclusive),
        (ConnectOutcome::Unreachable, PolicyError::ProbeInconclusive),
    ] {
        let (policy, applied, mut probes) = evidence();
        probes.negative[0].observed = outcome;
        assert_eq!(
            std::mem::discriminant(
                &validate_network_evidence(&policy, &applied, &probes).unwrap_err()
            ),
            std::mem::discriminant(&expected)
        );
    }
    for before in [true, false] {
        let (policy, applied, mut probes) = evidence();
        probes.negative[0].control_before = before;
        probes.negative[0].control_after = !before;
        assert!(matches!(
            validate_network_evidence(&policy, &applied, &probes),
            Err(PolicyError::ProbeInconclusive)
        ));
    }
}

#[test]
fn stale_or_loose_policy_evidence_is_rejected() {
    let (policy, mut applied, probes) = evidence();
    applied.allowed.push("0.0.0.0/0".parse().unwrap());
    assert!(matches!(
        validate_network_evidence(&policy, &applied, &probes),
        Err(PolicyError::PolicyMismatch)
    ));
    let (policy, mut applied, probes) = evidence();
    applied.bpf_attached = false;
    assert!(matches!(
        validate_network_evidence(&policy, &applied, &probes),
        Err(PolicyError::PolicyMismatch)
    ));
    let (policy, mut applied, probes) = evidence();
    applied.generation.boot_id = uuid::Uuid::new_v4();
    assert!(matches!(
        validate_network_evidence(&policy, &applied, &probes),
        Err(PolicyError::PolicyMismatch)
    ));
    let (policy, mut applied, probes) = evidence();
    applied.generation.invocation_id = "stale".into();
    assert!(matches!(
        validate_network_evidence(&policy, &applied, &probes),
        Err(PolicyError::PolicyMismatch)
    ));
    let (policy, mut applied, probes) = evidence();
    applied.generation.control_group = "/system.slice/other.service".into();
    assert!(matches!(
        validate_network_evidence(&policy, &applied, &probes),
        Err(PolicyError::PolicyMismatch)
    ));
}

#[test]
fn incomplete_probe_set_is_inconclusive() {
    for index in 0..3 {
        let (policy, applied, mut probes) = evidence();
        probes.negative.remove(index);
        assert!(matches!(
            validate_network_evidence(&policy, &applied, &probes),
            Err(PolicyError::ProbeInconclusive)
        ));
    }
    let (policy, applied, mut probes) = evidence();
    probes.public_registry_ok = false;
    assert!(matches!(
        validate_network_evidence(&policy, &applied, &probes),
        Err(PolicyError::ProbeInconclusive)
    ));
}

#[test]
fn overlapping_production_prefixes_need_distinct_sentinels() {
    let (base_policy, mut applied, mut probes) = evidence();
    let policy = compile_network(
        &NetworkPolicyConfig {
            production_cidrs: vec![
                "198.51.100.0/24".parse().unwrap(),
                "198.51.100.0/25".parse().unwrap(),
            ],
        },
        &HostAddresses {
            addresses: vec!["203.0.113.9".parse().unwrap()],
        },
    )
    .unwrap();
    assert_ne!(base_policy.digest(), policy.digest());
    applied.denied = policy.denied().to_vec();

    assert!(matches!(
        validate_network_evidence(&policy, &applied, &probes),
        Err(PolicyError::ProbeInconclusive)
    ));

    probes.negative.push(SentinelObservation {
        address: "198.51.100.1:8443".parse().unwrap(),
        control_before: true,
        control_after: true,
        observed: ConnectOutcome::Denied,
    });
    assert!(matches!(
        validate_network_evidence(&policy, &applied, &probes),
        Err(PolicyError::ProbeInconclusive)
    ));
    probes.negative.last_mut().unwrap().address = "198.51.100.200:443".parse().unwrap();
    assert!(matches!(
        validate_network_evidence(&policy, &applied, &probes),
        Ok(())
    ));
}

#[test]
fn canonical_policy_blocks_host_and_special_networks() {
    let config = NetworkPolicyConfig {
        production_cidrs: vec!["198.51.100.0/24".parse().unwrap()],
    };
    let host = HostAddresses {
        addresses: vec!["203.0.113.9".parse().unwrap()],
    };

    let policy = compile_network(&config, &host).unwrap();

    for address in [
        "127.1.2.3",
        "169.254.1.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "224.1.2.3",
        "0.1.2.3",
        "255.255.255.255",
        "203.0.113.9",
        "198.51.100.42",
        "::1",
        "fe80::1",
        "ff00::1",
        "fc00::1",
        "::",
        "2001:4860:4860::8888",
        "::ffff:1.1.1.1",
    ] {
        assert!(
            !policy.permits(address.parse().unwrap()),
            "permitted {address}"
        );
    }
    assert!(policy.permits("1.1.1.1".parse().unwrap()));
    let required: Vec<String> = policy
        .required_probe_prefixes()
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        required,
        ["127.0.0.0/8", "198.51.100.0/24", "203.0.113.9/32"]
    );
}

#[test]
fn reordered_duplicate_inputs_produce_identical_policy() {
    let a = compile_network(
        &NetworkPolicyConfig {
            production_cidrs: vec![
                "198.51.100.0/24".parse().unwrap(),
                "10.0.0.0/8".parse().unwrap(),
            ],
        },
        &HostAddresses {
            addresses: vec!["203.0.113.9".parse().unwrap(), "192.0.2.8".parse().unwrap()],
        },
    )
    .unwrap();
    let b = compile_network(
        &NetworkPolicyConfig {
            production_cidrs: vec![
                "10.0.0.0/8".parse().unwrap(),
                "198.51.100.0/24".parse().unwrap(),
                "10.0.0.0/8".parse().unwrap(),
            ],
        },
        &HostAddresses {
            addresses: vec![
                "192.0.2.8".parse().unwrap(),
                "203.0.113.9".parse().unwrap(),
                "192.0.2.8".parse().unwrap(),
            ],
        },
    )
    .unwrap();

    assert_eq!(a.digest(), b.digest());
    assert_eq!(
        crate::sandbox_policy::render_install_plan(&a).drop_in,
        crate::sandbox_policy::render_install_plan(&b).drop_in
    );
    assert_eq!(
        a.denied()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        b.denied()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        a.required_probe_prefixes()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        b.required_probe_prefixes()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    );
}

#[test]
fn empty_host_inventory_is_rejected() {
    let result = compile_network(
        &NetworkPolicyConfig {
            production_cidrs: vec![],
        },
        &HostAddresses { addresses: vec![] },
    );
    assert!(result.is_err());
}

#[test]
fn ipv6_host_is_a_required_probe_even_when_ipv6_is_denied() {
    let host_address: IpAddr = "2001:db8::9".parse().unwrap();
    let policy = compile_network(
        &NetworkPolicyConfig {
            production_cidrs: vec![],
        },
        &HostAddresses {
            addresses: vec![host_address],
        },
    )
    .unwrap();
    assert!(
        policy
            .required_probe_prefixes()
            .iter()
            .any(|cidr| cidr.to_string() == "2001:db8::9/128")
    );
    assert!(!policy.permits(host_address));
}
