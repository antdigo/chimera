use std::net::IpAddr;

use super::{HostAddresses, compile_network};
use crate::config::NetworkPolicyConfig;

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
