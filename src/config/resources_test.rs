use super::resources::{ExecutionResources, IoMax, ResourceLimits};

const LIMITS: &str = r#"
memory_high = "256 MiB"
memory_max = "512 MiB"
memory_swap_max = "0"
cpu_quota = "150%"
cpu_weight = 100
pids_max = "256"
io_weight = 100
"#;

#[test]
fn limits_have_exact_kernel_units() {
    let parsed: ResourceLimits = toml::from_str(LIMITS).unwrap();

    let writes = parsed.validate().unwrap().writes();

    assert!(writes.contains(&("memory.high", "268435456".into())));
    assert!(writes.contains(&("memory.max", "536870912".into())));
    assert!(writes.contains(&("memory.swap.max", "0".into())));
    assert!(writes.contains(&("cpu.max", "150000 100000".into())));
    assert!(writes.contains(&("cpu.weight", "100".into())));
    assert!(writes.contains(&("pids.max", "256".into())));
    assert!(writes.contains(&("io.weight", "default 100".into())));
}

#[test]
fn malformed_or_unbounded_limits_are_rejected() {
    for changed in [
        LIMITS.replace("512 MiB", "128 MiB"),
        LIMITS.replace("512 MiB", "max"),
        LIMITS.replace("150%", "0%"),
        LIMITS.replace("150%", "1.5%"),
        LIMITS.replace("256\"", "0\""),
        LIMITS.replace("cpu_weight = 100", "cpu_weight = 10001"),
        LIMITS.replace("512 MiB", "18446744073709551615 GiB"),
    ] {
        let result = toml::from_str::<ResourceLimits>(&changed)
            .map_err(|error| error.to_string())
            .and_then(|value| value.validate().map_err(|error| error.to_string()));
        assert!(result.is_err(), "accepted invalid limits: {changed}");
    }
}

#[test]
fn byte_and_decimal_grammars_are_exact() {
    for invalid in [
        "+512 MiB", "-512 MiB", "1.5 MiB", "1e3 MiB", "512  MiB", "512 MB", "512MiB", "max",
    ] {
        let changed = LIMITS.replace("512 MiB", invalid);
        let parsed: ResourceLimits = toml::from_str(&changed).unwrap();
        assert!(parsed.validate().is_err(), "accepted {invalid}");
    }

    for invalid in ["+150%", "-150%", "1.5%", "1e3%", "150", "max"] {
        let changed = LIMITS.replace("150%", invalid);
        let parsed: ResourceLimits = toml::from_str(&changed).unwrap();
        assert!(parsed.validate().is_err(), "accepted {invalid}");
    }

    for invalid in ["+256", "-256", "1.5", "1e3", "max"] {
        let changed = LIMITS.replace("pids_max = \"256\"", &format!("pids_max = \"{invalid}\""));
        let parsed: ResourceLimits = toml::from_str(&changed).unwrap();
        assert!(parsed.validate().is_err(), "accepted {invalid}");
    }
}

#[test]
fn io_max_is_normalized_and_rendered_in_device_order() {
    let mut parsed: ResourceLimits = toml::from_str(LIMITS).unwrap();
    parsed.io_max = vec![
        IoMax {
            device: "8:16".into(),
            read_bytes_per_second: "2 MiB".into(),
            write_bytes_per_second: "1 MiB".into(),
            read_iops: 200,
            write_iops: 100,
        },
        IoMax {
            device: "8:0".into(),
            read_bytes_per_second: "1024 B".into(),
            write_bytes_per_second: "2048".into(),
            read_iops: 20,
            write_iops: 10,
        },
    ];

    let io_writes = parsed
        .validate()
        .unwrap()
        .writes()
        .into_iter()
        .filter(|(name, _)| *name == "io.max")
        .collect::<Vec<_>>();

    assert_eq!(
        io_writes,
        vec![
            ("io.max", "8:0 rbps=1024 wbps=2048 riops=20 wiops=10".into()),
            (
                "io.max",
                "8:16 rbps=2097152 wbps=1048576 riops=200 wiops=100".into(),
            ),
        ]
    );
}

#[test]
fn zero_swap_and_supported_byte_suffixes_are_accepted() {
    for value in ["0", "1 B", "1 KiB", "1 MiB", "1 GiB", "1 TiB"] {
        let changed = LIMITS.replace(
            "memory_swap_max = \"0\"",
            &format!("memory_swap_max = \"{value}\""),
        );
        let parsed: ResourceLimits = toml::from_str(&changed).unwrap();
        assert!(parsed.validate().is_ok(), "rejected {value}");
    }
}

#[test]
fn resource_schema_round_trips() {
    let limits: ResourceLimits = toml::from_str(LIMITS).unwrap();
    let resources = ExecutionResources {
        global: limits.clone(),
        attempt: limits,
    };

    let serialized = toml::to_string(&resources).unwrap();
    let reparsed: ExecutionResources = toml::from_str(&serialized).unwrap();

    assert_eq!(reparsed, resources);
}

#[test]
fn duplicate_devices_are_rejected_after_normalization() {
    let mut parsed: ResourceLimits = toml::from_str(LIMITS).unwrap();
    parsed.io_max = vec![io_limit("8:1"), io_limit("08:01")];

    assert!(parsed.validate().is_err());
}

#[test]
fn malformed_devices_and_zero_io_limits_are_rejected() {
    for device in ["8", "8:1:2", "8:-1", "8: 1", "4294967296:1"] {
        let mut parsed: ResourceLimits = toml::from_str(LIMITS).unwrap();
        parsed.io_max = vec![io_limit(device)];
        assert!(parsed.validate().is_err(), "accepted {device}");
    }

    for zero in [
        IoMax {
            read_bytes_per_second: "0".into(),
            ..io_limit("8:1")
        },
        IoMax {
            write_bytes_per_second: "0".into(),
            ..io_limit("8:1")
        },
        IoMax {
            read_iops: 0,
            ..io_limit("8:1")
        },
        IoMax {
            write_iops: 0,
            ..io_limit("8:1")
        },
    ] {
        let mut parsed: ResourceLimits = toml::from_str(LIMITS).unwrap();
        parsed.io_max = vec![zero];
        assert!(parsed.validate().is_err());
    }
}

#[test]
fn unknown_fields_are_rejected_at_every_resource_level() {
    assert!(toml::from_str::<ResourceLimits>(&format!("{LIMITS}unknown = 1\n")).is_err());
    let error = toml::from_str::<ExecutionResources>("unknown = 1\nglobal = {}\nattempt = {}\n")
        .unwrap_err();
    assert!(error.to_string().contains("unknown field"));

    let with_unknown_io = format!(
        "{LIMITS}io_max = [{{ device = \"8:0\", read_bytes_per_second = \"1\", write_bytes_per_second = \"1\", read_iops = 1, write_iops = 1, unknown = 1 }}]\n"
    );
    assert!(toml::from_str::<ResourceLimits>(&with_unknown_io).is_err());
}

fn io_limit(device: &str) -> IoMax {
    IoMax {
        device: device.into(),
        read_bytes_per_second: "1 MiB".into(),
        write_bytes_per_second: "1 MiB".into(),
        read_iops: 100,
        write_iops: 100,
    }
}
