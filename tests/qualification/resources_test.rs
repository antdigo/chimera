use super::catalog::{CaseKey, Reason, ScenarioId, required_cases, required_checks};
use super::host::NativeConfig;
use super::report::EvidenceMode;
use super::resources::*;
use chimera::config::resources::IoMax;

fn key(name: &str) -> CaseKey {
    required_cases()
        .into_iter()
        .find(|k| k.case == name)
        .unwrap()
}
fn limits(cgroup: &str, global: bool) -> LimitReadback {
    LimitReadback {
        cgroup: cgroup.into(),
        memory_high: if global { 1048576 } else { 524288 },
        memory_max: if global { 2097152 } else { 1048576 },
        memory_swap_max: 0,
        pids_max: if global { 200 } else { 10 },
        cpu_quota_usec: if global { 100000 } else { 50000 },
        cpu_period_usec: 100000,
        cpu_weight: 100,
        io_weight: 100,
        io: vec![IoLimitReadback {
            major: 8,
            minor: 0,
            read_bps: 10000,
            write_bps: 10000,
            read_iops: 100,
            write_iops: 100,
        }],
    }
}
fn sample(index: u64) -> MetricSample {
    MetricSample {
        phase: if index == 0 {
            SamplePhase::Before
        } else if index == 12 {
            SamplePhase::After
        } else {
            SamplePhase::Active
        },
        elapsed_ms: index * 250,
        pss_bytes: 4096,
        cpu_usage_usec: index * 100000,
        io: vec![IoCounters {
            major: 8,
            minor: 0,
            read_bytes: index * 1000,
            write_bytes: index * 1000,
            read_ops: index * 10,
            write_ops: index * 10,
        }],
        pids_current: 2,
        memory_current: 8192,
        memory_events_oom_kill: index,
        pids_events_max: index,
        cpu_nr_periods: index * 2,
        cpu_nr_throttled: index,
        cpu_throttled_usec: index * 1000,
        host_mem_available_bytes: 10485760,
        sentinel_latency_us: 1000,
    }
}
pub(super) fn fixture(key: &CaseKey) -> (NativeConfig, ResourceInput, ResourceFacts) {
    let mut config: NativeConfig =
        serde_json::from_str(include_str!("../fixtures/qualification/config.json")).unwrap();
    config.max_parallel_builds = 40;
    config.maximum_chimera_pids = 200;
    config.execution_resources.global.pids_max = "200".into();
    for limits in [
        &mut config.execution_resources.global,
        &mut config.execution_resources.attempt,
    ] {
        limits.io_max = vec![IoMax {
            device: "8:0".into(),
            read_bytes_per_second: "10000".into(),
            write_bytes_per_second: "10000".into(),
            read_iops: 100,
            write_iops: 100,
        }];
    }
    let input = ResourceInput {
        global_cgroup: "/fixture/global".into(),
        attempt_cgroups: (0..key.concurrency)
            .map(|i| format!("/fixture/global/attempt-{i}"))
            .collect(),
        workload_deadline_ms: 5000,
        io_warmup_ms: 500,
    };
    let facts = ResourceFacts {
        baseline: (0..=40)
            .map(|i| SentinelSample {
                elapsed_ms: i * 250,
                host_mem_available_bytes: 10485760,
                latency_us: 1000,
            })
            .collect(),
        global: ScopedSamples {
            limits: limits(&input.global_cgroup, true),
            samples: (0..=12).map(sample).collect(),
        },
        attempts: input
            .attempt_cgroups
            .iter()
            .map(|path| ScopedSamples {
                limits: limits(path, false),
                samples: (0..=12).map(sample).collect(),
            })
            .collect(),
        startup_ms: 100,
        cleanup_ms: 100,
        oom_contained: true,
        pid_limit_hit: true,
        cpu_saturation_completed: true,
        io_saturation_completed: true,
        expected_work_completed: true,
        cleanup_confirmed: true,
    };
    (config, input, facts)
}
fn evaluate(
    name: &str,
    mutate: impl FnOnce(&mut ResourceFacts),
) -> Result<Vec<super::report::Check>, Reason> {
    let key = key(name);
    let (config, input, mut facts) = fixture(&key);
    mutate(&mut facts);
    evaluate_resources(EvidenceMode::Fixture, &key, &config, &input, &facts)
}

#[test]
fn resources_p99_and_elapsed_counter_rates_are_not_means_or_counter_totals() {
    assert_eq!(nearest_rank_p99(&[100, 200, 9000]), Ok(9000));
    assert!(nearest_rank_p99(&[]).is_err());
    let (_, _, mut facts) = fixture(&key("cpu"));
    facts.global.samples = (0..3)
        .map(|i| {
            let mut s = sample(i);
            s.elapsed_ms = i * 1000;
            s.io[0].write_ops = 10 + i * 10;
            s
        })
        .collect();
    let summary = summarize_resources(&facts).unwrap();
    assert_eq!(summary.write_iops, 10.0);
    assert_eq!(summary.total_cpu_usage_usec, 200000);
}

#[test]
fn resources_all_catalogue_cases_use_exact_checks_but_native_remains_blocked() {
    for key in required_cases()
        .into_iter()
        .filter(|k| matches!(k.scenario, ScenarioId::S09 | ScenarioId::S16))
    {
        let (config, input, facts) = fixture(&key);
        let checks =
            evaluate_resources(EvidenceMode::Fixture, &key, &config, &input, &facts).unwrap();
        assert_eq!(
            checks.iter().map(|c| c.id).collect::<Vec<_>>(),
            required_checks(&key)
        );
        for mode in [EvidenceMode::NativeDebian, EvidenceMode::NestedSmoke] {
            assert_eq!(
                evaluate_resources(mode, &key, &config, &input, &facts),
                Err(Reason::BackendUnavailable)
            );
        }
    }
}

#[test]
fn resources_incomplete_samples_never_become_zero_cost_success() {
    let mutations: Vec<fn(&mut ResourceFacts)> = vec![
        |f| f.global.samples.clear(),
        |f| f.global.samples.truncate(1),
        |f| f.global.samples[5].elapsed_ms = 1000,
        |f| f.global.samples[5].elapsed_ms += 1,
        |f| f.global.samples[5].pss_bytes = 0,
        |f| f.global.samples[5].cpu_usage_usec = 0,
        |f| f.global.samples[5].io[0].write_ops = 0,
        |f| f.global.samples[5].io[0].read_bytes = 0,
        |f| f.global.samples[5].memory_events_oom_kill = 0,
        |f| f.global.samples[5].pids_events_max = 0,
        |f| f.global.samples[5].cpu_nr_throttled = 0,
        |f| f.global.samples[5].cpu_nr_periods = 0,
        |f| f.global.samples[5].cpu_throttled_usec = 0,
        |f| f.global.samples.remove(5).phase = SamplePhase::After,
        |f| f.global.samples[1].phase = SamplePhase::Before,
        |f| f.baseline.pop().unwrap().latency_us = 0,
        |f| f.expected_work_completed = false,
        |f| f.attempts.clear(),
    ];
    for (i, mutate) in mutations.into_iter().enumerate() {
        assert!(evaluate("cpu", mutate).is_err(), "mutation {i}");
    }
}

#[test]
fn resources_explicit_violations_win_over_stale_and_missing_evidence() {
    for stale in [false, true] {
        assert_eq!(
            evaluate("cpu", |f| {
                f.expected_work_completed = false;
                if stale {
                    f.attempts[0].limits.cgroup = "/fixture/stale".into();
                }
                f.global.samples[5].host_mem_available_bytes = 0;
            }),
            Err(Reason::BoundaryViolation)
        );
        assert_eq!(
            evaluate("cpu", |f| {
                f.global.samples[5].sentinel_latency_us = 1000000;
                f.attempts.clear();
            }),
            Err(Reason::SloExceeded)
        );
        assert_eq!(
            evaluate("cpu", |f| {
                f.cleanup_confirmed = false;
                f.global.samples[5].host_mem_available_bytes = 0;
                f.attempts.clear();
            }),
            Err(Reason::CleanupUnconfirmed)
        );
    }
    assert_eq!(
        evaluate("cpu", |f| {
            f.attempts[0].limits.cgroup = "/fixture/stale".into();
            f.global.samples.clear();
        }),
        Err(Reason::StaleEvidence)
    );
}

#[test]
fn resources_each_attempt_enforces_quota_and_io_even_when_global_is_healthy() {
    assert_eq!(
        evaluate("cpu", |f| {
            for (i, s) in f.attempts[0].samples.iter_mut().enumerate() {
                s.cpu_usage_usec = i as u64 * 200000;
            }
        }),
        Err(Reason::BoundaryViolation)
    );
    assert_eq!(
        evaluate("io", |f| {
            for (i, s) in f.attempts[0].samples.iter_mut().enumerate() {
                s.io[0].write_bytes = i as u64 * 10000;
            }
        }),
        Err(Reason::BoundaryViolation)
    );
    assert!(
        evaluate("cpu", |f| {
            for s in &mut f.attempts[0].samples {
                s.cpu_nr_throttled = 0;
                s.cpu_throttled_usec = 0;
            }
        })
        .is_err()
    );
    assert!(
        evaluate("io", |f| {
            for s in &mut f.attempts[0].samples {
                s.io[0].write_ops = 0;
            }
        })
        .is_err()
    );
    assert_eq!(
        evaluate("cpu", |f| f.global.limits.cpu_quota_usec = 99999),
        Err(Reason::BoundaryViolation)
    );
    assert!(evaluate("io", |f| f.global.limits.io.clear()).is_err());
}

#[test]
fn resources_readbacks_parse_all_canonical_devices_and_reject_missing_max_and_duplicates() {
    let (mut config, _, _) = fixture(&key("io"));
    config.execution_resources.global.io_max.push(IoMax {
        device: "8:16".into(),
        read_bytes_per_second: "20000".into(),
        write_bytes_per_second: "30000".into(),
        read_iops: 200,
        write_iops: 300,
    });
    let writes = config
        .execution_resources
        .global
        .validate()
        .unwrap()
        .writes();
    let readback = parse_limit_readback("/fixture/global", &writes).unwrap();
    assert_eq!(readback.io.len(), 2);
    assert_eq!(readback.io[1].minor, 16);
    assert_eq!(readback.io[1].write_bps, 30000);
    for missing in ["memory.max", "cpu.max", "io.weight"] {
        let incomplete: Vec<_> = writes
            .iter()
            .filter(|(name, _)| *name != missing)
            .cloned()
            .collect();
        assert!(parse_limit_readback("/fixture/global", &incomplete).is_err());
    }
    let mut bad = writes.clone();
    bad[1].1 = "max".into();
    assert!(parse_limit_readback("/fixture/global", &bad).is_err());
    let mut bad = writes.clone();
    bad.push(writes[0].clone());
    assert!(parse_limit_readback("/fixture/global", &bad).is_err());
}

#[test]
fn resources_schema_rejects_rss_substitution_and_absent_pss() {
    let (_, _, facts) = fixture(&key("cpu"));
    let mut value = serde_json::to_value(&facts).unwrap();
    value["global"]["samples"][0]["rss_bytes"] = 100.into();
    assert!(serde_json::from_value::<ResourceFacts>(value).is_err());
    let mut value = serde_json::to_value(&facts).unwrap();
    value["global"]["samples"][0]
        .as_object_mut()
        .unwrap()
        .remove("pss_bytes");
    assert!(serde_json::from_value::<ResourceFacts>(value).is_err());
}

#[test]
fn resources_global_summary_does_not_count_attempt_pss_twice() {
    let mut key = key("native-storage");
    key.concurrency = 40;
    let (config, input, mut facts) = fixture(&key);
    assert_eq!(summarize_resources(&facts).unwrap().peak_pss_bytes, 4096);
    facts.attempts[39].samples[4].pss_bytes = 0;
    assert_eq!(
        evaluate_resources(EvidenceMode::Fixture, &key, &config, &input, &facts),
        Err(Reason::MissingEvidence)
    );
    facts.attempts[39].samples[4].host_mem_available_bytes = 0;
    assert_eq!(
        evaluate_resources(EvidenceMode::Fixture, &key, &config, &input, &facts),
        Err(Reason::BoundaryViolation)
    );
}

#[test]
fn resources_ten_active_samples_and_idle_pss_are_explicit() {
    let key = key("cpu");
    let (config, input, mut facts) = fixture(&key);
    for scope in std::iter::once(&mut facts.global).chain(facts.attempts.iter_mut()) {
        for index in [0, 12] {
            let sample = &mut scope.samples[index];
            sample.pss_bytes = 0;
            sample.pids_current = 0;
            sample.memory_current = 0;
        }
    }
    assert!(evaluate_resources(EvidenceMode::Fixture, &key, &config, &input, &facts).is_ok());
    for scope in std::iter::once(&mut facts.global).chain(facts.attempts.iter_mut()) {
        scope.samples.truncate(11);
        scope.samples[10].phase = SamplePhase::After;
    }
    assert_eq!(
        evaluate_resources(EvidenceMode::Fixture, &key, &config, &input, &facts),
        Err(Reason::MissingEvidence)
    );
}

#[test]
fn resources_all_limit_fields_and_devices_are_checked_with_healthy_sentinel() {
    for field in [
        "memory_high",
        "memory_max",
        "memory_swap_max",
        "pids_max",
        "cpu_quota_usec",
        "cpu_period_usec",
        "cpu_weight",
        "io_weight",
    ] {
        let key = key("io");
        let (config, input, facts) = fixture(&key);
        for scope in ["global", "attempts"] {
            let mut value = serde_json::to_value(&facts).unwrap();
            let limits = if scope == "global" {
                &mut value["global"]["limits"]
            } else {
                &mut value["attempts"][0]["limits"]
            };
            let old = limits[field].as_u64().unwrap();
            limits[field] = (old + 1).into();
            let changed = serde_json::from_value(value).unwrap();
            assert_eq!(
                evaluate_resources(EvidenceMode::Fixture, &key, &config, &input, &changed),
                Err(Reason::BoundaryViolation),
                "{scope} {field}"
            );
        }
    }
    for mutate in [
        (|f: &mut ResourceFacts| f.global.limits.io[0].minor = 16) as fn(&mut ResourceFacts),
        |f| {
            let duplicate = f.attempts[0].limits.io[0].clone();
            f.attempts[0].limits.io.push(duplicate);
        },
        |f| f.attempts[0].samples[4].io[0].minor = 16,
        |f| f.attempts[0].samples[4].io.clear(),
    ] {
        assert!(evaluate("io", mutate).is_err());
    }
}

#[test]
fn resources_reserve_baseline_completion_and_deadlines_cannot_be_skipped() {
    assert_eq!(
        evaluate("io", |f| {
            f.baseline[0].host_mem_available_bytes = 0;
            f.global.samples.clear();
        }),
        Err(Reason::BoundaryViolation)
    );
    assert_eq!(
        evaluate("io", |f| {
            f.baseline[0].latency_us = 1000000;
            f.global.samples.clear();
        }),
        Err(Reason::SloExceeded)
    );
    assert_eq!(
        evaluate("io", |f| {
            f.cleanup_ms = 1001;
            f.attempts.clear();
        }),
        Err(Reason::DeadlineExceeded)
    );
    assert_eq!(
        evaluate("io", |f| {
            f.startup_ms = 5001;
            f.attempts.clear();
        }),
        Err(Reason::DeadlineExceeded)
    );
    for (name, mutate) in [
        (
            "memory-oom",
            (|f: &mut ResourceFacts| f.oom_contained = false) as fn(&mut ResourceFacts),
        ),
        ("pids", |f| f.pid_limit_hit = false),
        ("cpu", |f| f.cpu_saturation_completed = false),
        ("io", |f| f.io_saturation_completed = false),
    ] {
        assert_eq!(
            evaluate(name, mutate),
            Err(if name == "memory-oom" {
                Reason::BoundaryViolation
            } else {
                Reason::MissingEvidence
            })
        );
    }
}

#[test]
fn resources_extreme_untrusted_timestamps_cannot_overflow_rate_comparison() {
    let key = key("io");
    let (mut config, input, mut facts) = fixture(&key);
    config.execution_resources.attempt.io_max[0].write_iops = u64::MAX;
    facts.attempts[0].limits.io[0].write_iops = u64::MAX;
    facts.attempts[0].samples[11].elapsed_ms = u64::MAX - 1;
    facts.attempts[0].samples[12].elapsed_ms = u64::MAX;
    assert!(evaluate_resources(EvidenceMode::Fixture, &key, &config, &input, &facts).is_err());
}

#[test]
fn resources_missing_periods_cannot_hide_affirmative_cpu_overuse_or_oom_escape() {
    assert_eq!(
        evaluate("native-storage", |f| {
            for (i, s) in f.attempts[0].samples.iter_mut().enumerate() {
                s.cpu_usage_usec = i as u64 * 200000;
                s.cpu_nr_periods = 0;
                s.cpu_nr_throttled = 0;
            }
            f.expected_work_completed = false;
        }),
        Err(Reason::BoundaryViolation)
    );
    assert_eq!(
        evaluate("memory-oom", |f| {
            f.oom_contained = false;
            f.attempts.clear();
        }),
        Err(Reason::BoundaryViolation)
    );
}

#[test]
fn resources_regressing_periods_cannot_hide_cpu_overuse_and_cleanup_has_priority() {
    for name in ["cpu", "native-storage"] {
        for cleanup_confirmed in [true, false] {
            assert_eq!(
                evaluate(name, |facts| {
                    for (index, sample) in facts.attempts[0].samples.iter_mut().enumerate() {
                        sample.cpu_usage_usec = index as u64 * 200000;
                    }
                    facts.attempts[0].samples[1].cpu_nr_periods = 1000;
                    facts.expected_work_completed = false;
                    facts.cleanup_confirmed = cleanup_confirmed;
                }),
                Err(if cleanup_confirmed {
                    Reason::BoundaryViolation
                } else {
                    Reason::CleanupUnconfirmed
                }),
                "{name}, cleanup_confirmed={cleanup_confirmed}"
            );
        }
    }
}

#[test]
fn resources_every_configured_device_needs_matching_counters_and_limits() {
    let key = key("io");
    let (mut config, input, mut facts) = fixture(&key);
    for limits in [
        &mut config.execution_resources.global,
        &mut config.execution_resources.attempt,
    ] {
        let mut second = limits.io_max[0].clone();
        second.device = "8:16".into();
        limits.io_max.push(second);
    }
    for scope in std::iter::once(&mut facts.global).chain(facts.attempts.iter_mut()) {
        let mut second = scope.limits.io[0].clone();
        second.minor = 16;
        scope.limits.io.push(second);
        for s in &mut scope.samples {
            let mut second = s.io[0].clone();
            second.minor = 16;
            s.io.push(second);
        }
    }
    assert!(evaluate_resources(EvidenceMode::Fixture, &key, &config, &input, &facts).is_ok());
    let mut bad = facts.clone();
    bad.attempts[0].limits.io.pop();
    assert_eq!(
        evaluate_resources(EvidenceMode::Fixture, &key, &config, &input, &bad),
        Err(Reason::BoundaryViolation)
    );
    let mut bad = facts.clone();
    for s in &mut bad.attempts[0].samples {
        s.io.pop();
    }
    assert_eq!(
        evaluate_resources(EvidenceMode::Fixture, &key, &config, &input, &bad),
        Err(Reason::MissingEvidence)
    );
    for (i, s) in facts.attempts[0].samples.iter_mut().enumerate() {
        s.io[1].write_ops = i as u64 * 100;
    }
    assert_eq!(
        evaluate_resources(EvidenceMode::Fixture, &key, &config, &input, &facts),
        Err(Reason::BoundaryViolation)
    );
}
