//! Pure E0 fixture evaluation. These local series are not driver observations:
//! neither wire labels nor numeric readbacks authenticate a native cgroup.
//! E1 must supply pinned run-owned collection, PID-start checks and a watchdog.
use super::catalog::{CaseKey, Reason, ScenarioId, required_cases, required_checks};
use super::host::NativeConfig;
use super::report::{Check, EvidenceMode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const SAMPLE_MS: u64 = 250;
const MAX_SAMPLES: usize = 1202; // Five-minute bounded fixture plus endpoints.

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SamplePhase {
    Before,
    Active,
    // After the workload, before teardown removes these cgroup counters.
    After,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IoCounters {
    pub major: u32,
    pub minor: u32,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_ops: u64,
    pub write_ops: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricSample {
    pub phase: SamplePhase,
    pub elapsed_ms: u64,
    pub pss_bytes: u64,
    pub cpu_usage_usec: u64,
    pub io: Vec<IoCounters>,
    pub pids_current: u64,
    pub memory_current: u64,
    pub memory_events_oom_kill: u64,
    pub pids_events_max: u64,
    pub cpu_nr_periods: u64,
    pub cpu_nr_throttled: u64,
    pub cpu_throttled_usec: u64,
    pub host_mem_available_bytes: u64,
    pub sentinel_latency_us: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IoLimitReadback {
    pub major: u32,
    pub minor: u32,
    pub read_bps: u64,
    pub write_bps: u64,
    pub read_iops: u64,
    pub write_iops: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitReadback {
    pub cgroup: String,
    pub memory_high: u64,
    pub memory_max: u64,
    pub memory_swap_max: u64,
    pub pids_max: u64,
    pub cpu_quota_usec: u64,
    pub cpu_period_usec: u64,
    pub cpu_weight: u64,
    pub io_weight: u64,
    pub io: Vec<IoLimitReadback>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedSamples {
    pub limits: LimitReadback,
    pub samples: Vec<MetricSample>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SentinelSample {
    pub elapsed_ms: u64,
    pub host_mem_available_bytes: u64,
    pub latency_us: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceFacts {
    pub baseline: Vec<SentinelSample>,
    pub global: ScopedSamples,
    pub attempts: Vec<ScopedSamples>,
    pub startup_ms: u64,
    pub cleanup_ms: u64,
    pub oom_contained: bool,
    pub pid_limit_hit: bool,
    pub cpu_saturation_completed: bool,
    pub io_saturation_completed: bool,
    pub expected_work_completed: bool,
    pub cleanup_confirmed: bool,
}
/// Expected scope comes from the fixture orchestrator, never from readbacks.
#[derive(Clone, Debug)]
pub struct ResourceInput {
    pub global_cgroup: String,
    pub attempt_cgroups: Vec<String>,
    pub workload_deadline_ms: u64,
    pub io_warmup_ms: u64,
}
/// JSON field suffixes name units; counts are dimensionless. No RSS field exists.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceSummary {
    pub peak_pss_bytes: u64,
    pub peak_pids: u64,
    pub sentinel_p99_us: u64,
    pub read_iops: f64,
    pub write_iops: f64,
    pub minimum_host_mem_available_bytes: u64,
    pub cpu_throttled_periods: u64,
    pub cpu_throttled_usec: u64,
    pub total_cpu_usage_usec: u64,
    pub startup_ms: u64,
    pub cleanup_ms: u64,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseMetrics {
    pub key: CaseKey,
    pub summary: ResourceSummary,
}

fn decimal(value: &str) -> Result<u64, Reason> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Reason::MissingEvidence);
    }
    value.parse().map_err(|_| Reason::MissingEvidence)
}
/// Bounded parser over supplied file contents. Never opens a caller-named path.
/// Multiple io.max rows are retained; no first-device fallback is permitted.
pub fn parse_limit_readback(
    cgroup: &str,
    files: &[(&str, String)],
) -> Result<LimitReadback, Reason> {
    if files.len() > 256 || files.iter().any(|(_, v)| v.len() > 32768) {
        return Err(Reason::MissingEvidence);
    }
    let one = |name| -> Result<&str, Reason> {
        let values: Vec<_> = files.iter().filter(|(n, _)| *n == name).collect();
        if values.len() != 1 {
            return Err(Reason::MissingEvidence);
        }
        Ok(values[0].1.trim())
    };
    let cpu: Vec<_> = one("cpu.max")?.split_whitespace().collect();
    let weight: Vec<_> = one("io.weight")?.split_whitespace().collect();
    if cpu.len() != 2 || weight.len() != 2 || weight[0] != "default" {
        return Err(Reason::MissingEvidence);
    }
    let mut io = Vec::new();
    for (_, contents) in files.iter().filter(|(n, _)| *n == "io.max") {
        for line in contents.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() != 5 {
                return Err(Reason::MissingEvidence);
            }
            let (major, minor) = fields[0].split_once(':').ok_or(Reason::MissingEvidence)?;
            let parameter = |name: &str| -> Result<u64, Reason> {
                let matches: Vec<_> = fields[1..]
                    .iter()
                    .filter_map(|s| s.split_once('='))
                    .filter(|(n, _)| *n == name)
                    .collect();
                if matches.len() != 1 {
                    return Err(Reason::MissingEvidence);
                }
                decimal(matches[0].1)
            };
            io.push(IoLimitReadback {
                major: decimal(major)?
                    .try_into()
                    .map_err(|_| Reason::MissingEvidence)?,
                minor: decimal(minor)?
                    .try_into()
                    .map_err(|_| Reason::MissingEvidence)?,
                read_bps: parameter("rbps")?,
                write_bps: parameter("wbps")?,
                read_iops: parameter("riops")?,
                write_iops: parameter("wiops")?,
            });
        }
    }
    io.sort_by_key(|v| (v.major, v.minor));
    if io
        .windows(2)
        .any(|p| (p[0].major, p[0].minor) == (p[1].major, p[1].minor))
    {
        return Err(Reason::MissingEvidence);
    }
    Ok(LimitReadback {
        cgroup: cgroup.into(),
        memory_high: decimal(one("memory.high")?)?,
        memory_max: decimal(one("memory.max")?)?,
        memory_swap_max: decimal(one("memory.swap.max")?)?,
        pids_max: decimal(one("pids.max")?)?,
        cpu_quota_usec: decimal(cpu[0])?,
        cpu_period_usec: decimal(cpu[1])?,
        cpu_weight: decimal(one("cpu.weight")?)?,
        io_weight: decimal(weight[1])?,
        io,
    })
}

pub fn nearest_rank_p99(values: &[u64]) -> Result<u64, Reason> {
    if values.is_empty() || values.len() > MAX_SAMPLES {
        return Err(Reason::MissingEvidence);
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let rank = values
        .len()
        .checked_mul(99)
        .ok_or(Reason::MissingEvidence)?
        .div_ceil(100);
    sorted
        .get(rank.checked_sub(1).ok_or(Reason::MissingEvidence)?)
        .copied()
        .ok_or(Reason::MissingEvidence)
}
fn counters(s: &MetricSample) -> [u64; 6] {
    [
        s.cpu_usage_usec,
        s.memory_events_oom_kill,
        s.pids_events_max,
        s.cpu_nr_periods,
        s.cpu_nr_throttled,
        s.cpu_throttled_usec,
    ]
}
fn io_counters(s: &IoCounters) -> [u64; 4] {
    [s.read_bytes, s.write_bytes, s.read_ops, s.write_ops]
}
fn valid_series(samples: &[MetricSample]) -> bool {
    (2..=MAX_SAMPLES).contains(&samples.len())
        && samples.iter().all(|s| {
            s.io.len() <= 128
                && s.io
                    .windows(2)
                    .all(|p| (p[0].major, p[0].minor) < (p[1].major, p[1].minor))
                && (s.pss_bytes > 0
                    || (s.phase != SamplePhase::Active
                        && s.pids_current == 0
                        && s.memory_current == 0))
                && s.cpu_nr_throttled <= s.cpu_nr_periods
        })
        && samples.windows(2).all(|p| {
            p[0].elapsed_ms < p[1].elapsed_ms
                && counters(&p[0])
                    .iter()
                    .zip(counters(&p[1]))
                    .all(|(a, b)| *a <= b)
                && p[0].io.len() == p[1].io.len()
                && p[0].io.iter().zip(&p[1].io).all(|(a, b)| {
                    (a.major, a.minor) == (b.major, b.minor)
                        && io_counters(a)
                            .iter()
                            .zip(io_counters(b))
                            .all(|(a, b)| *a <= b)
                })
        })
}
pub fn summarize_resources(facts: &ResourceFacts) -> Result<ResourceSummary, Reason> {
    let samples = &facts.global.samples;
    if !valid_series(samples) {
        return Err(Reason::MissingEvidence);
    }
    let first = &samples[0];
    let last = &samples[samples.len() - 1];
    let elapsed = (last.elapsed_ms - first.elapsed_ms) as f64 / 1000.0;
    let ops = |write| -> f64 {
        first
            .io
            .iter()
            .zip(&last.io)
            .map(|(a, b)| {
                if write {
                    (b.write_ops - a.write_ops) as f64
                } else {
                    (b.read_ops - a.read_ops) as f64
                }
            })
            .sum::<f64>()
            / elapsed
    };
    let summary = ResourceSummary {
        peak_pss_bytes: samples.iter().map(|s| s.pss_bytes).max().unwrap(),
        peak_pids: samples.iter().map(|s| s.pids_current).max().unwrap(),
        sentinel_p99_us: nearest_rank_p99(
            &samples
                .iter()
                .map(|s| s.sentinel_latency_us)
                .collect::<Vec<_>>(),
        )?,
        read_iops: ops(false),
        write_iops: ops(true),
        minimum_host_mem_available_bytes: samples
            .iter()
            .map(|s| s.host_mem_available_bytes)
            .min()
            .unwrap(),
        cpu_throttled_periods: last.cpu_nr_throttled - first.cpu_nr_throttled,
        cpu_throttled_usec: last.cpu_throttled_usec - first.cpu_throttled_usec,
        total_cpu_usage_usec: last.cpu_usage_usec - first.cpu_usage_usec,
        startup_ms: facts.startup_ms,
        cleanup_ms: facts.cleanup_ms,
    };
    if !valid_summary(&summary) {
        return Err(Reason::MissingEvidence);
    }
    Ok(summary)
}
pub fn valid_summary(s: &ResourceSummary) -> bool {
    s.peak_pss_bytes > 0
        && s.peak_pids > 0
        && s.read_iops.is_finite()
        && s.write_iops.is_finite()
        && s.read_iops >= 0.0
        && s.write_iops >= 0.0
}
fn rank(reason: Reason) -> u8 {
    match reason {
        Reason::CleanupUnconfirmed => 5,
        Reason::BoundaryViolation | Reason::SloExceeded | Reason::DeadlineExceeded => 4,
        Reason::StaleEvidence => 3,
        _ => 1,
    }
}
fn note(error: &mut Option<Reason>, reason: Reason) {
    if error.is_none_or(|old| rank(reason) > rank(old)) {
        *error = Some(reason);
    }
}
fn above_rate(delta: u64, elapsed_ms: u64, limit_per_second: u64) -> bool {
    // The numerator always fits. If the allowed budget exceeds u128, no u64
    // counter delta could exceed it; saturation preserves that comparison.
    u128::from(delta) * 10000
        > u128::from(limit_per_second)
            .saturating_mul(u128::from(elapsed_ms))
            .saturating_mul(11)
}
fn enforce_scope(
    scope: &ScopedSamples,
    expected: &LimitReadback,
    key: &CaseKey,
    input: &ResourceInput,
    config: &NativeConfig,
    attempt: bool,
    error: &mut Option<Reason>,
) {
    if scope.limits.cgroup != expected.cgroup {
        note(error, Reason::StaleEvidence);
    }
    let mut actual = scope.limits.clone();
    actual.cgroup = expected.cgroup.clone();
    if actual != *expected {
        note(error, Reason::BoundaryViolation);
    }
    let samples = &scope.samples;
    for s in samples {
        if s.host_mem_available_bytes < config.minimum_production_memory_bytes
            || s.memory_current > expected.memory_max
            || s.pids_current > expected.pids_max
        {
            note(error, Reason::BoundaryViolation);
        }
    }
    if nearest_rank_p99(
        &samples
            .iter()
            .map(|s| s.sentinel_latency_us)
            .collect::<Vec<_>>(),
    )
    .is_ok_and(|p| u128::from(p) > u128::from(config.sentinel_p99_ms) * 1000)
    {
        note(error, Reason::SloExceeded);
    }
    let active: Vec<_> = samples
        .iter()
        .filter(|s| s.phase == SamplePhase::Active)
        .collect();
    if let (Some(first), Some(last)) = (active.first(), active.last()) {
        if let (Some(elapsed), Some(usage)) = (
            last.elapsed_ms.checked_sub(first.elapsed_ms),
            last.cpu_usage_usec.checked_sub(first.cpu_usage_usec),
        ) && u128::from(elapsed) * 1000 >= u128::from(expected.cpu_period_usec) * 10
            && u128::from(usage) * u128::from(expected.cpu_period_usec) * 10
                > u128::from(expected.cpu_quota_usec)
                    .saturating_mul(u128::from(elapsed))
                    .saturating_mul(11000)
        {
            note(error, Reason::BoundaryViolation);
        }
        if key.case == "cpu"
            && (last
                .cpu_nr_periods
                .checked_sub(first.cpu_nr_periods)
                .is_none_or(|periods| periods < 10)
                || (attempt
                    && (last.cpu_nr_throttled <= first.cpu_nr_throttled
                        || last.cpu_throttled_usec <= first.cpu_throttled_usec)))
        {
            note(error, Reason::MissingEvidence);
        }
        let sustained: Vec<_> = active
            .iter()
            .filter(|s| s.elapsed_ms.saturating_sub(first.elapsed_ms) >= input.io_warmup_ms)
            .collect();
        if let (Some(start), Some(end)) = (sustained.first(), sustained.last()) {
            let elapsed = end.elapsed_ms.saturating_sub(start.elapsed_ms);
            for bound in &expected.io {
                let find = |s: &MetricSample| {
                    s.io.iter()
                        .find(|io| (io.major, io.minor) == (bound.major, bound.minor))
                        .cloned()
                };
                if let (Some(a), Some(b)) = (find(start), find(end)) {
                    for ((before, after), limit) in
                        io_counters(&a).into_iter().zip(io_counters(&b)).zip([
                            bound.read_bps,
                            bound.write_bps,
                            bound.read_iops,
                            bound.write_iops,
                        ])
                    {
                        if let Some(delta) = after.checked_sub(before) {
                            if elapsed > 0 && above_rate(delta, elapsed, limit) {
                                note(error, Reason::BoundaryViolation);
                            }
                            if key.case == "io" && delta == 0 {
                                note(error, Reason::MissingEvidence);
                            }
                        }
                    }
                } else {
                    note(error, Reason::MissingEvidence);
                }
            }
            if elapsed == 0 {
                note(error, Reason::MissingEvidence);
            }
        } else {
            note(error, Reason::MissingEvidence);
        }
        if attempt
            && ((key.case == "memory-oom"
                && last.memory_events_oom_kill <= first.memory_events_oom_kill)
                || (key.case == "pids" && last.pids_events_max <= first.pids_events_max))
        {
            note(error, Reason::MissingEvidence);
        }
    }
    let devices: Vec<_> = expected.io.iter().map(|d| (d.major, d.minor)).collect();
    if !valid_series(samples)
        || active.len() < 10
        || samples
            .first()
            .is_none_or(|s| s.phase != SamplePhase::Before || s.elapsed_ms != 0)
        || samples.last().is_none_or(|s| s.phase != SamplePhase::After)
        || samples
            .iter()
            .skip(1)
            .take(samples.len().saturating_sub(2))
            .any(|s| s.phase != SamplePhase::Active)
        || samples
            .windows(2)
            .any(|p| p[1].elapsed_ms.checked_sub(p[0].elapsed_ms) != Some(SAMPLE_MS))
        || samples
            .iter()
            .any(|s| s.io.iter().map(|d| (d.major, d.minor)).collect::<Vec<_>>() != devices)
    {
        note(error, Reason::MissingEvidence);
    }
    if samples
        .last()
        .is_some_and(|s| s.elapsed_ms > input.workload_deadline_ms)
    {
        note(error, Reason::DeadlineExceeded);
    }
}

pub fn evaluate_resources(
    mode: EvidenceMode,
    key: &CaseKey,
    config: &NativeConfig,
    input: &ResourceInput,
    facts: &ResourceFacts,
) -> Result<Vec<Check>, Reason> {
    if mode != EvidenceMode::Fixture {
        return Err(Reason::BackendUnavailable);
    }
    config.validate()?;
    if !matches!(key.scenario, ScenarioId::S09 | ScenarioId::S16)
        || !required_cases().contains(key)
        || input.attempt_cgroups.len() != usize::from(key.concurrency)
        || input.attempt_cgroups.iter().collect::<BTreeSet<_>>().len()
            != input.attempt_cgroups.len()
        || input
            .attempt_cgroups
            .iter()
            .any(|p| !p.starts_with(&format!("{}/", input.global_cgroup)) || p.contains(".."))
        || input.global_cgroup.is_empty()
        || input.workload_deadline_ms == 0
        || input.workload_deadline_ms > config.max_case_ms
        || input.workload_deadline_ms > 300000
        || input.io_warmup_ms >= input.workload_deadline_ms
        || key.concurrency > config.max_parallel_builds
    {
        return Err(Reason::InvalidConfig);
    }
    let global = parse_limit_readback(
        &input.global_cgroup,
        &config
            .execution_resources
            .global
            .validate()
            .map_err(|_| Reason::InvalidConfig)?
            .writes(),
    )?;
    let attempt_writes = config
        .execution_resources
        .attempt
        .validate()
        .map_err(|_| Reason::InvalidConfig)?
        .writes();
    let mut error = None;
    if !facts.cleanup_confirmed {
        note(&mut error, Reason::CleanupUnconfirmed);
    }
    if key.case == "memory-oom" && !facts.oom_contained {
        note(&mut error, Reason::BoundaryViolation);
    }
    if facts.cleanup_ms > config.cleanup_deadline_ms
        || facts.startup_ms > input.workload_deadline_ms
    {
        note(&mut error, Reason::DeadlineExceeded);
    }
    if global.memory_max > config.maximum_chimera_memory_bytes
        || global.pids_max > config.maximum_chimera_pids
    {
        return Err(Reason::InvalidConfig);
    }
    if facts
        .baseline
        .iter()
        .any(|s| s.host_mem_available_bytes < config.minimum_production_memory_bytes)
    {
        note(&mut error, Reason::BoundaryViolation);
    }
    if nearest_rank_p99(
        &facts
            .baseline
            .iter()
            .map(|s| s.latency_us)
            .collect::<Vec<_>>(),
    )
    .is_ok_and(|p| u128::from(p) > u128::from(config.sentinel_p99_ms) * 1000)
    {
        note(&mut error, Reason::SloExceeded);
    }
    if facts.baseline.len() != 41
        || facts
            .baseline
            .iter()
            .enumerate()
            .any(|(i, s)| s.elapsed_ms != i as u64 * SAMPLE_MS)
    {
        note(&mut error, Reason::MissingEvidence);
    }
    enforce_scope(
        &facts.global,
        &global,
        key,
        input,
        config,
        false,
        &mut error,
    );
    let expected_paths: BTreeSet<_> = input.attempt_cgroups.iter().collect();
    let observed_paths: BTreeSet<_> = facts.attempts.iter().map(|s| &s.limits.cgroup).collect();
    if !observed_paths.is_subset(&expected_paths) {
        note(&mut error, Reason::StaleEvidence);
    }
    if facts.attempts.len() != input.attempt_cgroups.len() || observed_paths != expected_paths {
        note(&mut error, Reason::MissingEvidence);
    }
    for scope in &facts.attempts {
        let expected = parse_limit_readback(&scope.limits.cgroup, &attempt_writes)?;
        enforce_scope(scope, &expected, key, input, config, true, &mut error);
        if scope
            .samples
            .iter()
            .map(|s| (s.elapsed_ms, s.phase))
            .collect::<Vec<_>>()
            != facts
                .global
                .samples
                .iter()
                .map(|s| (s.elapsed_ms, s.phase))
                .collect::<Vec<_>>()
        {
            note(&mut error, Reason::MissingEvidence);
        }
    }
    if !facts.expected_work_completed
        || (key.case == "memory-oom" && !facts.oom_contained)
        || (key.case == "pids" && !facts.pid_limit_hit)
        || (key.case == "cpu" && !facts.cpu_saturation_completed)
        || (key.case == "io" && !facts.io_saturation_completed)
        || global.io.is_empty()
        || config.execution_resources.attempt.io_max.is_empty()
    {
        note(&mut error, Reason::MissingEvidence);
    }
    if let Err(reason) = summarize_resources(facts) {
        note(&mut error, reason);
    }
    if let Some(reason) = error {
        return Err(reason);
    }
    Ok(required_checks(key)
        .iter()
        .map(|id| Check {
            id: *id,
            passed: true,
        })
        .collect())
}
