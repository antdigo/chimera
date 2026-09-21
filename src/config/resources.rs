use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

const CPU_PERIOD_MICROSECONDS: u64 = 100_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionResources {
    pub global: ResourceLimits,
    pub attempt: ResourceLimits,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    pub memory_high: String,
    pub memory_max: String,
    pub memory_swap_max: String,
    pub cpu_quota: String,
    pub cpu_weight: u16,
    pub pids_max: String,
    pub io_weight: u16,
    #[serde(default)]
    pub io_max: Vec<IoMax>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IoMax {
    pub device: String,
    pub read_bytes_per_second: String,
    pub write_bytes_per_second: String,
    pub read_iops: u64,
    pub write_iops: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedLimits {
    writes: Vec<(&'static str, String)>,
}

impl ValidatedLimits {
    pub fn writes(&self) -> Vec<(&'static str, String)> {
        self.writes.clone()
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ResourceConfigError {
    #[error("invalid resource limit for {field}")]
    InvalidValue { field: &'static str },
    #[error("memory_high must not exceed memory_max")]
    MemoryOrder,
    #[error("duplicate io_max device")]
    DuplicateDevice,
}

impl ResourceLimits {
    pub fn validate(&self) -> Result<ValidatedLimits, ResourceConfigError> {
        let memory_high = parse_bytes(&self.memory_high, "memory_high", false)?;
        let memory_max = parse_bytes(&self.memory_max, "memory_max", false)?;
        if memory_high > memory_max {
            return Err(ResourceConfigError::MemoryOrder);
        }
        let memory_swap_max = parse_bytes(&self.memory_swap_max, "memory_swap_max", true)?;
        let cpu_quota = parse_cpu_quota(&self.cpu_quota)?;
        validate_weight(self.cpu_weight, "cpu_weight")?;
        let pids_max = parse_decimal(&self.pids_max, "pids_max", false)?;
        validate_weight(self.io_weight, "io_weight")?;

        let mut devices = HashSet::new();
        let mut io_lines = Vec::with_capacity(self.io_max.len());
        for limit in &self.io_max {
            let device = parse_device(&limit.device)?;
            if !devices.insert(device) {
                return Err(ResourceConfigError::DuplicateDevice);
            }
            let read_bytes = parse_bytes(
                &limit.read_bytes_per_second,
                "io_max.read_bytes_per_second",
                false,
            )?;
            let write_bytes = parse_bytes(
                &limit.write_bytes_per_second,
                "io_max.write_bytes_per_second",
                false,
            )?;
            if limit.read_iops == 0 {
                return Err(invalid("io_max.read_iops"));
            }
            if limit.write_iops == 0 {
                return Err(invalid("io_max.write_iops"));
            }
            io_lines.push((
                device,
                format!(
                    "{}:{} rbps={read_bytes} wbps={write_bytes} riops={} wiops={}",
                    device.0, device.1, limit.read_iops, limit.write_iops
                ),
            ));
        }
        io_lines.sort_unstable_by_key(|(device, _)| *device);

        let mut writes = vec![
            ("memory.high", memory_high.to_string()),
            ("memory.max", memory_max.to_string()),
            ("memory.swap.max", memory_swap_max.to_string()),
            ("cpu.max", format!("{cpu_quota} {CPU_PERIOD_MICROSECONDS}")),
            ("cpu.weight", self.cpu_weight.to_string()),
            ("pids.max", pids_max.to_string()),
            ("io.weight", format!("default {}", self.io_weight)),
        ];
        writes.extend(io_lines.into_iter().map(|(_, line)| ("io.max", line)));

        Ok(ValidatedLimits { writes })
    }
}

fn parse_bytes(
    value: &str,
    field: &'static str,
    allow_zero: bool,
) -> Result<u64, ResourceConfigError> {
    let (number, multiplier) = match value.split_once(' ') {
        Some((number, suffix)) if !number.is_empty() && !suffix.contains(' ') => {
            let multiplier = match suffix {
                "B" => 1,
                "KiB" => 1_u64 << 10,
                "MiB" => 1_u64 << 20,
                "GiB" => 1_u64 << 30,
                "TiB" => 1_u64 << 40,
                _ => return Err(invalid(field)),
            };
            (number, multiplier)
        }
        Some(_) => return Err(invalid(field)),
        None => (value, 1),
    };
    let number = parse_decimal(number, field, allow_zero)?;
    number.checked_mul(multiplier).ok_or_else(|| invalid(field))
}

fn parse_cpu_quota(value: &str) -> Result<u64, ResourceConfigError> {
    let percent = value
        .strip_suffix('%')
        .ok_or_else(|| invalid("cpu_quota"))?;
    let percent = parse_decimal(percent, "cpu_quota", false)?;
    percent
        .checked_mul(1_000)
        .ok_or_else(|| invalid("cpu_quota"))
}

fn parse_decimal(
    value: &str,
    field: &'static str,
    allow_zero: bool,
) -> Result<u64, ResourceConfigError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid(field));
    }
    let parsed = value.parse::<u64>().map_err(|_| invalid(field))?;
    if !allow_zero && parsed == 0 {
        return Err(invalid(field));
    }
    Ok(parsed)
}

fn validate_weight(value: u16, field: &'static str) -> Result<(), ResourceConfigError> {
    if !(1..=10_000).contains(&value) {
        return Err(invalid(field));
    }
    Ok(())
}

fn parse_device(value: &str) -> Result<(u32, u32), ResourceConfigError> {
    let (major, minor) = value
        .split_once(':')
        .ok_or_else(|| invalid("io_max.device"))?;
    if minor.contains(':') {
        return Err(invalid("io_max.device"));
    }
    let major = parse_u32(major, "io_max.device")?;
    let minor = parse_u32(minor, "io_max.device")?;
    Ok((major, minor))
}

fn parse_u32(value: &str, field: &'static str) -> Result<u32, ResourceConfigError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid(field));
    }
    value.parse::<u32>().map_err(|_| invalid(field))
}

fn invalid(field: &'static str) -> ResourceConfigError {
    ResourceConfigError::InvalidValue { field }
}
