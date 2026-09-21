use std::fmt;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::cache::auth::{CacheAuthority, CapabilityHandle};

use super::PolicyError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityService {
    Cache,
    Artifact,
    Deploy,
}

pub struct CapabilityDescriptor {
    pub attempt_id: Uuid,
    pub service: CapabilityService,
    pub grant_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub local_path: String,
}

pub fn validate_descriptor(
    descriptor: &CapabilityDescriptor,
    attempt: Uuid,
    now: DateTime<Utc>,
) -> Result<(), PolicyError> {
    if attempt.is_nil()
        || descriptor.attempt_id.is_nil()
        || descriptor.grant_id.is_nil()
        || descriptor.attempt_id != attempt
        || descriptor.expires_at <= now
        || descriptor.local_path
            != format!("/run/chimera/capabilities/{}.sock", descriptor.grant_id)
    {
        return Err(PolicyError::InvalidCapabilityDescriptor);
    }

    Ok(())
}

pub struct CacheCapabilityBinding {
    attempt_id: Uuid,
    handle: CapabilityHandle,
}

impl CacheCapabilityBinding {
    pub fn new(attempt_id: Uuid, handle: CapabilityHandle) -> Result<Self, PolicyError> {
        if attempt_id.is_nil() {
            return Err(PolicyError::InvalidCapabilityDescriptor);
        }

        Ok(Self { attempt_id, handle })
    }

    pub fn attempt_id(&self) -> Uuid {
        self.attempt_id
    }

    pub async fn revoke(self, authority: &CacheAuthority) {
        authority.revoke(&self.handle).await;
    }
}

impl fmt::Debug for CacheCapabilityBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CacheCapabilityBinding([redacted])")
    }
}
