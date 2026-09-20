use std::sync::Arc;

use tokio::sync::OwnedSemaphorePermit;
use uuid::Uuid;

use super::{ExecutionDomain, ExecutionDomainError, ExecutionDomainRoot};

/// Reserved capacity that is returned if provisioning is cancelled or fails.
#[derive(Debug)]
pub struct DomainPermit {
    root: ExecutionDomainRoot,
    permit: OwnedSemaphorePermit,
}

impl DomainPermit {
    pub fn provision(self) -> Result<ExecutionDomain, ExecutionDomainError> {
        let mut domain = self.root.create_domain_with_id(Uuid::new_v4())?;
        domain.admission_permit = Some(self.permit);
        Ok(domain)
    }
}

impl ExecutionDomainRoot {
    pub async fn reserve(&self) -> Result<DomainPermit, ExecutionDomainError> {
        // Subscribe before checking health so poison cannot be missed between
        // the initial check and registration of a blocked waiter.
        let mut poisoned = self.poisoned_receiver();
        self.ensure_healthy()?;
        let permit = tokio::select! {
            _ = poisoned.changed() => {
                return Err(ExecutionDomainError::PoisonedRoot {
                    path: self.path().to_path_buf(),
                });
            }
            permit = Arc::clone(&self.admission).acquire_owned() => {
                permit.map_err(|_| ExecutionDomainError::AdmissionClosed {
                    path: self.path().to_path_buf(),
                })?
            }
        };
        // Poison and capacity may become ready together. Never hand that
        // capacity to a caller after the root has failed.
        self.ensure_healthy()?;
        Ok(DomainPermit {
            root: self.clone(),
            permit,
        })
    }
}
