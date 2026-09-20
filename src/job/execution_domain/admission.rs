use std::sync::Arc;

use super::{AttemptIdentity, ExecutionDomain, ExecutionDomainError, ExecutionDomainRoot};
use tokio::sync::OwnedSemaphorePermit;

/// Reserved capacity that is returned if provisioning is cancelled or fails.
#[derive(Debug)]
pub struct DomainPermit {
    root: ExecutionDomainRoot,
    permit: OwnedSemaphorePermit,
}

impl DomainPermit {
    pub async fn provision(
        self,
        attempt: AttemptIdentity,
    ) -> Result<ExecutionDomain, ExecutionDomainError> {
        super::manager::DomainManager::spawn(self.root, self.permit, attempt).await
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
