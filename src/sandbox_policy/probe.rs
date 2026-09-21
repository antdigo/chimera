use std::net::SocketAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::sandbox_policy::PolicyError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectOutcome {
    Connected,
    Refused,
    TimedOut,
    Denied,
    Unreachable,
}

pub async fn probe_connect(
    address: SocketAddr,
    deadline: Duration,
) -> Result<ConnectOutcome, PolicyError> {
    match timeout(deadline, TcpStream::connect(address)).await {
        Ok(Ok(_)) => Ok(ConnectOutcome::Connected),
        Err(_) => Ok(ConnectOutcome::TimedOut),
        Ok(Err(error)) => match error.kind() {
            std::io::ErrorKind::PermissionDenied => Ok(ConnectOutcome::Denied),
            std::io::ErrorKind::ConnectionRefused => Ok(ConnectOutcome::Refused),
            std::io::ErrorKind::TimedOut => Ok(ConnectOutcome::TimedOut),
            _ if matches!(error.raw_os_error(), Some(51 | 65 | 100 | 101 | 113)) => {
                Ok(ConnectOutcome::Unreachable)
            }
            _ => Err(PolicyError::Io(error)),
        },
    }
}

#[cfg(test)]
#[path = "probe_test.rs"]
mod probe_test;
