use std::time::Duration;

use crate::{AdmissionLimits, DataPacingConfig, PacingLimit};

/// Established session lifetime policy.
///
/// A zero duration causes immediate expiration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionTimeouts {
    pub idle_timeout: Duration,
    pub max_lifetime: Duration,
}

impl Default for SessionTimeouts {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(60),
            max_lifetime: Duration::from_secs(3600),
        }
    }
}

/// Experimental native UDP server configuration.
#[derive(Clone, Copy, Debug)]
pub struct ServerConfig {
    pub max_sessions: usize,
    pub max_pending: usize,
    pub max_initial_cache: usize,
    pub admission: AdmissionLimits,
    pub timeouts: SessionTimeouts,
    pub pacing: DataPacingConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_sessions: 10_000,
            max_pending: 4096,
            max_initial_cache: 8192,
            admission: AdmissionLimits::default(),
            timeouts: SessionTimeouts::default(),
            pacing: DataPacingConfig::default(),
        }
    }
}

/// Established UDP client configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientConfig {
    pub timeouts: SessionTimeouts,
    pub pacing: PacingLimit,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            timeouts: SessionTimeouts::default(),

            pacing: DataPacingConfig::default().per_session,
        }
    }
}
