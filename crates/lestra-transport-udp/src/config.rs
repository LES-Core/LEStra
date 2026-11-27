use crate::AdmissionLimits;

/// Experimental native UDP server configuration.
#[derive(Clone, Copy, Debug)]
pub struct ServerConfig {
    pub max_sessions: usize,
    pub max_pending: usize,
    pub max_initial_cache: usize,
    pub admission: AdmissionLimits,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_sessions: 10_000,
            max_pending: 4096,
            max_initial_cache: 8192,
            admission: AdmissionLimits::default(),
        }
    }
}
