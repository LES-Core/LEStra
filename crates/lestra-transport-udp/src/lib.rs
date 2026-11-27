//! Experimental native UDP transport for LEStra.
//!
//! Provides non-blocking UDP I/O, client handshake scheduling,
//! managed client connections, server-side session routing,
//! bounded INITIAL admission, amplification accounting,
//! session expiration and fixed-rate DATA transmission limits.
//!
//! Adaptive congestion control, multi-identity authorization
//! and production hardening remain incomplete.

mod admission;
mod amplification;
mod client;
mod config;
mod connection;
mod initial_cache;
mod pacing;
mod send_queue;
mod server;
mod session_table;
mod socket;
mod timer;

pub use admission::{AdmissionGate, AdmissionLimits};

pub use amplification::{AMPLIFICATION_FACTOR, AmplificationBudget};

pub use client::{ConnectError, ConnectStatus, UdpClient};

pub use config::{ClientConfig, ServerConfig, SessionTimeouts};

pub use connection::{ConnectionCloseReason, ConnectionEvent, UdpConnection};

pub use pacing::{DataPacingConfig, PacingLimit};

pub use server::{ServerEvent, UdpServer};

pub use session_table::{
    ConnectionId, ExpirationReason, RouteEvent, SessionTable, SessionTableError,
};

pub use send_queue::FlushStatus;

pub use socket::{IncomingDatagram, UdpIo};
