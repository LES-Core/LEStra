//! Experimental native UDP transport for LEStra.
//!
//! Provides non-blocking UDP I/O, client handshake scheduling,
//! server-side session routing, bounded INITIAL admission,
//! amplification accounting and secure datagram exchange.
//!
//! Established session timeouts, multi-identity authorization,
//! congestion response and production hardening remain incomplete.

mod admission;
mod amplification;
mod client;
mod config;
mod initial_cache;
mod server;
mod session_table;
mod socket;
mod timer;

pub use admission::{AdmissionGate, AdmissionLimits};

pub use amplification::{AMPLIFICATION_FACTOR, AmplificationBudget};

pub use client::{ConnectError, ConnectStatus, UdpClient};

pub use config::{ServerConfig, SessionTimeouts};

pub use server::{ServerEvent, UdpServer};

pub use session_table::{
    ConnectionId, ExpirationReason, RouteEvent, SessionTable, SessionTableError,
};

pub use socket::{IncomingDatagram, UdpIo};
