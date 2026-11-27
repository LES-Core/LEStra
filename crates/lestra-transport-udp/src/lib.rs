//! Experimental native UDP transport for LEStra.
//!
//! Provides non-blocking UDP I/O, bounded framing validation,
//! client handshake scheduling, server-side session routing,
//! INITIAL rate limiting and amplification budget primitives.
//!
//! Full server admission integration, session timeouts
//! and congestion response remain unimplemented.

mod admission;
mod amplification;
mod client;
mod session_table;
mod socket;
mod timer;

pub use admission::{AdmissionGate, AdmissionLimits};

pub use amplification::{AMPLIFICATION_FACTOR, AmplificationBudget};

pub use client::{ConnectError, ConnectStatus, UdpClient};

pub use session_table::{ConnectionId, RouteEvent, SessionTable, SessionTableError};

pub use socket::{IncomingDatagram, UdpIo};
