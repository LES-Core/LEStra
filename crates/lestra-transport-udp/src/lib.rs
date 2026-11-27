//! Experimental native UDP transport for LEStra.
//!
//! Provides non-blocking UDP I/O, bounded framing validation,
//! client handshake scheduling and server-side session routing
//! without requiring an async runtime.
//!
//! INITIAL admission, amplification accounting,
//! established session timeouts and congestion response
//! remain unimplemented.

mod client;
mod session_table;
mod socket;
mod timer;

pub use client::{ConnectError, ConnectStatus, UdpClient};

pub use session_table::{ConnectionId, RouteEvent, SessionTable, SessionTableError};

pub use socket::{IncomingDatagram, UdpIo};
