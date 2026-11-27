//! Experimental native UDP transport for LEStra.
//!
//! Provides non-blocking UDP I/O, bounded framing validation,
//! and client handshake scheduling without an async runtime.
//!
//! Server admission, session routing, amplification accounting,
//! established session scheduling and congestion response
//! remain unimplemented.

mod client;
mod socket;
mod timer;

pub use client::{ConnectError, ConnectStatus, UdpClient};
pub use socket::{IncomingDatagram, UdpIo};
