//! Experimental native UDP transport for LEStra.
//!
//! Provides non-blocking UDP I/O and bounded packet
//! framing validation without requiring an async runtime.
//!
//! Framing validation does not authenticate packets.
//!
//! Session routing, handshake scheduling, admission control,
//! amplification accounting and congestion response
//! remain unimplemented.

mod socket;

pub use socket::{IncomingDatagram, UdpIo};
