use std::{
    io,
    net::{SocketAddr, UdpSocket},
};

use lestra_codec::{CodecError, PacketHeader, decode_packet};

const RECEIVE_BUFFER_SIZE: usize = 65_535;

/// Result of receiving and validating a UDP datagram.
///
/// Successful framing validation does not authenticate
/// the remote peer or the packet contents.
#[derive(Debug)]
pub enum IncomingDatagram<'a> {
    Packet {
        source: SocketAddr,
        header: PacketHeader,
        bytes: &'a [u8],
    },

    Rejected {
        source: SocketAddr,
        error: CodecError,
    },
}

/// Non-blocking native UDP socket.
///
/// Owns a reusable receive buffer. Does not perform
/// authentication, session routing or retransmission.
pub struct UdpIo {
    socket: UdpSocket,
    receive_buffer: Box<[u8]>,
}

impl UdpIo {
    /// Bind a non-blocking UDP socket.
    pub fn bind(address: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(address)?;

        socket.set_nonblocking(true)?;

        Ok(Self {
            socket,
            receive_buffer: vec![0_u8; RECEIVE_BUFFER_SIZE].into_boxed_slice(),
        })
    }

    /// Return the bound local socket address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Send one syntactically valid LEStra datagram.
    ///
    /// WouldBlock means the caller must retry later
    /// using the same serialized packet bytes.
    ///
    /// Successful transmission does not imply delivery.
    pub fn send_to(&self, destination: SocketAddr, bytes: &[u8]) -> io::Result<()> {
        decode_packet(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

        let written = self.socket.send_to(bytes, destination)?;

        if written != bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "incomplete UDP datagram transmission",
            ));
        }

        Ok(())
    }

    /// Poll for one incoming UDP datagram.
    ///
    /// Returns None when no datagram is available.
    /// Invalid framing is reported as Rejected.
    ///
    /// Returned packet bytes borrow the internal
    /// receive buffer until the next receive operation.
    pub fn poll_recv(&mut self) -> io::Result<Option<IncomingDatagram<'_>>> {
        let (len, source) = match self.socket.recv_from(&mut self.receive_buffer) {
            Ok(received) => received,

            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Ok(None);
            }

            Err(error) => return Err(error),
        };

        let bytes = &self.receive_buffer[..len];

        let incoming = match decode_packet(bytes) {
            Ok(packet) => IncomingDatagram::Packet {
                source,
                header: packet.header,
                bytes,
            },

            Err(error) => IncomingDatagram::Rejected { source, error },
        };

        Ok(Some(incoming))
    }
}
