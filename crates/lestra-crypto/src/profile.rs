use lestra_codec as v1;

use lestra_codec::{
    CodecError, HEADER_LEN,
    v2::{self, DecodedPacket, PacketHeader},
};

/// Explicitly selected experimental native UDP profile.
///
/// The profile is fixed for the entire Noise session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireProfile {
    V1,
    V2,
}

impl WireProfile {
    pub const fn wire_major(self) -> u8 {
        match self {
            Self::V1 => v1::DRAFT_WIRE_MAJOR,
            Self::V2 => v2::DRAFT_WIRE_MAJOR,
        }
    }

    pub const fn supports_ack(self) -> bool {
        matches!(self, Self::V2)
    }

    pub(crate) const fn prologue(self) -> &'static [u8] {
        match self {
            Self::V1 => b"LEStra/native-udp/v1",
            Self::V2 => b"LEStra/native-udp/v2",
        }
    }

    pub(crate) fn decode_packet(self, bytes: &[u8]) -> Result<DecodedPacket<'_>, CodecError> {
        match self {
            Self::V1 => {
                let packet = v1::decode_packet(bytes)?;

                Ok(DecodedPacket {
                    header: PacketHeader {
                        kind: v2::PacketType::try_from(packet.header.kind as u8)?,

                        destination_connection_id: packet.header.destination_connection_id,

                        packet_number: packet.header.packet_number,
                    },

                    raw_header: packet.raw_header,
                    body: packet.body,
                })
            }

            Self::V2 => v2::decode_packet(bytes),
        }
    }

    fn legacy_header(header: PacketHeader) -> Result<v1::PacketHeader, CodecError> {
        Ok(v1::PacketHeader {
            kind: v1::PacketType::try_from(header.kind as u8)?,

            destination_connection_id: header.destination_connection_id,

            packet_number: header.packet_number,
        })
    }

    pub(crate) fn encode_header(
        self,
        header: PacketHeader,
        body_len: usize,
        output: &mut [u8; HEADER_LEN],
    ) -> Result<(), CodecError> {
        match self {
            Self::V1 => v1::encode_header(Self::legacy_header(header)?, body_len, output),

            Self::V2 => v2::encode_header(header, body_len, output),
        }
    }

    pub(crate) fn encode_packet_into<'a>(
        self,
        header: PacketHeader,
        body: &[u8],
        output: &'a mut [u8],
    ) -> Result<&'a [u8], CodecError> {
        match self {
            Self::V1 => v1::encode_packet_into(Self::legacy_header(header)?, body, output),

            Self::V2 => v2::encode_packet_into(header, body, output),
        }
    }
}
