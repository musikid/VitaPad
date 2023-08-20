use bytes::{Buf, BytesMut};
use flatbuffers_structs::{flatbuffers, net_protocol::PacketContent};
use tokio_util::codec::Decoder;

use crate::events::Event;

pub struct PadCodec {
    size: Option<usize>,
}

impl Decoder for PadCodec {
    type Item = Event;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        const OFFSET_SIZE: usize = std::mem::size_of::<flatbuffers::UOffsetT>();

        if self.size.is_none() {
            if src.len() < OFFSET_SIZE {
                return Ok(None);
            }

            self.size = Some(flatbuffers::UOffsetT::from_le_bytes(
                src[..OFFSET_SIZE].try_into().unwrap(),
            ) as usize);
            src.advance(OFFSET_SIZE);
        }

        let len = self.size.unwrap();
        if src.len() < len {
            return Ok(None);
        }

        let packet = flatbuffers_structs::net_protocol::root_as_packet(&src[..len])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let event = match packet.content_type() {
            PacketContent::Pad => {
                let pad = packet.content_as_pad().ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::Other, "Packet content is not pad data")
                })?;
                let pad = pad.try_into().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Invalid pad data: {}", e),
                    )
                })?;
                Some(Event::PadDataReceived { data: pad })
            }
            _ => None,
        };

        src.advance(len);
        Ok(event)
    }
}
