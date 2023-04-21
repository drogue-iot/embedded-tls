// When a PSK is used and early data is allowed for that PSK, the client
// can send Application Data in its first flight of messages.  If the
// client opts to do so, it MUST supply both the "pre_shared_key" and
// "early_data" extensions.
//
// The "extension_data" field of this extension contains an
// "EarlyDataIndication" value.

use crate::{
    buffer::CryptoBuffer,
    parse_buffer::{ParseBuffer, ParseError},
    TlsError,
};

pub struct EarlyDataIndication;

impl EarlyDataIndication {
    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        if !buf.is_empty() {
            return Err(ParseError::InvalidData);
        }

        Ok(EarlyDataIndication)
    }

    pub fn encode(&self, _buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        Ok(())
    }
}

pub struct EarlyDataIndicationInNewSessionTicket {
    pub max_early_data_size: u32,
}

impl EarlyDataIndicationInNewSessionTicket {
    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        Ok(Self {
            max_early_data_size: buf.read_u32()?,
        })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.push_u32(self.max_early_data_size)
    }
}
