use heapless::Vec;

use crate::{
    buffer::CryptoBuffer,
    parse_buffer::{ParseBuffer, ParseError},
    TlsError,
};

pub struct ProtocolName<'a> {
    pub name: &'a str,
}

impl<'a> ProtocolName<'a> {
    // RFC 7301, Section 6.  IANA Considerations
    // The initial set of registrations for this registry is as follows:
    pub const HTTP_1_1: Self = Self { name: "http/1.1" };
    pub const SPDY_1: Self = Self { name: "spdy/1" };
    pub const SPDY_2: Self = Self { name: "spdy/2" };
    pub const SPDY_3: Self = Self { name: "spdy/3" };

    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        let str_len = buf.read_u8()?;
        let str_bytes = buf.slice(str_len as usize)?.as_slice();

        if str_bytes.is_ascii() {
            core::str::from_utf8(str_bytes)
                .map(|name| Self { name })
                .map_err(|_| ParseError::InvalidData)
        } else {
            Err(ParseError::InvalidData)
        }
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u8_length(|buf| buf.extend_from_slice(self.name.as_bytes()))
    }
}

pub struct ApplicationLayerProtocolNegotiation<'a, const N: usize> {
    // Note: server response must contain a single protocol name.
    pub protocol_name_list: Vec<ProtocolName<'a>, N>,
}

impl<'a, const N: usize> ApplicationLayerProtocolNegotiation<'a, N> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        let data_length = buf.read_u16()? as usize;

        Ok(Self {
            protocol_name_list: buf.read_list::<_, N>(data_length, ProtocolName::parse)?,
        })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u16_length(|buf| {
            for name in self.protocol_name_list.iter() {
                name.encode(buf)?;
            }
            Ok(())
        })
    }
}
