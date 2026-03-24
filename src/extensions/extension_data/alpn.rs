use crate::{
    TlsError,
    buffer::CryptoBuffer,
    parse_buffer::{ParseBuffer, ParseError},
};

/// ALPN protocol name list per RFC 7301, Section 3.1.
///
/// Wire format:
/// ```text
/// opaque ProtocolName<1..2^8-1>;
///
/// struct {
///     ProtocolName protocol_name_list<2..2^16-1>
/// } ProtocolNameList;
/// ```
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AlpnProtocolNameList<'a> {
    pub protocols: heapless::Vec<&'a [u8], 4>,
}

impl<'a> AlpnProtocolNameList<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        let list_len = buf.read_u16()? as usize;
        let mut list_buf = buf.slice(list_len)?;

        let mut protocols = heapless::Vec::new();
        while !list_buf.is_empty() {
            let name_len = list_buf.read_u8()? as usize;
            if name_len == 0 {
                return Err(ParseError::InvalidData);
            }
            let name = list_buf.slice(name_len)?;
            let _ = protocols.push(name.as_slice());
        }

        Ok(Self { protocols })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        // Outer u16 length prefix for the ProtocolNameList
        buf.with_u16_length(|buf| {
            for protocol in &self.protocols {
                buf.push(protocol.len() as u8)
                    .map_err(|_| TlsError::EncodeError)?;
                buf.extend_from_slice(protocol)?;
            }
            Ok(())
        })
    }
}
