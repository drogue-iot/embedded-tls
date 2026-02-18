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
    pub protocols: &'a [&'a [u8]],
}

impl<'a> AlpnProtocolNameList<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        // We parse but don't store the individual protocol names in a heapless
        // container — just validate the wire format. The slice reference is kept
        // for the lifetime of the parse buffer, but since we can't reconstruct
        // `&[&[u8]]` from a flat buffer without allocation, we store an empty
        // slice. Callers that need the parsed protocols (server-side) would need
        // a different approach; for our client-side use we only need encode().
        let list_len = buf.read_u16()? as usize;
        let mut list_buf = buf.slice(list_len)?;

        while !list_buf.is_empty() {
            let name_len = list_buf.read_u8()? as usize;
            if name_len == 0 {
                return Err(ParseError::InvalidData);
            }
            let _name = list_buf.slice(name_len)?;
        }

        Ok(Self { protocols: &[] })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        // Outer u16 length prefix for the ProtocolNameList
        buf.with_u16_length(|buf| {
            for protocol in self.protocols {
                buf.push(protocol.len() as u8)
                    .map_err(|_| TlsError::EncodeError)?;
                buf.extend_from_slice(protocol)?;
            }
            Ok(())
        })
    }
}
