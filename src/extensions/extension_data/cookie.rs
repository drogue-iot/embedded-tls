use crate::{
    buffer::CryptoBuffer,
    parse_buffer::{
        ParseBuffer,
        ParseError,
    },
    TlsError,
};

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Cookie<'a> {
    pub cookie: &'a [u8],
}

impl<'a> Cookie<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        let data_length = buf.read_u16()? as usize;
        let cookie = buf.slice(data_length)?.as_slice();
        Ok(Self { cookie })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u16_length(|buf| buf.extend_from_slice(self.cookie))
    }
}
