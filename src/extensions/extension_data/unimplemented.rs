use crate::{
    TlsError,
    buffer::CryptoBuffer,
    parse_buffer::{ParseBuffer, ParseError},
};

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Unimplemented<'a> {
    pub data: &'a [u8],
}

impl<'a> Unimplemented<'a> {
    #[allow(clippy::unnecessary_wraps)]
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        Ok(Self {
            data: buf.as_slice(),
        })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.extend_from_slice(self.data)
    }
}
