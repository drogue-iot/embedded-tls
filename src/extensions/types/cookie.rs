use crate::{
    buffer::CryptoBuffer,
    extensions::ExtensionType,
    parse_buffer::{ParseBuffer, ParseError},
    TlsError,
};

pub struct Cookie<'a> {
    pub cookie: &'a [u8],
}

impl<'a> Cookie<'a> {
    pub const EXTENSION_TYPE: ExtensionType = ExtensionType::Cookie;

    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        let data_length = buf.read_u16()? as usize;
        let cookie = buf.slice(data_length)?.as_slice();
        Ok(Self { cookie })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u16_length(|buf| buf.extend_from_slice(self.cookie))
    }
}
