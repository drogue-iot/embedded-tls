// RFC 7685, Section 3.  Padding Extension
// The "extension_data" for the extension consists of an arbitrary
// number of zero bytes.  For example, the smallest "padding" extension
// is four bytes long and is encoded as 0x00 0x15 0x00 0x00.  A ten-byte
// extension would include six bytes of "extension_data" and would be
// encoded as:
//
// 00 15 00 06 00 00 00 00 00 00
// |---| |---| |---------------|
//   |     |           |
//   |     |           \- extension_data: 6 zero bytes
//   |     |
//   |     \------------- 16-bit, extension_data length
//   |
//   \------------------- extension_type for padding extension

use crate::{
    buffer::CryptoBuffer,
    extensions::ExtensionType,
    parse_buffer::{ParseBuffer, ParseError},
    TlsError,
};

pub struct Padding {
    pub zero_count: u16,
}

impl Padding {
    pub const EXTENSION_TYPE: ExtensionType = ExtensionType::Padding;

    pub fn parse<'a>(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        let data_length = buf.remaining();

        // The client MUST fill the padding extension completely with zero
        // bytes, although the padding extension_data field may be empty.
        if buf.as_slice().iter().any(|b| *b != 0) {
            return Err(ParseError::InvalidData);
        }

        Ok(Self {
            zero_count: data_length as u16,
        })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        for _ in 0..self.zero_count {
            buf.push(0)?;
        }
        Ok(())
    }
}
