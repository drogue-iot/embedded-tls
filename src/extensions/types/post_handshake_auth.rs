use crate::{
    buffer::CryptoBuffer,
    extensions::ExtensionType,
    parse_buffer::{ParseBuffer, ParseError},
    TlsError,
};

// RFC 8446, Section 4.2.6.  Post-Handshake Client Authentication
// struct {} PostHandshakeAuth;
// The "extension_data" field of the "post_handshake_auth" extension is
// zero length.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PostHandshakeAuth;

impl PostHandshakeAuth {
    pub const EXTENSION_TYPE: ExtensionType = ExtensionType::PostHandshakeAuth;

    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        if !buf.is_empty() {
            Err(ParseError::InvalidData)
        } else {
            Ok(Self)
        }
    }

    pub fn encode(&self, _buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        Ok(())
    }
}
