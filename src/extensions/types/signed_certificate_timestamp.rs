use heapless::Vec;

use crate::{
    buffer::CryptoBuffer,
    extensions::ExtensionType,
    parse_buffer::{ParseBuffer, ParseError},
    TlsError,
};

// RFC 6962
// Clients that support the extension SHOULD send a ClientHello
// extension with the appropriate type and empty "extension_data".
pub struct SignedCertificateTimestampsIndication;
impl SignedCertificateTimestampsIndication {
    pub const EXTENSION_TYPE: ExtensionType = ExtensionType::SignedCertificateTimestamp;

    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        if !buf.is_empty() {
            return Err(ParseError::InvalidData);
        }

        Ok(Self)
    }

    pub fn encode(&self, _buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        Ok(())
    }
}

// opaque SerializedSCT<1..2^16-1>;

pub struct SerializedSct<'a>(pub &'a [u8]);

impl<'a> SerializedSct<'a> {
    pub const EXTENSION_TYPE: ExtensionType = ExtensionType::SignedCertificateTimestamp;

    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        let len = buf.read_u16()? as usize;
        let bytes = buf.slice(len)?.as_slice();
        Ok(Self(bytes))
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u16_length(|buf| buf.extend_from_slice(self.0))
    }
}

// Servers MUST only send SCTs to clients who have indicated support for
// the extension in the ClientHello, in which case the SCTs are sent by
// setting the "extension_data" to a "SignedCertificateTimestampList".

// struct {
//     SerializedSCT sct_list <1..2^16-1>;
// } SignedCertificateTimestampList;
pub struct SignedCertificateTimestamps<'a, const N: usize> {
    pub sct_list: Vec<SerializedSct<'a>, N>,
}

impl<'a, const N: usize> SignedCertificateTimestamps<'a, N> {
    pub const EXTENSION_TYPE: ExtensionType = ExtensionType::SignedCertificateTimestamp;

    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        let len = buf.read_u16()? as usize;
        let sct_list = buf.read_list(len, SerializedSct::parse)?;
        Ok(Self { sct_list })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u16_length(|buf| {
            for sct in self.sct_list.iter() {
                sct.encode(buf)?;
            }
            Ok(())
        })
    }
}
