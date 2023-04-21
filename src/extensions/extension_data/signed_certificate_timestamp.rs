use heapless::Vec;

use crate::{
    buffer::CryptoBuffer,
    parse_buffer::{ParseBuffer, ParseError},
    TlsError,
};

#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
// RFC 6962
// Clients that support the extension SHOULD send a ClientHello
// extension with the appropriate type and empty "extension_data".
pub struct SignedCertificateTimestampIndication;
impl SignedCertificateTimestampIndication {
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

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
// opaque SerializedSCT<1..2^16-1>;
pub struct SerializedSct<'a>(pub &'a [u8]);

impl<'a> SerializedSct<'a> {
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
