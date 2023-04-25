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
pub enum CertificateStatusRequest {
    // TODO
    // OCSPStatusRequest(OCSPStatusRequest),
}

impl CertificateStatusRequest {
    pub fn parse(_buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        unimplemented!()
    }

    pub fn encode(&self, _buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        unimplemented!()
    }
}
