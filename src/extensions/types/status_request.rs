use crate::{
    buffer::CryptoBuffer,
    extensions::ExtensionType,
    parse_buffer::{ParseBuffer, ParseError},
    TlsError,
};

pub enum CertificateStatusRequest {
    // TODO
    // OCSPStatusRequest(OCSPStatusRequest),
}

impl CertificateStatusRequest {
    pub const EXTENSION_TYPE: ExtensionType = ExtensionType::StatusRequest;

    pub fn parse<'a>(_buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        unimplemented!()
    }

    pub fn encode(&self, _buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        unimplemented!()
    }
}
