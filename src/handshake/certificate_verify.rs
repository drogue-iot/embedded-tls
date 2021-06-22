use crate::extensions::ClientExtension::SignatureAlgorithms;
use crate::parse_buffer::ParseBuffer;
use crate::signature_schemes::SignatureScheme;
use crate::TlsError;

use heapless::{consts::*, Vec};

#[derive(Debug)]
pub struct CertificateVerify {
    signature_scheme: SignatureScheme,
    signature: Vec<u8, U512>,
}

impl CertificateVerify {
    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, TlsError> {
        let signature_scheme = SignatureScheme::of(
            buf.read_u16()
                .map_err(|_| TlsError::InvalidSignatureScheme)?,
        )
        .ok_or(TlsError::InvalidSignatureScheme)?;

        let len = buf.read_u16().map_err(|_| TlsError::InvalidSignature)?;
        let signature = buf
            .slice(len as usize)
            .map_err(|_| TlsError::InvalidSignature)?;

        let signature: Result<Vec<u8, _>, ()> = signature.into();

        Ok(Self {
            signature_scheme,
            signature: signature.map_err(|_| TlsError::InvalidSignature)?,
        })
    }
}
