use crate::parse_buffer::ParseBuffer;
use crate::signature_schemes::SignatureScheme;
use crate::TlsError;

#[derive(Debug)]
pub struct CertificateVerify<'a> {
    signature_scheme: SignatureScheme,
    signature: &'a [u8],
}

impl<'a> CertificateVerify<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<CertificateVerify<'a>, TlsError> {
        let signature_scheme = SignatureScheme::of(
            buf.read_u16()
                .map_err(|_| TlsError::InvalidSignatureScheme)?,
        )
        .ok_or(TlsError::InvalidSignatureScheme)?;

        let len = buf.read_u16().map_err(|_| TlsError::InvalidSignature)?;
        let signature = buf
            .slice(len as usize)
            .map_err(|_| TlsError::InvalidSignature)?;

        Ok(Self {
            signature_scheme,
            signature: signature.as_slice(),
        })
    }
}
