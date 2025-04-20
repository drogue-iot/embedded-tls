use crate::TlsError;
use crate::extensions::extension_data::signature_algorithms::SignatureScheme;
use crate::parse_buffer::ParseBuffer;

use super::CryptoBuffer;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CertificateVerifyRef<'a> {
    pub signature_scheme: SignatureScheme,
    pub signature: &'a [u8],
}

impl<'a> CertificateVerifyRef<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<CertificateVerifyRef<'a>, TlsError> {
        let signature_scheme =
            SignatureScheme::parse(buf).map_err(|_| TlsError::InvalidSignatureScheme)?;

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

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CertificateVerify {
    pub(crate) signature_scheme: SignatureScheme,
    pub(crate) signature: heapless::Vec<u8, 128>,
}

impl CertificateVerify {
    pub(crate) fn encode(&self, buf: &mut CryptoBuffer<'_>) -> Result<(), TlsError> {
        buf.push_u16(self.signature_scheme.as_u16())?;
        buf.with_u16_length(|buf| buf.extend_from_slice(self.signature.as_slice()))?;
        Ok(())
    }
}
