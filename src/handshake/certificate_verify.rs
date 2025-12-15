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

// Calculations for max. signature sizes:
// ecdsaSHA256 -> 6 bytes (ASN.1 structure) + 32-33 bytes (r) + 32-33 bytes (s) = 70..72 bytes
// ecdsaSHA384 -> 6 bytes (ASN.1 structure) + 48-49 bytes (r) + 48-49 bytes (s) = 102..104 bytes
// Ed25519 -> 6 bytes (ASN.1 structure) + 32-33 bytes (r) + 32-33 bytes (s) = 70..72 bytes
// RSA2048 -> 256 bytes
// RSA3072 -> 384 bytee
// RSA4096 -> 512 bytes
#[cfg(feature = "rsa")]
const SIGNATURE_SIZE: usize = 512;
#[cfg(not(feature = "rsa"))]
const SIGNATURE_SIZE: usize = 104;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CertificateVerify {
    pub(crate) signature_scheme: SignatureScheme,
    pub(crate) signature: heapless::Vec<u8, SIGNATURE_SIZE>,
}

impl CertificateVerify {
    pub(crate) fn encode(&self, buf: &mut CryptoBuffer<'_>) -> Result<(), TlsError> {
        buf.push_u16(self.signature_scheme.as_u16())?;
        buf.with_u16_length(|buf| buf.extend_from_slice(self.signature.as_slice()))?;
        Ok(())
    }
}
