// This file contains the client_certificate_type and server_certificate_type extension type
// definitions as defined in RFC 7250.
use heapless::Vec;

use crate::{
    buffer::CryptoBuffer,
    parse_buffer::{ParseBuffer, ParseError},
    TlsError,
};

#[derive(Clone, Copy, Debug)]
pub enum CertType {
    X509 = 0,
    Reserved = 1,
    RawPublicKey = 2,
    _1609Dot2 = 3,
}

impl CertType {
    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        match buf.read_u8()? {
            v if v == Self::X509 as u8 => Ok(Self::X509),
            v if v == Self::Reserved as u8 => Ok(Self::Reserved),
            v if v == Self::RawPublicKey as u8 => Ok(Self::RawPublicKey),
            v if v == Self::_1609Dot2 as u8 => Ok(Self::_1609Dot2),
            other => {
                warn!("Read unknown CertType: {}", other);
                Err(ParseError::InvalidData)
            }
        }
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.push(*self as u8)
    }
}

pub struct CertTypeRequest<const N: usize> {
    pub cert_types: Vec<CertType, N>,
}

impl<const N: usize> CertTypeRequest<N> {
    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        let len = buf.read_u8()? as usize;

        let cert_types = buf.read_list(len, CertType::parse)?;
        Ok(Self { cert_types })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u8_length(|buf| {
            for cert_ty in self.cert_types.iter() {
                cert_ty.encode(buf)?;
            }
            Ok(())
        })
    }
}

pub struct CertTypeResponse {
    pub cert_type: CertType,
}

impl CertTypeResponse {
    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        Ok(Self {
            cert_type: CertType::parse(buf)?,
        })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        self.cert_type.encode(buf)
    }
}
