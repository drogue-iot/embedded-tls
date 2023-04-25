use heapless::Vec;

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
// opaque DistinguishedName<1..2^16-1>;
pub struct DistinguishedName<'a> {
    pub name: &'a [u8],
}

impl<'a> DistinguishedName<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        let name_len = buf.read_u16()?;
        let name = buf.slice(name_len as usize)?.as_slice();
        Ok(Self { name })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u16_length(|buf| buf.extend_from_slice(self.name))
            .map_err(|_| TlsError::EncodeError)
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
// struct {
//     DistinguishedName authorities<3..2^16-1>;
// } CertificateAuthoritiesExtension;
pub struct CertificateAuthorities<'a, const N: usize> {
    pub authorities: Vec<DistinguishedName<'a>, N>,
}

impl<'a, const N: usize> CertificateAuthorities<'a, N> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        let data_length = buf.read_u16()?;
        buf.read_list(data_length as usize, DistinguishedName::parse)
            .map(|authorities| Self { authorities })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u16_length(|buf| {
            for authority in self.authorities.iter() {
                authority.encode(buf)?;
            }
            Ok(())
        })
    }
}
