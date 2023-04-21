use heapless::Vec;

use crate::{
    buffer::CryptoBuffer,
    extensions::ExtensionType,
    parse_buffer::{ParseBuffer, ParseError},
    TlsError,
};

// struct {
//     opaque certificate_extension_oid<1..2^8-1>;
//     opaque certificate_extension_values<0..2^16-1>;
// } OIDFilter;
pub struct OidFilter<'a> {
    pub oid: &'a [u8],
    pub values: &'a [u8],
}

impl<'a> OidFilter<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        let oid_length = buf.read_u8()? as usize;
        let oid = buf.slice(oid_length)?.as_slice();
        let values_length = buf.read_u16()? as usize;
        let values = buf.slice(values_length)?.as_slice();

        Ok(Self { oid, values })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u16_length(|buf| {
            buf.with_u8_length(|buf| buf.extend_from_slice(self.oid))?;
            buf.with_u16_length(|buf| buf.extend_from_slice(self.values))?;
            Ok(())
        })
    }
}

// struct {
//     OIDFilter filters<0..2^16-1>;
// } OIDFilterExtension;

pub struct OidFilters<'a, const N: usize> {
    pub filters: Vec<OidFilter<'a>, N>,
}

impl<'a, const N: usize> OidFilters<'a, N> {
    pub const EXTENSION_TYPE: ExtensionType = ExtensionType::OidFilters;

    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        let data_length = buf.read_u16()? as usize;

        Ok(Self {
            filters: buf.read_list::<_, N>(data_length, OidFilter::parse)?,
        })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u16_length(|buf| {
            for name in self.filters.iter() {
                name.encode(buf)?;
            }
            Ok(())
        })
    }
}
