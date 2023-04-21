use heapless::Vec;

use crate::{
    buffer::CryptoBuffer,
    extensions::ExtensionType,
    parse_buffer::{ParseBuffer, ParseError},
    TlsError,
};

#[derive(Copy, Clone, Debug, PartialOrd, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NamedGroup {
    /* Elliptic Curve Groups (ECDHE) */
    Secp256r1 = 0x0017,
    Secp384r1 = 0x0018,
    Secp521r1 = 0x0019,
    X25519 = 0x001D,
    X448 = 0x001E,

    /* Finite Field Groups (DHE) */
    Ffdhe2048 = 0x0100,
    Ffdhe3072 = 0x0101,
    Ffdhe4096 = 0x0102,
    Ffdhe6144 = 0x0103,
    Ffdhe8192 = 0x0104,
}

impl NamedGroup {
    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        match buf.read_u16()? {
            v if v == Self::Secp256r1 as u16 => Ok(Self::Secp256r1),
            v if v == Self::Secp384r1 as u16 => Ok(Self::Secp384r1),
            v if v == Self::Secp521r1 as u16 => Ok(Self::Secp521r1),
            v if v == Self::X25519 as u16 => Ok(Self::X25519),
            v if v == Self::X448 as u16 => Ok(Self::X448),
            v if v == Self::Ffdhe2048 as u16 => Ok(Self::Ffdhe2048),
            v if v == Self::Ffdhe3072 as u16 => Ok(Self::Ffdhe3072),
            v if v == Self::Ffdhe4096 as u16 => Ok(Self::Ffdhe4096),
            v if v == Self::Ffdhe6144 as u16 => Ok(Self::Ffdhe6144),
            v if v == Self::Ffdhe8192 as u16 => Ok(Self::Ffdhe8192),
            _ => Err(ParseError::InvalidData),
        }
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.push_u16(*self as u16)
            .map_err(|_| TlsError::EncodeError)
    }
}

pub struct SupportedGroups<const N: usize> {
    pub supported_groups: Vec<NamedGroup, N>,
}

impl<const N: usize> SupportedGroups<N> {
    pub const EXTENSION_TYPE: ExtensionType = ExtensionType::SupportedGroups;

    pub fn parse<'a>(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        let data_length = buf.read_u16()?;

        let mut data = buf.slice(data_length as usize)?;
        let mut supported_groups = Vec::new();
        while !data.is_empty() {
            supported_groups
                .push(NamedGroup::parse(&mut data)?)
                .map_err(|_| ParseError::InsufficientSpace)?;
        }

        Ok(Self { supported_groups })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u16_length(|buf| {
            for g in self.supported_groups.iter() {
                g.encode(buf)?;
            }
            Ok(())
        })
    }
}
