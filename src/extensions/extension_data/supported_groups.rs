use heapless::Vec;

use crate::{
    TlsError,
    buffer::CryptoBuffer,
    parse_buffer::{ParseBuffer, ParseError},
};

#[derive(Copy, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NamedGroup {
    /* Elliptic Curve Groups (ECDHE) */
    Secp256r1,
    Secp384r1,
    Secp521r1,
    X25519,
    X448,

    /* Finite Field Groups (DHE) */
    Ffdhe2048,
    Ffdhe3072,
    Ffdhe4096,
    Ffdhe6144,
    Ffdhe8192,

    /* Post-quantum hybrid groups */
    X25519MLKEM768,
    SecP256r1MLKEM768,
    SecP384r1MLKEM1024,
}

impl NamedGroup {
    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        match buf.read_u16()? {
            0x0017 => Ok(Self::Secp256r1),
            0x0018 => Ok(Self::Secp384r1),
            0x0019 => Ok(Self::Secp521r1),
            0x001D => Ok(Self::X25519),
            0x001E => Ok(Self::X448),

            0x0100 => Ok(Self::Ffdhe2048),
            0x0101 => Ok(Self::Ffdhe3072),
            0x0102 => Ok(Self::Ffdhe4096),
            0x0103 => Ok(Self::Ffdhe6144),
            0x0104 => Ok(Self::Ffdhe8192),

            0x11EB => Ok(Self::SecP256r1MLKEM768),
            0x11EC => Ok(Self::X25519MLKEM768),
            0x11ED => Ok(Self::SecP384r1MLKEM1024),

            _ => Err(ParseError::InvalidData),
        }
    }

    pub fn as_u16(self) -> u16 {
        match self {
            Self::Secp256r1 => 0x0017,
            Self::Secp384r1 => 0x0018,
            Self::Secp521r1 => 0x0019,
            Self::X25519 => 0x001D,
            Self::X448 => 0x001E,

            Self::Ffdhe2048 => 0x0100,
            Self::Ffdhe3072 => 0x0101,
            Self::Ffdhe4096 => 0x0102,
            Self::Ffdhe6144 => 0x0103,
            Self::Ffdhe8192 => 0x0104,

            Self::SecP256r1MLKEM768 => 0x11EB,
            Self::X25519MLKEM768 => 0x11EC,
            Self::SecP384r1MLKEM1024 => 0x11ED,
        }
    }

    pub fn encode(self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.push_u16(self.as_u16())
            .map_err(|_| TlsError::EncodeError)
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SupportedGroups<const N: usize> {
    pub supported_groups: Vec<NamedGroup, N>,
}

impl<const N: usize> SupportedGroups<N> {
    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        let data_length = buf.read_u16()? as usize;

        Ok(Self {
            supported_groups: buf.read_list::<_, N>(data_length, NamedGroup::parse)?,
        })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u16_length(|buf| {
            for g in &self.supported_groups {
                g.encode(buf)?;
            }
            Ok(())
        })
    }
}
