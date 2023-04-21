use crate::{
    buffer::CryptoBuffer,
    extensions::ExtensionType,
    parse_buffer::{ParseBuffer, ParseError},
    TlsError,
};
use heapless::Vec;

#[derive(Clone, Copy, PartialEq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ProtocolVersion(u16);

impl ProtocolVersion {
    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.push_u16(self.0).map_err(|_| TlsError::EncodeError)
    }

    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        Ok(Self(buf.read_u16()?))
    }
}

pub const TLS13: ProtocolVersion = ProtocolVersion(0x0304);

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SupportedVersions<const N: usize> {
    pub versions: Vec<ProtocolVersion, N>,
}

impl<const N: usize> SupportedVersions<N> {
    pub const EXTENSION_TYPE: ExtensionType = ExtensionType::SupportedVersions;

    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        let data_length = buf.read_u8()?;

        let mut data = buf.slice(data_length as usize)?;
        let mut versions = Vec::new();
        while !data.is_empty() {
            versions
                .push(ProtocolVersion::parse(&mut data)?)
                .map_err(|_| ParseError::InsufficientSpace)?;
        }

        Ok(Self { versions })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u8_length(|buf| {
            for v in self.versions.iter() {
                v.encode(buf)?;
            }
            Ok(())
        })
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SupportedVersion {
    selected_version: ProtocolVersion,
}

impl SupportedVersion {
    pub const EXTENSION_TYPE: ExtensionType = ExtensionType::SupportedVersions;

    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        Ok(Self {
            selected_version: ProtocolVersion::parse(buf)?,
        })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        self.selected_version.encode(buf)
    }
}
