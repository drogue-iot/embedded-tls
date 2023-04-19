use crate::extensions::common::KeyShareEntry;
use crate::extensions::ExtensionType;
use crate::parse_buffer::{ParseBuffer, ParseError};
use crate::supported_versions::ProtocolVersion;
use crate::TlsError;
use heapless::Vec;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ServerExtension<'a> {
    SupportedVersion(SupportedVersion),
    KeyShare(KeyShare<'a>),
    PreSharedKey(u16),

    SupportedGroups,
    ServerName,
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SupportedVersion {
    selected_version: ProtocolVersion,
}

impl SupportedVersion {
    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        let selected_version = buf.read_u16()?;
        Ok(Self { selected_version })
    }
}

pub struct ServerExtensionParserIterator<'a, 'b> {
    buffer: &'b mut ParseBuffer<'a>,
}

impl<'a, 'b> ServerExtensionParserIterator<'a, 'b> {
    pub fn new(buffer: &'b mut ParseBuffer<'a>) -> Self {
        Self { buffer }
    }
}

impl<'a, 'b> Iterator for ServerExtensionParserIterator<'a, 'b> {
    type Item = Result<Option<ServerExtension<'a>>, TlsError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buffer.is_empty() {
            return None;
        }

        Some(ServerExtension::parse(&mut self.buffer))
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct KeyShare<'a>(pub(crate) KeyShareEntry<'a>);

impl<'a> KeyShare<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<KeyShare<'a>, ParseError> {
        Ok(KeyShare(KeyShareEntry::parse(buf)?))
    }
}

impl<'a> ServerExtension<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Option<ServerExtension<'a>>, TlsError> {
        let extension_type =
            ExtensionType::of(buf.read_u16().map_err(|_| TlsError::UnknownExtensionType)?)
                .ok_or(TlsError::UnknownExtensionType)?;

        trace!("extension type {:?}", extension_type);

        let extension_length = buf
            .read_u16()
            .map_err(|_| TlsError::InvalidExtensionsLength)?;

        trace!("extension length {}", extension_length);

        Self::from_type_and_data(extension_type, &mut buf.slice(extension_length as usize)?)
    }

    pub fn parse_vector<const N: usize>(
        buf: &mut ParseBuffer<'a>,
    ) -> Result<Vec<ServerExtension<'a>, N>, TlsError> {
        let mut iter = ServerExtensionParserIterator::new(buf);

        let mut extensions = Vec::new();

        while let Some(extension) = iter.next() {
            if let Some(extension) = extension? {
                extensions
                    .push(extension)
                    .map_err(|_| TlsError::DecodeError)?;
            }
        }

        Ok(extensions)
    }

    fn from_type_and_data<'b>(
        extension_type: ExtensionType,
        data: &mut ParseBuffer<'b>,
    ) -> Result<Option<ServerExtension<'b>>, TlsError> {
        let extension = match extension_type {
            ExtensionType::SupportedVersions => ServerExtension::SupportedVersion(
                SupportedVersion::parse(data).map_err(|_| TlsError::InvalidSupportedVersions)?,
            ),
            ExtensionType::KeyShare => ServerExtension::KeyShare(
                KeyShare::parse(data).map_err(|_| TlsError::InvalidKeyShare)?,
            ),
            ExtensionType::PreSharedKey => {
                let value = data.read_u16()?;

                ServerExtension::PreSharedKey(value)
            }
            ExtensionType::SupportedGroups => ServerExtension::SupportedGroups,
            ExtensionType::ServerName => ServerExtension::ServerName,
            t => {
                warn!("Unimplemented extension: {:?}", t);
                return Ok(None);
            }
        };

        Ok(Some(extension))
    }
}
