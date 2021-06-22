use crate::extensions::common::KeyShareEntry;
use crate::extensions::ExtensionType;
use crate::extensions::ExtensionType::SupportedVersions;
use crate::named_groups::NamedGroup;
use crate::parse_buffer::{ParseBuffer, ParseError};
use crate::supported_versions::ProtocolVersion;
use crate::TlsError;
use heapless::{consts::*, Vec};

#[derive(Debug)]
pub enum ServerExtension {
    SupportedVersion(SupportedVersion),
    KeyShare(KeyShare),
}

#[derive(Debug)]
pub struct SupportedVersion {
    selected_version: ProtocolVersion,
}

impl SupportedVersion {
    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        let selected_version = buf.read_u16()?;
        Ok(Self { selected_version })
    }
}

#[derive(Debug)]
pub struct KeyShare(pub(crate) KeyShareEntry);

impl KeyShare {
    pub fn parse(buf: &mut ParseBuffer) -> Result<KeyShare, ParseError> {
        Ok(KeyShare(KeyShareEntry::parse(buf)?))
    }
}

impl ServerExtension {
    pub fn parse_vector(buf: &mut ParseBuffer) -> Result<Vec<ServerExtension, U16>, TlsError> {
        let mut extensions = Vec::new();

        loop {
            if buf.is_empty() {
                break;
            }

            let extension_type =
                ExtensionType::of(buf.read_u16().map_err(|_| TlsError::UnknownExtensionType)?)
                    .ok_or(TlsError::UnknownExtensionType)?;

            info!("extension type {:?}", extension_type);

            let extension_length = buf
                .read_u16()
                .map_err(|_| TlsError::InvalidExtensionsLength)?;

            info!("extension length {}", extension_length);

            match extension_type {
                ExtensionType::SupportedVersions => {
                    extensions.push(ServerExtension::SupportedVersion(
                        SupportedVersion::parse(
                            &mut buf
                                .slice(extension_length as usize)
                                .map_err(|_| TlsError::InvalidExtensionsLength)?,
                        )
                        .map_err(|_| TlsError::InvalidSupportedVersions)?,
                    ));
                }
                ExtensionType::KeyShare => {
                    extensions.push(ServerExtension::KeyShare(
                        KeyShare::parse(
                            &mut buf
                                .slice(extension_length as usize)
                                .map_err(|_| TlsError::InvalidExtensionsLength)?,
                        )
                        .map_err(|_| TlsError::InvalidKeyShare)?,
                    ));
                }
                ExtensionType::SupportedGroups => {
                    let _ = buf.slice(extension_length as usize);
                }
                _ => return Err(TlsError::Unimplemented),
            }
        }
        Ok(extensions)
    }
}
