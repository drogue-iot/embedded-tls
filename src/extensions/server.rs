use crate::extensions::common::KeyShareEntry;
use crate::extensions::ExtensionType;
use crate::parse_buffer::{ParseBuffer, ParseError};
use crate::supported_versions::ProtocolVersion;
use crate::TlsError;
use heapless::{consts::*, Vec};

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ServerExtension<'a> {
    SupportedVersion(SupportedVersion),
    KeyShare(KeyShare<'a>),
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

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct KeyShare<'a>(pub(crate) KeyShareEntry<'a>);

impl<'a> KeyShare<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<KeyShare<'a>, ParseError> {
        Ok(KeyShare(KeyShareEntry::parse(buf)?))
    }
}

impl<'a> ServerExtension<'a> {
    pub fn parse_vector(
        buf: &mut ParseBuffer<'a>,
    ) -> Result<Vec<ServerExtension<'a>, U16>, TlsError> {
        let mut extensions = Vec::new();

        loop {
            if buf.is_empty() {
                break;
            }

            let extension_type =
                ExtensionType::of(buf.read_u16().map_err(|_| TlsError::UnknownExtensionType)?)
                    .ok_or(TlsError::UnknownExtensionType)?;

            //info!("extension type {:?}", extension_type);

            let extension_length = buf
                .read_u16()
                .map_err(|_| TlsError::InvalidExtensionsLength)?;

            //info!("extension length {}", extension_length);

            match extension_type {
                ExtensionType::SupportedVersions => {
                    extensions
                        .push(ServerExtension::SupportedVersion(
                            SupportedVersion::parse(
                                &mut buf
                                    .slice(extension_length as usize)
                                    .map_err(|_| TlsError::InvalidExtensionsLength)?,
                            )
                            .map_err(|_| TlsError::InvalidSupportedVersions)?,
                        ))
                        .map_err(|_| TlsError::DecodeError)?;
                }
                ExtensionType::KeyShare => {
                    extensions
                        .push(ServerExtension::KeyShare(
                            KeyShare::parse(
                                &mut buf
                                    .slice(extension_length as usize)
                                    .map_err(|_| TlsError::InvalidExtensionsLength)?,
                            )
                            .map_err(|_| TlsError::InvalidKeyShare)?,
                        ))
                        .map_err(|_| TlsError::DecodeError)?;
                }
                ExtensionType::SupportedGroups => {
                    let _ = buf.slice(extension_length as usize);
                }
                ExtensionType::ServerName => {
                    let _ = buf.slice(extension_length as usize);
                }
                t => {
                    info!("Unsupported extension type {:?}", t);
                    return Err(TlsError::Unimplemented);
                }
            }
        }
        Ok(extensions)
    }
}
