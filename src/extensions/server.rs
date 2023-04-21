use crate::alert::{AlertDescription, AlertLevel};
use crate::extensions::extension_data::key_share::KeyShareServerHello;
use crate::extensions::extension_data::server_name::ServerNameResponse;
use crate::extensions::extension_data::supported_versions::SupportedVersionsServerHello;
use crate::extensions::ExtensionType;
use crate::parse_buffer::{ParseBuffer, ParseError};
use crate::TlsError;
use heapless::Vec;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ServerExtension<'a> {
    SupportedVersion(SupportedVersionsServerHello),
    KeyShare(KeyShareServerHello<'a>),
    PreSharedKey(u16),

    SupportedGroups,
    ServerName(ServerNameResponse),
}

pub struct ServerExtensionParserIterator<'a, 'b> {
    buffer: &'b mut ParseBuffer<'a>,
    allowed: &'b [ExtensionType],
}

impl<'a, 'b> ServerExtensionParserIterator<'a, 'b> {
    pub fn new(buffer: &'b mut ParseBuffer<'a>, allowed: &'b [ExtensionType]) -> Self {
        Self { buffer, allowed }
    }
}

impl<'a, 'b> Iterator for ServerExtensionParserIterator<'a, 'b> {
    type Item = Result<Option<ServerExtension<'a>>, TlsError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buffer.is_empty() {
            return None;
        }

        Some(ServerExtension::parse(self.buffer, self.allowed))
    }
}

impl<'a> ServerExtension<'a> {
    pub fn parse(
        buf: &mut ParseBuffer<'a>,
        allowed: &[ExtensionType],
    ) -> Result<Option<ServerExtension<'a>>, TlsError> {
        let extension_type = match ExtensionType::parse(buf) {
            Ok(extension_type) => extension_type,
            Err(ParseError::InvalidData) => return Ok(None),
            Err(_) => return Err(TlsError::DecodeError),
        };

        trace!("extension type {:?}", extension_type);

        if !allowed.contains(&extension_type) {
            warn!(
                "{:?} extension is not allowed in this context",
                extension_type
            );

            // Section 4.2.  Extensions
            // If an implementation receives an extension
            // which it recognizes and which is not specified for the message in
            // which it appears, it MUST abort the handshake with an
            // "illegal_parameter" alert.
            return Err(TlsError::AbortHandshake(
                AlertLevel::Fatal,
                AlertDescription::IllegalParameter,
            ));
        }

        let extension_length = buf
            .read_u16()
            .map_err(|_| TlsError::InvalidExtensionsLength)?;

        trace!("extension length {}", extension_length);

        Self::from_type_and_data(extension_type, &mut buf.slice(extension_length as usize)?)
    }

    pub fn parse_vector<const N: usize>(
        buf: &mut ParseBuffer<'a>,
        allowed: &[ExtensionType],
    ) -> Result<Vec<ServerExtension<'a>, N>, TlsError> {
        let extensions_len = buf
            .read_u16()
            .map_err(|_| TlsError::InvalidExtensionsLength)?;

        let mut ext_buf = buf.slice(extensions_len as usize)?;

        let mut extensions = Vec::new();

        for extension in ServerExtensionParserIterator::new(&mut ext_buf, allowed) {
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
                SupportedVersionsServerHello::parse(data)
                    .map_err(|_| TlsError::InvalidSupportedVersions)?,
            ),
            ExtensionType::KeyShare => ServerExtension::KeyShare(
                KeyShareServerHello::parse(data).map_err(|_| TlsError::InvalidKeyShare)?,
            ),
            ExtensionType::PreSharedKey => {
                let value = data.read_u16()?;

                ServerExtension::PreSharedKey(value)
            }
            ExtensionType::SupportedGroups => ServerExtension::SupportedGroups,
            ExtensionType::ServerName => {
                ServerExtension::ServerName(ServerNameResponse::parse(data)?)
            }
            t => {
                warn!("Unimplemented extension: {:?}", t);
                return Ok(None);
            }
        };

        Ok(Some(extension))
    }
}
