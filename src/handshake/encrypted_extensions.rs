use crate::extensions::server::ServerExtension;
use crate::extensions::ExtensionType;

use crate::parse_buffer::ParseBuffer;
use crate::TlsError;
use heapless::Vec;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EncryptedExtensions<'a> {
    extensions: Vec<ServerExtension<'a>, 16>,
}

impl<'a> EncryptedExtensions<'a> {
    // Source: https://www.rfc-editor.org/rfc/rfc8446#section-4.2 table, rows marked with EE
    const ALLOWED_EXTENSIONS: &[ExtensionType] = &[
        ExtensionType::ServerName,
        ExtensionType::MaxFragmentLength,
        ExtensionType::SupportedGroups,
        ExtensionType::UseSrtp,
        ExtensionType::Heartbeat,
        ExtensionType::ApplicationLayerProtocolNegotiation,
        ExtensionType::ClientCertificateType,
        ExtensionType::ServerCertificateType,
        ExtensionType::EarlyData,
    ];

    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<EncryptedExtensions<'a>, TlsError> {
        ServerExtension::parse_vector(buf, Self::ALLOWED_EXTENSIONS)
            .map(|extensions| Self { extensions })
    }
}
