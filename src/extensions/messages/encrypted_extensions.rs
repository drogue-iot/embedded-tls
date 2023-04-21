use crate::{
    buffer::CryptoBuffer,
    extensions::{
        extension_data::{
            application_layer_protocol_negotiation::ApplicationLayerProtocolNegotiation,
            certificate_type::CertTypeResponse, early_data::EarlyDataIndication,
            heartbeat::Heartbeat, max_fragment_length::MaxFragmentLength,
            server_name::ServerNameList, supported_groups::SupportedGroups, use_srtp::UseSrtp,
        },
        messages::unexpected_extension_type,
        ExtensionType,
    },
    parse_buffer::{ParseBuffer, ParseError},
    TlsError,
};

// TODO: check if these are the correct data types
pub enum EncryptedExtensionsExtension<'a> {
    ServerName(ServerNameList<'a, 1>),
    MaxFragmentLength(MaxFragmentLength),
    SupportedGroups(SupportedGroups<16>),
    UseSrtp(UseSrtp<'a, 4>),
    Heartbeat(Heartbeat),
    ApplicationLayerProtocolNegotiation(ApplicationLayerProtocolNegotiation<'a, 2>),
    ClientCertificateType(CertTypeResponse),
    ServerCertificateType(CertTypeResponse),
    EarlyData(EarlyDataIndication),
}

impl<'a> EncryptedExtensionsExtension<'a> {
    pub fn extension_type(&self) -> ExtensionType {
        match self {
            Self::ServerName(_) => ExtensionType::ServerName,
            Self::SupportedGroups(_) => ExtensionType::SupportedGroups,
            Self::MaxFragmentLength(_) => ExtensionType::MaxFragmentLength,
            Self::UseSrtp(_) => ExtensionType::UseSrtp,
            Self::Heartbeat(_) => ExtensionType::Heartbeat,
            Self::ApplicationLayerProtocolNegotiation(_) => {
                ExtensionType::ApplicationLayerProtocolNegotiation
            }
            Self::ClientCertificateType(_) => ExtensionType::ClientCertificateType,
            Self::ServerCertificateType(_) => ExtensionType::ServerCertificateType,
            Self::EarlyData(_) => ExtensionType::EarlyData,
        }
    }

    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        match ExtensionType::parse(buf)? {
            ExtensionType::ServerName => Ok(Self::ServerName(ServerNameList::parse(buf)?)),
            ExtensionType::MaxFragmentLength => {
                Ok(Self::MaxFragmentLength(MaxFragmentLength::parse(buf)?))
            }
            ExtensionType::SupportedGroups => {
                Ok(Self::SupportedGroups(SupportedGroups::parse(buf)?))
            }
            ExtensionType::UseSrtp => Ok(Self::UseSrtp(UseSrtp::parse(buf)?)),
            ExtensionType::Heartbeat => Ok(Self::Heartbeat(Heartbeat::parse(buf)?)),
            ExtensionType::ApplicationLayerProtocolNegotiation => {
                Ok(Self::ApplicationLayerProtocolNegotiation(
                    ApplicationLayerProtocolNegotiation::parse(buf)?,
                ))
            }
            ExtensionType::ClientCertificateType => {
                Ok(Self::ClientCertificateType(CertTypeResponse::parse(buf)?))
            }
            ExtensionType::ServerCertificateType => {
                Ok(Self::ServerCertificateType(CertTypeResponse::parse(buf)?))
            }
            ExtensionType::EarlyData => Ok(Self::EarlyData(EarlyDataIndication::parse(buf)?)),
            other => Err(unexpected_extension_type(other)),
        }
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        self.extension_type().encode(buf)?;

        buf.with_u16_length(|buf| match self {
            Self::ServerName(ext) => ext.encode(buf),
            Self::SupportedGroups(ext) => ext.encode(buf),
            Self::MaxFragmentLength(ext) => ext.encode(buf),
            Self::UseSrtp(ext) => ext.encode(buf),
            Self::Heartbeat(ext) => ext.encode(buf),
            Self::ApplicationLayerProtocolNegotiation(ext) => ext.encode(buf),
            Self::ClientCertificateType(ext) => ext.encode(buf),
            Self::ServerCertificateType(ext) => ext.encode(buf),
            Self::EarlyData(ext) => ext.encode(buf),
        })
    }
}
