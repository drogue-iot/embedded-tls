use crate::{
    buffer::CryptoBuffer,
    extensions::{
        messages::unexpected_extension_type,
        types::{
            key_share::KeyShareServerHello, pre_shared_key::PreSharedKeyServerHello,
            supported_versions::SupportedVersions,
        },
        ExtensionType,
    },
    parse_buffer::{ParseBuffer, ParseError},
    TlsError,
};

// TODO: check if these are the correct data types
pub enum ServerHelloExtension<'a> {
    KeyShare(KeyShareServerHello<'a>),
    PreSharedKey(PreSharedKeyServerHello),
    SupportedVersions(SupportedVersions<16>),
}

impl<'a> ServerHelloExtension<'a> {
    pub fn extension_type(&self) -> ExtensionType {
        match self {
            Self::SupportedVersions(_) => ExtensionType::SupportedVersions,
            Self::KeyShare(_) => ExtensionType::KeyShare,
            Self::PreSharedKey(_) => ExtensionType::PreSharedKey,
        }
    }

    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        match ExtensionType::parse(buf)? {
            ExtensionType::PreSharedKey => {
                Ok(Self::PreSharedKey(PreSharedKeyServerHello::parse(buf)?))
            }
            ExtensionType::SupportedVersions => {
                Ok(Self::SupportedVersions(SupportedVersions::parse(buf)?))
            }
            ExtensionType::KeyShare => Ok(Self::KeyShare(KeyShareServerHello::parse(buf)?)),
            other => Err(unexpected_extension_type(other)),
        }
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        self.extension_type().encode(buf)?;

        buf.with_u16_length(|buf| match self {
            Self::SupportedVersions(ext) => ext.encode(buf),
            Self::KeyShare(ext) => ext.encode(buf),
            Self::PreSharedKey(ext) => ext.encode(buf),
        })
    }
}
