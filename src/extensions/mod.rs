pub mod common;
pub mod server;

use crate::signature_schemes::SignatureScheme;

use crate::buffer::*;
use crate::max_fragment_length::MaxFragmentLength;
use crate::named_groups::NamedGroup;
use crate::supported_versions::ProtocolVersions;
use crate::TlsError;
use heapless::{consts::*, String, Vec};

#[derive(Debug)]
pub enum ExtensionType {
    ServerName = 0,
    MaxFragmentLength = 1,
    StatusRequest = 5,
    SupportedGroups = 10,
    SignatureAlgorithms = 13,
    UseSrtp = 14,
    Heatbeat = 15,
    ApplicationLayerProtocolNegotiation = 16,
    SignedCertificateTimestamp = 18,
    ClientCertificateType = 19,
    ServerCertificateType = 20,
    Padding = 21,
    PreSharedKey = 41,
    EarlyData = 42,
    SupportedVersions = 43,
    Cookie = 44,
    PskKeyExchangeModes = 45,
    CertificateAuthorities = 47,
    OidFilters = 48,
    PostHandshakeAuth = 49,
    SignatureAlgorithmsCert = 50,
    KeyShare = 51,
}

impl ExtensionType {
    pub fn of(num: u16) -> Option<Self> {
        info!("extension type of {:x}", num);
        match num {
            0 => Some(Self::ServerName),
            1 => Some(Self::MaxFragmentLength),
            5 => Some(Self::StatusRequest),
            10 => Some(Self::SupportedGroups),
            13 => Some(Self::SignatureAlgorithms),
            14 => Some(Self::UseSrtp),
            15 => Some(Self::Heatbeat),
            16 => Some(Self::ApplicationLayerProtocolNegotiation),
            18 => Some(Self::SignedCertificateTimestamp),
            19 => Some(Self::ClientCertificateType),
            20 => Some(Self::ServerCertificateType),
            21 => Some(Self::Padding),
            41 => Some(Self::PreSharedKey),
            42 => Some(Self::EarlyData),
            43 => Some(Self::SupportedVersions),
            44 => Some(Self::Cookie),
            45 => Some(Self::PskKeyExchangeModes),
            47 => Some(Self::CertificateAuthorities),
            48 => Some(Self::OidFilters),
            49 => Some(Self::PostHandshakeAuth),
            50 => Some(Self::SignatureAlgorithmsCert),
            51 => Some(Self::KeyShare),
            _ => None,
        }
    }
}

pub enum ClientExtension {
    ServerName {
        server_name: String<U256>,
    },
    SupportedVersions {
        versions: ProtocolVersions,
    },
    SignatureAlgorithms {
        supported_signature_algorithms: Vec<SignatureScheme, U16>,
    },
    SupportedGroups {
        supported_groups: Vec<NamedGroup, U16>,
    },
    KeyShare {
        group: NamedGroup,
        opaque: Vec<u8, U128>,
    },
    SignatureAlgorithmsCert {
        supported_signature_algorithms: Vec<SignatureScheme, U16>,
    },
    MaxFragmentLength(MaxFragmentLength),
}

impl ClientExtension {
    pub fn extension_type(&self) -> [u8; 2] {
        match self {
            ClientExtension::ServerName { .. } => ExtensionType::ServerName as u16,
            ClientExtension::SupportedVersions { .. } => ExtensionType::SupportedVersions as u16,
            ClientExtension::SignatureAlgorithms { .. } => {
                ExtensionType::SignatureAlgorithms as u16
            }
            ClientExtension::KeyShare { .. } => ExtensionType::KeyShare as u16,
            ClientExtension::SupportedGroups { .. } => ExtensionType::SupportedGroups as u16,
            ClientExtension::SignatureAlgorithmsCert { .. } => {
                ExtensionType::SignatureAlgorithmsCert as u16
            }
            ClientExtension::MaxFragmentLength(_) => ExtensionType::MaxFragmentLength as u16,
        }
        .to_be_bytes()
    }

    pub(crate) fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.extend_from_slice(&self.extension_type())
            .map_err(|_| TlsError::EncodeError)?;
        let extension_length_marker = buf.len();
        info!("marker at {}", extension_length_marker);
        buf.push(0).map_err(|_| TlsError::EncodeError)?;
        buf.push(0).map_err(|_| TlsError::EncodeError)?;

        match self {
            ClientExtension::ServerName { server_name } => {
                info!("server name ext");
            }
            ClientExtension::SupportedVersions { versions } => {
                info!("supported versions ext");
                buf.push(versions.len() as u8 * 2)
                    .map_err(|_| TlsError::EncodeError)?;
                for v in versions {
                    buf.extend_from_slice(&v.to_be_bytes())
                        .map_err(|_| TlsError::EncodeError)?;
                }
            }
            ClientExtension::SignatureAlgorithms {
                supported_signature_algorithms,
            } => {
                info!("supported sig algo ext");
                buf.extend_from_slice(
                    &(supported_signature_algorithms.len() as u16 * 2).to_be_bytes(),
                )
                .map_err(|_| TlsError::EncodeError)?;

                for a in supported_signature_algorithms {
                    buf.extend_from_slice(&(*a as u16).to_be_bytes())
                        .map_err(|_| TlsError::EncodeError)?;
                }
            }
            ClientExtension::SignatureAlgorithmsCert {
                supported_signature_algorithms,
            } => {
                info!("supported sig algo cert ext");
                buf.extend_from_slice(
                    &(supported_signature_algorithms.len() as u16 * 2).to_be_bytes(),
                )
                .map_err(|_| TlsError::EncodeError)?;

                for a in supported_signature_algorithms {
                    buf.extend_from_slice(&(*a as u16).to_be_bytes())
                        .map_err(|_| TlsError::EncodeError)?;
                }
            }
            ClientExtension::SupportedGroups { supported_groups } => {
                info!("supported groups ext");
                buf.extend_from_slice(&(supported_groups.len() as u16 * 2).to_be_bytes())
                    .map_err(|_| TlsError::EncodeError)?;

                for g in supported_groups {
                    buf.extend_from_slice(&(*g as u16).to_be_bytes())
                        .map_err(|_| TlsError::EncodeError)?;
                }
            }
            ClientExtension::KeyShare { group, opaque } => {
                info!("key_share ext");
                buf.extend_from_slice(&(2 + 2 as u16 + opaque.len() as u16).to_be_bytes())
                    .map_err(|_| TlsError::EncodeError)?;
                // one key-share
                buf.extend_from_slice(&(*group as u16).to_be_bytes())
                    .map_err(|_| TlsError::EncodeError)?;
                buf.extend_from_slice(&(opaque.len() as u16).to_be_bytes())
                    .map_err(|_| TlsError::EncodeError)?;
                buf.extend_from_slice(opaque.as_ref())
                    .map_err(|_| TlsError::EncodeError)?;
            }
            ClientExtension::MaxFragmentLength(len) => {
                info!("max fragment length");
                buf.push(*len as u8).map_err(|_| TlsError::EncodeError)?;
            }
        }

        info!("tail at {}", buf.len());
        let extension_length = (buf.len() as u16 - extension_length_marker as u16) - 2;
        info!("len: {}", extension_length);
        buf.set(extension_length_marker, extension_length.to_be_bytes()[0])
            .map_err(|_| TlsError::EncodeError)?;
        buf.set(
            extension_length_marker + 1,
            extension_length.to_be_bytes()[1],
        )
        .map_err(|_| TlsError::EncodeError)?;
        Ok(())
    }
}
