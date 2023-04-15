pub mod common;
pub mod server;

use crate::signature_schemes::SignatureScheme;

use crate::buffer::*;
use crate::max_fragment_length::MaxFragmentLength;
use crate::named_groups::NamedGroup;
use crate::supported_versions::ProtocolVersions;
use crate::TlsError;
use heapless::Vec;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
        //info!("extension type of {:x}", num);
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

pub enum ClientExtension<'a> {
    ServerName {
        server_name: &'a str,
    },
    SupportedVersions {
        versions: ProtocolVersions,
    },
    SignatureAlgorithms {
        supported_signature_algorithms: Vec<SignatureScheme, 16>,
    },
    SupportedGroups {
        supported_groups: Vec<NamedGroup, 16>,
    },
    KeyShare {
        group: NamedGroup,
        opaque: &'a [u8],
    },
    PreSharedKey {
        identities: Vec<&'a [u8], 4>,
        hash_size: usize,
    },
    PskKeyExchangeModes {
        modes: Vec<PskKeyExchangeMode, 4>,
    },
    SignatureAlgorithmsCert {
        supported_signature_algorithms: Vec<SignatureScheme, 16>,
    },
    MaxFragmentLength(MaxFragmentLength),
}

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum PskKeyExchangeMode {
    PskKe = 0,
    PskDheKe = 1,
}

impl ClientExtension<'_> {
    pub fn extension_type(&self) -> ExtensionType {
        match self {
            ClientExtension::ServerName { .. } => ExtensionType::ServerName,
            ClientExtension::SupportedVersions { .. } => ExtensionType::SupportedVersions,
            ClientExtension::SignatureAlgorithms { .. } => ExtensionType::SignatureAlgorithms,
            ClientExtension::KeyShare { .. } => ExtensionType::KeyShare,
            ClientExtension::SupportedGroups { .. } => ExtensionType::SupportedGroups,
            ClientExtension::SignatureAlgorithmsCert { .. } => {
                ExtensionType::SignatureAlgorithmsCert
            }
            ClientExtension::PskKeyExchangeModes { .. } => ExtensionType::PskKeyExchangeModes,
            ClientExtension::PreSharedKey { .. } => ExtensionType::PreSharedKey,
            ClientExtension::MaxFragmentLength(_) => ExtensionType::MaxFragmentLength,
        }
    }

    pub(crate) fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.push_u16(self.extension_type() as u16)
            .map_err(|_| TlsError::EncodeError)?;

        buf.with_u16_length(|buf| {
            match self {
                ClientExtension::ServerName { server_name } => {
                    //info!("server name ext");
                    buf.with_u16_length(|buf| {
                        const NAME_TYPE_HOST: u8 = 0;
                        buf.push(NAME_TYPE_HOST)
                            .map_err(|_| TlsError::EncodeError)?;

                        buf.with_u16_length(|buf| buf.extend_from_slice(server_name.as_bytes()))
                            .map_err(|_| TlsError::EncodeError)
                    })
                }
                ClientExtension::PskKeyExchangeModes { modes } => buf.with_u8_length(|buf| {
                    for mode in modes {
                        buf.push(*mode as u8).map_err(|_| TlsError::EncodeError)?;
                    }
                    Ok(())
                }),
                ClientExtension::SupportedVersions { versions } => {
                    //info!("supported versions ext");
                    buf.with_u8_length(|buf| {
                        for &v in versions {
                            buf.push_u16(v).map_err(|_| TlsError::EncodeError)?;
                        }
                        Ok(())
                    })
                }
                ClientExtension::SignatureAlgorithms {
                    supported_signature_algorithms,
                } => {
                    //info!("supported sig algo ext");
                    buf.with_u16_length(|buf| {
                        for &a in supported_signature_algorithms {
                            buf.push_u16(a as u16).map_err(|_| TlsError::EncodeError)?;
                        }
                        Ok(())
                    })
                }
                ClientExtension::SignatureAlgorithmsCert {
                    supported_signature_algorithms,
                } => {
                    //info!("supported sig algo cert ext");
                    buf.with_u16_length(|buf| {
                        for &a in supported_signature_algorithms {
                            buf.push_u16(a as u16).map_err(|_| TlsError::EncodeError)?;
                        }
                        Ok(())
                    })
                }
                ClientExtension::SupportedGroups { supported_groups } => {
                    //info!("supported groups ext");
                    buf.with_u16_length(|buf| {
                        for &g in supported_groups {
                            buf.push_u16(g as u16).map_err(|_| TlsError::EncodeError)?;
                        }
                        Ok(())
                    })
                }
                ClientExtension::KeyShare { group, opaque } => {
                    //info!("key_share ext");
                    buf.with_u16_length(|buf| {
                        // one key-share
                        buf.push_u16(*group as u16)
                            .map_err(|_| TlsError::EncodeError)?;

                        buf.with_u16_length(|buf| buf.extend_from_slice(opaque.as_ref()))
                            .map_err(|_| TlsError::EncodeError)
                    })
                }
                ClientExtension::PreSharedKey {
                    identities,
                    hash_size,
                } => {
                    buf.with_u16_length(|buf| {
                        for identity in identities {
                            buf.with_u16_length(|buf| buf.extend_from_slice(identity))
                                .map_err(|_| TlsError::EncodeError)?;

                            // NOTE: No support for ticket age, set to 0 as recommended by RFC
                            buf.push_u32(0).map_err(|_| TlsError::EncodeError)?;
                        }
                        Ok(())
                    })
                    .map_err(|_| TlsError::EncodeError)?;

                    // NOTE: We encode binders later after computing the transcript.
                    let binders_len = (1 + hash_size) * identities.len();
                    buf.push_u16(binders_len as u16)
                        .map_err(|_| TlsError::EncodeError)?;

                    for _ in 0..binders_len {
                        buf.push(0).map_err(|_| TlsError::EncodeError)?;
                    }

                    Ok(())
                }
                ClientExtension::MaxFragmentLength(len) => {
                    //info!("max fragment length");
                    buf.push(*len as u8).map_err(|_| TlsError::EncodeError)
                }
            }
        })
    }
}
