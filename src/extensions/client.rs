use crate::extensions::types::key_share::KeyShare;
use crate::extensions::types::server_name::ServerNameList;
use crate::extensions::ExtensionType;
use crate::signature_schemes::SignatureScheme;

use crate::buffer::*;
use crate::max_fragment_length::MaxFragmentLength;
use crate::named_groups::NamedGroup;
use crate::supported_versions::ProtocolVersions;
use crate::TlsError;
use heapless::Vec;

pub enum ClientExtension<'a> {
    ServerName(ServerNameList<'a, 1>),
    SupportedVersions {
        versions: ProtocolVersions,
    },
    SignatureAlgorithms {
        supported_signature_algorithms: Vec<SignatureScheme, 16>,
    },
    SupportedGroups {
        supported_groups: Vec<NamedGroup, 16>,
    },
    KeyShare(KeyShare<'a>),
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
        trace!("Encoding client extension {:?}", self.extension_type());
        buf.push_u16(self.extension_type() as u16)
            .map_err(|_| TlsError::EncodeError)?;

        buf.with_u16_length(|buf| {
            match self {
                ClientExtension::ServerName(server_name_list) => server_name_list.encode(buf),
                ClientExtension::PskKeyExchangeModes { modes } => buf.with_u8_length(|buf| {
                    for mode in modes {
                        buf.push(*mode as u8).map_err(|_| TlsError::EncodeError)?;
                    }
                    Ok(())
                }),
                ClientExtension::SupportedVersions { versions } => buf.with_u8_length(|buf| {
                    for &v in versions {
                        buf.push_u16(v).map_err(|_| TlsError::EncodeError)?;
                    }
                    Ok(())
                }),
                ClientExtension::SignatureAlgorithms {
                    supported_signature_algorithms,
                } => buf.with_u16_length(|buf| {
                    for &a in supported_signature_algorithms {
                        buf.push_u16(a as u16).map_err(|_| TlsError::EncodeError)?;
                    }
                    Ok(())
                }),
                ClientExtension::SignatureAlgorithmsCert {
                    supported_signature_algorithms,
                } => buf.with_u16_length(|buf| {
                    for &a in supported_signature_algorithms {
                        buf.push_u16(a as u16).map_err(|_| TlsError::EncodeError)?;
                    }
                    Ok(())
                }),
                ClientExtension::SupportedGroups { supported_groups } => {
                    buf.with_u16_length(|buf| {
                        for &g in supported_groups {
                            buf.push_u16(g as u16).map_err(|_| TlsError::EncodeError)?;
                        }
                        Ok(())
                    })
                }
                ClientExtension::KeyShare(key_share) => key_share.encode(buf),
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
                    buf.push(*len as u8).map_err(|_| TlsError::EncodeError)
                }
            }
        })
    }
}
