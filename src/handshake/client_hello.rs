use core::marker::PhantomData;

use crate::crypto_ops::TlsHash;
use heapless::Vec;
use p256::EncodedPoint;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::rand_core::RngCore;
use typenum::Unsigned;

use crate::TlsError;
use crate::config::{TlsCipherSuite, TlsConfig};
use crate::extensions::extension_data::alpn::AlpnProtocolNameList;
use crate::extensions::extension_data::key_share::{KeyShareClientHello, KeyShareEntry};
use crate::extensions::extension_data::pre_shared_key::PreSharedKeyClientHello;
use crate::extensions::extension_data::psk_key_exchange_modes::{
    PskKeyExchangeMode, PskKeyExchangeModes,
};
use crate::extensions::extension_data::server_name::ServerNameList;
use crate::extensions::extension_data::signature_algorithms::SignatureAlgorithms;
use crate::extensions::extension_data::supported_groups::{NamedGroup, SupportedGroups};
use crate::extensions::extension_data::supported_versions::{SupportedVersionsClientHello, TLS13};
use crate::extensions::messages::ClientHelloExtension;
use crate::handshake::{LEGACY_VERSION, Random};
use crate::key_schedule::{HashOutputSize, WriteKeySchedule};
use crate::{CryptoProvider, buffer::CryptoBuffer};
use crate::parse_buffer::ParseBuffer;

pub struct ClientHello<'config, CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub(crate) config: &'config TlsConfig<'config>,
    random: Random,
    cipher_suite: PhantomData<CipherSuite>,
    pub(crate) secret: EphemeralSecret,
}

impl<'config, CipherSuite> ClientHello<'config, CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub fn new<Provider>(config: &'config TlsConfig<'config>, mut provider: Provider) -> Self
    where
        Provider: CryptoProvider,
    {
        let mut random = [0; 32];
        provider.rng().fill_bytes(&mut random);

        Self {
            config,
            random,
            cipher_suite: PhantomData,
            secret: EphemeralSecret::random(&mut provider.rng()),
        }
    }

    pub(crate) fn encode(&self, buf: &mut CryptoBuffer<'_>) -> Result<(), TlsError> {
        let public_key = EncodedPoint::from(&self.secret.public_key());
        let public_key = public_key.as_ref();

        buf.push_u16(LEGACY_VERSION)
            .map_err(|_| TlsError::EncodeError)?;
        buf.extend_from_slice(&self.random)
            .map_err(|_| TlsError::EncodeError)?;

        // session id (empty)
        buf.push(0).map_err(|_| TlsError::EncodeError)?;

        // cipher suites (2+)
        //buf.extend_from_slice(&((self.config.cipher_suites.len() * 2) as u16).to_be_bytes());
        //for c in self.config.cipher_suites.iter() {
        //buf.extend_from_slice(&(*c as u16).to_be_bytes());
        //}
        buf.push_u16(2).map_err(|_| TlsError::EncodeError)?;
        buf.push_u16(CipherSuite::CODE_POINT)
            .map_err(|_| TlsError::EncodeError)?;

        // compression methods, 1 byte of 0
        buf.push(1).map_err(|_| TlsError::EncodeError)?;
        buf.push(0).map_err(|_| TlsError::EncodeError)?;

        // extensions (1+)
        buf.with_u16_length(|buf| {
            // Section 4.2.1.  Supported Versions
            // Implementations of this specification MUST send this extension in the
            // ClientHello containing all versions of TLS which they are prepared to
            // negotiate
            ClientHelloExtension::SupportedVersions(SupportedVersionsClientHello {
                versions: Vec::from_slice(&[TLS13]).unwrap(),
            })
            .encode(buf)?;

            ClientHelloExtension::SignatureAlgorithms(SignatureAlgorithms {
                supported_signature_algorithms: self.config.signature_schemes.clone(),
            })
            .encode(buf)?;

            if let Some(max_fragment_length) = self.config.max_fragment_length {
                ClientHelloExtension::MaxFragmentLength(max_fragment_length).encode(buf)?;
            }

            ClientHelloExtension::SupportedGroups(SupportedGroups {
                supported_groups: self.config.named_groups.clone(),
            })
            .encode(buf)?;

            ClientHelloExtension::PskKeyExchangeModes(PskKeyExchangeModes {
                modes: Vec::from_slice(&[PskKeyExchangeMode::PskDheKe]).unwrap(),
            })
            .encode(buf)?;

            ClientHelloExtension::KeyShare(KeyShareClientHello {
                client_shares: Vec::from_slice(&[KeyShareEntry {
                    group: NamedGroup::Secp256r1,
                    opaque: public_key,
                }])
                .unwrap(),
            })
            .encode(buf)?;

            if let Some(server_name) = self.config.server_name {
                ClientHelloExtension::ServerName(ServerNameList::single(server_name))
                    .encode(buf)?;
            }

            if let Some(alpn_protocols) = self.config.alpn_protocols {
                let mut protos = Vec::new();
                for p in alpn_protocols {
                    let _ = protos.push(*p);
                }
                ClientHelloExtension::ApplicationLayerProtocolNegotiation(AlpnProtocolNameList {
                    protocols: protos,
                })
                .encode(buf)?;
            }

            // Section 4.2
            // When multiple extensions of different types are present, the
            // extensions MAY appear in any order, with the exception of
            // "pre_shared_key" which MUST be the last extension in
            // the ClientHello.
            if let Some((_, identities)) = &self.config.psk {
                ClientHelloExtension::PreSharedKey(PreSharedKeyClientHello {
                    identities: identities.clone(),
                    hash_size: <CipherSuite::Hash as TlsHash>::OutputSize::to_usize(),
                })
                .encode(buf)?;
            }

            Ok(())
        })?;

        Ok(())
    }

    pub fn finalize(
        &self,
        enc_buf: &mut [u8],
        transcript: &mut CipherSuite::Hash,
        write_key_schedule: &mut WriteKeySchedule<CipherSuite>,
    ) -> Result<(), TlsError> {
        // Special case for PSK which needs to:
        //
        // 1. Add the client hello without the binders to the transcript
        // 2. Create the binders for each identity using the transcript
        // 3. Add the rest of the client hello.
        //
        // This causes a few issues since lengths must be correctly inside the payload,
        // but won't actually be added to the record buffer until the end.
        if let Some((_, identities)) = &self.config.psk {
            let binders_len = identities.len() * (1 + HashOutputSize::<CipherSuite>::to_usize());

            let binders_pos = enc_buf.len() - binders_len;

            // NOTE: Exclude the binders_len itself from the digest
            transcript.update(&enc_buf[0..binders_pos - 2]);

            // Append after the client hello data. Sizes have already been set.
            let mut buf = CryptoBuffer::wrap(&mut enc_buf[binders_pos..]);
            // Create a binder and encode for each identity
            for _id in identities {
                let binder = write_key_schedule.create_psk_binder(transcript)?;
                binder.encode(&mut buf)?;
            }

            transcript.update(&enc_buf[binders_pos - 2..]);
        } else {
            transcript.update(enc_buf);
        }

        Ok(())
    }
}

/// Parsed `ClientHello` for server-side processing.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ParsedClientHello<'a> {
    pub session_id: &'a [u8],
    pub key_shares: Vec<KeyShareEntry<'a>, 4>,
    pub alpn_protocols: Vec<&'a [u8], 4>,
}

impl<'a> ParsedClientHello<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, TlsError> {
        let legacy_version = buf.read_u16().map_err(|_| TlsError::InvalidHandshake)?;
        if legacy_version != LEGACY_VERSION {
            return Err(TlsError::InvalidHandshake);
        }

        // Random (skip, not needed by server currently)
        buf.slice(32).map_err(|_| TlsError::InvalidHandshake)?;

        // Session ID
        let session_id_len = buf.read_u8().map_err(|_| TlsError::InvalidSessionIdLength)?;
        let session_id = buf
            .slice(session_id_len as usize)
            .map_err(|_| TlsError::InvalidSessionIdLength)?
            .as_slice();

        // Cipher suites (skip over, we use the compile-time CipherSuite)
        let cipher_suites_len = buf.read_u16().map_err(|_| TlsError::InvalidHandshake)? as usize;
        buf.slice(cipher_suites_len).map_err(|_| TlsError::InvalidHandshake)?;

        // Compression methods
        let compression_len = buf.read_u8().map_err(|_| TlsError::InvalidHandshake)?;
        buf.slice(compression_len as usize)
            .map_err(|_| TlsError::InvalidHandshake)?;

        // Extensions
        let extensions = ClientHelloExtension::parse_vector::<16>(buf)?;

        let mut key_shares = Vec::new();
        let mut alpn_protocols = Vec::new();
        let mut has_tls13 = false;

        for ext in &extensions {
            match ext {
                ClientHelloExtension::KeyShare(ks) => {
                    for share in &ks.client_shares {
                        let _ = key_shares.push(share.clone());
                    }
                }
                ClientHelloExtension::SupportedVersions(sv) => {
                    for v in &sv.versions {
                        if *v == TLS13 {
                            has_tls13 = true;
                        }
                    }
                }
                ClientHelloExtension::ApplicationLayerProtocolNegotiation(alpn) => {
                    for proto in &alpn.protocols {
                        let _ = alpn_protocols.push(*proto);
                    }
                }
                _ => {}
            }
        }

        if !has_tls13 {
            return Err(TlsError::InvalidSupportedVersions);
        }

        Ok(Self {
            session_id,
            key_shares,
            alpn_protocols,
        })
    }

}
