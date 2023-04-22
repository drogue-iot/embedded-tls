use digest::OutputSizeUser;
use heapless::Vec;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::rand_core::{CryptoRng, RngCore};
use p256::EncodedPoint;

use crate::buffer::*;
use crate::config::{TlsCipherSuite, TlsConfig};
use crate::extensions::client::{ClientExtension, PskKeyExchangeMode};
use crate::handshake::{Random, LEGACY_VERSION};
use crate::named_groups::NamedGroup;
use crate::supported_versions::TLS13;
use crate::TlsError;

pub struct ClientHello<'config, CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub(crate) config: &'config TlsConfig<'config, CipherSuite>,
    random: Random,
    pub(crate) secret: EphemeralSecret,
}

impl<'config, CipherSuite> ClientHello<'config, CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub fn new<RNG>(config: &'config TlsConfig<'config, CipherSuite>, rng: &mut RNG) -> Self
    where
        RNG: CryptoRng + RngCore,
    {
        let mut random = [0; 32];
        rng.fill_bytes(&mut random);

        Self {
            config,
            random,
            secret: EphemeralSecret::random(rng),
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
            ClientExtension::SupportedVersions {
                versions: Vec::from_slice(&[TLS13]).unwrap(),
            }
            .encode(buf)?;

            ClientExtension::SignatureAlgorithms {
                supported_signature_algorithms: self.config.signature_schemes.clone(),
            }
            .encode(buf)?;

            if let Some(max_fragment_length) = self.config.max_fragment_length {
                ClientExtension::MaxFragmentLength(max_fragment_length).encode(buf)?;
            }

            ClientExtension::SupportedGroups {
                supported_groups: self.config.named_groups.clone(),
            }
            .encode(buf)?;

            ClientExtension::PskKeyExchangeModes {
                modes: Vec::from_slice(&[PskKeyExchangeMode::PskDheKe]).unwrap(),
            }
            .encode(buf)?;

            ClientExtension::KeyShare {
                group: NamedGroup::Secp256r1,
                opaque: public_key,
            }
            .encode(buf)?;

            if let Some(server_name) = self.config.server_name {
                // TODO Add SNI extension
                ClientExtension::ServerName { server_name }.encode(buf)?;
            }

            // Section 4.2
            // When multiple extensions of different types are present, the
            // extensions MAY appear in any order, with the exception of
            // "pre_shared_key" which MUST be the last extension in
            // the ClientHello.
            if let Some((_, identities)) = &self.config.psk {
                ClientExtension::PreSharedKey {
                    identities: identities.clone(),
                    hash_size: <CipherSuite::Hash as OutputSizeUser>::output_size(),
                }
                .encode(buf)?;
            }

            Ok(())
        })?;

        Ok(())
    }
}
