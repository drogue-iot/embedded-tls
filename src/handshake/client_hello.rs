use heapless::{consts::*, Vec};
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::rand_core::{CryptoRng, RngCore};
use p256::EncodedPoint;

use crate::buffer::*;
use crate::config::{TlsCipherSuite, TlsConfig};
use crate::extensions::ClientExtension;
use crate::handshake::{Random, LEGACY_VERSION};
use crate::named_groups::NamedGroup;
use crate::signature_schemes::SignatureScheme;
use crate::supported_versions::{ProtocolVersion, TLS13};
use crate::TlsError;

pub struct ClientHello<'config, CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    config: &'config TlsConfig<'config, CipherSuite>,
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
            random: random,
            secret: EphemeralSecret::random(rng),
        }
    }

    pub(crate) fn encode(&self, buf: &mut CryptoBuffer<'_>) -> Result<(), TlsError> {
        let public_key = EncodedPoint::from(&self.secret.public_key());
        let public_key = public_key.as_ref();

        buf.extend_from_slice(&LEGACY_VERSION.to_be_bytes())
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
        buf.extend_from_slice(&2u16.to_be_bytes())
            .map_err(|_| TlsError::EncodeError)?;
        buf.extend_from_slice(&CipherSuite::CODE_POINT.to_be_bytes())
            .map_err(|_| TlsError::EncodeError)?;

        // compression methods, 1 byte of 0
        buf.push(1).map_err(|_| TlsError::EncodeError)?;
        buf.push(0).map_err(|_| TlsError::EncodeError)?;

        // extensions (1+)
        let mut extensions = Vec::<ClientExtension, U16>::new();
        let extension_length_marker = buf.len();
        buf.push(0).map_err(|_| TlsError::EncodeError)?;
        buf.push(0).map_err(|_| TlsError::EncodeError)?;

        let mut versions = Vec::<ProtocolVersion, U16>::new();
        versions.push(TLS13).map_err(|_| TlsError::EncodeError)?;

        extensions
            .push(ClientExtension::SupportedVersions { versions })
            .map_err(|_| TlsError::EncodeError)?;

        let mut supported_signature_algorithms = Vec::<SignatureScheme, U16>::new();
        supported_signature_algorithms.extend(self.config.signature_schemes.iter());
        extensions
            .push(ClientExtension::SignatureAlgorithms {
                supported_signature_algorithms,
            })
            .map_err(|_| TlsError::EncodeError)?;

        let mut supported_groups = Vec::<NamedGroup, U16>::new();
        supported_groups.extend(self.config.named_groups.iter());
        extensions
            .push(ClientExtension::SupportedGroups { supported_groups })
            .map_err(|_| TlsError::EncodeError)?;

        let mut opaque = Vec::<u8, U128>::new();
        opaque
            .extend_from_slice(public_key)
            .map_err(|_| TlsError::EncodeError)?;

        extensions
            .push(ClientExtension::KeyShare {
                group: NamedGroup::Secp256r1,
                opaque,
            })
            .map_err(|_| TlsError::EncodeError)?;

        if let Some(server_name) = self.config.server_name.as_ref() {
            // TODO Add SNI extension
            extensions
                .push(ClientExtension::ServerName { server_name })
                .map_err(|_| TlsError::EncodeError)?;
        }

        //extensions.push(ClientExtension::MaxFragmentLength(
        //self.config.max_fragment_length,
        //));

        // ----------------------------------------
        // ----------------------------------------

        for e in extensions {
            //info!("encode extension");
            e.encode(buf)?;
        }

        let extensions_length = (buf.len() as u16 - extension_length_marker as u16) - 2;
        //info!("extensions length: {:x?}", extensions_length.to_be_bytes());
        buf.set(extension_length_marker, extensions_length.to_be_bytes()[0])
            .map_err(|_| TlsError::EncodeError)?;
        buf.set(
            extension_length_marker + 1,
            extensions_length.to_be_bytes()[1],
        )
        .map_err(|_| TlsError::EncodeError)?;

        Ok(())
    }
}
