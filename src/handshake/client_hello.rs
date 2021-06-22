use heapless::{consts::*, ArrayLength, Vec};
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::rand_core::{CryptoRng, RngCore};
use p256::EncodedPoint;

use crate::config::{Config, TlsCipherSuite};
use crate::content_types::ContentType;
use crate::extensions::common::KeyShareEntry;
use crate::extensions::ClientExtension;
use crate::handshake::{HandshakeType, Random, LEGACY_VERSION};
use crate::named_groups::NamedGroup;
use crate::signature_schemes::SignatureScheme;
use crate::supported_versions::{ProtocolVersion, TLS13};
use crate::TlsError;
use sha2::Digest;

pub struct ClientHello<'config, RNG, CipherSuite>
where
    RNG: CryptoRng + RngCore + Copy,
    CipherSuite: TlsCipherSuite,
{
    config: &'config Config<RNG, CipherSuite>,
    random: Random,
    pub(crate) secret: EphemeralSecret,
}

impl<'config, RNG, CipherSuite> ClientHello<'config, RNG, CipherSuite>
where
    RNG: CryptoRng + RngCore + Copy,
    CipherSuite: TlsCipherSuite,
{
    pub fn new(config: &'config Config<RNG, CipherSuite>) -> Self {
        let mut random = [0; 32];
        let mut rng = config.rng;
        rng.fill_bytes(&mut random);

        Self {
            config,
            random: random,
            secret: EphemeralSecret::random(rng),
        }
    }

    pub fn encode<N: ArrayLength<u8>>(&self, buf: &mut Vec<u8, N>) -> Result<(), TlsError> {
        let public_key = EncodedPoint::from(&self.secret.public_key());
        let public_key = public_key.as_ref();

        buf.extend_from_slice(&LEGACY_VERSION.to_be_bytes());
        buf.extend_from_slice(&self.random);

        // session id (empty)
        buf.push(0);

        // cipher suites (2+)
        //buf.extend_from_slice(&((self.config.cipher_suites.len() * 2) as u16).to_be_bytes());
        //for c in self.config.cipher_suites.iter() {
        //buf.extend_from_slice(&(*c as u16).to_be_bytes());
        //}
        buf.extend_from_slice(&2u16.to_be_bytes());
        buf.extend_from_slice(&CipherSuite::CODE_POINT.to_be_bytes());

        // compression methods, 1 byte of 0
        buf.push(1);
        buf.push(0);

        // extensions (1+)
        let mut extensions = Vec::<ClientExtension, U16>::new();
        let extension_length_marker = buf.len();
        buf.push(0);
        buf.push(0);

        let mut versions = Vec::<ProtocolVersion, U16>::new();
        versions.push(TLS13);
        extensions.push(ClientExtension::SupportedVersions { versions });

        let mut supported_signature_algorithms = Vec::<SignatureScheme, U16>::new();
        supported_signature_algorithms.extend(self.config.signature_schemes.iter());
        extensions.push(ClientExtension::SignatureAlgorithms {
            supported_signature_algorithms,
        });

        let mut supported_groups = Vec::<NamedGroup, U16>::new();
        supported_groups.extend(self.config.named_groups.iter());
        extensions.push(ClientExtension::SupportedGroups { supported_groups });

        let mut opaque = Vec::<u8, U128>::new();
        opaque.extend_from_slice(public_key);

        extensions.push(ClientExtension::KeyShare {
            group: NamedGroup::Secp256r1,
            opaque,
        });

        //extensions.push(ClientExtension::MaxFragmentLength(
        //self.config.max_fragment_length,
        //));

        // ----------------------------------------
        // ----------------------------------------

        for e in extensions {
            info!("encode extension");
            e.encode(buf);
        }

        let extensions_length = (buf.len() as u16 - extension_length_marker as u16) - 2;
        info!("extensions length: {:x?}", extensions_length.to_be_bytes());
        buf[extension_length_marker] = extensions_length.to_be_bytes()[0];
        buf[extension_length_marker + 1] = extensions_length.to_be_bytes()[1];

        Ok(())
    }
}
