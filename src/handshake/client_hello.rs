use digest::OutputSizeUser;
use heapless::Vec;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::rand_core::{CryptoRng, RngCore};
use p256::EncodedPoint;

use crate::buffer::*;
use crate::config::{TlsCipherSuite, TlsConfig};
use crate::extensions::{ClientExtension, PskKeyExchangeMode};
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
        let extension_length_marker = buf.len();
        buf.push(0).map_err(|_| TlsError::EncodeError)?;
        buf.push(0).map_err(|_| TlsError::EncodeError)?;

        ClientExtension::SupportedVersions {
            versions: Vec::from_slice(&[TLS13]).unwrap(),
        }
        .encode(buf)?;

        ClientExtension::SignatureAlgorithms {
            supported_signature_algorithms: self.config.signature_schemes.clone(),
        }
        .encode(buf)?;

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

        if let Some(server_name) = self.config.server_name.as_ref() {
            // TODO Add SNI extension
            ClientExtension::ServerName { server_name }.encode(buf)?;
        }

        // IMPORTANT: The pre shared keys must be encoded last, since we encode the binders
        // at a later stage
        if let Some((_, identities)) = &self.config.psk {
            ClientExtension::PreSharedKey {
                identities: identities.clone(),
                hash_size: <CipherSuite::Hash as OutputSizeUser>::output_size(),
            }
            .encode(buf)?;
        }

        //extensions.push(ClientExtension::MaxFragmentLength(
        //self.config.max_fragment_length,
        //));

        // ----------------------------------------
        // ----------------------------------------

        let extensions_length = (buf.len() - extension_length_marker - 2) as u16;
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
