use heapless::{consts::*, ArrayLength, Vec};

use crate::drivers::tls::cipher_suites::CipherSuite;
use crate::drivers::tls::crypto_engine::CryptoEngine;
use crate::drivers::tls::extensions::common::KeyShareEntry;
use crate::drivers::tls::extensions::server::ServerExtension;
use crate::drivers::tls::handshake::Random;
use crate::drivers::tls::named_groups::NamedGroup;
use crate::drivers::tls::parse_buffer::ParseBuffer;
use crate::drivers::tls::{AsyncRead, AsyncWrite, TlsError};
use p256::ecdh::{EphemeralSecret, SharedSecret};
use p256::PublicKey;
use sha2::Digest;

#[derive(Debug)]
pub struct ServerHello {
    random: Random,
    legacy_session_id_echo: Vec<u8, U32>,
    cipher_suite: CipherSuite,
    extensions: Vec<ServerExtension, U16>,
}

impl ServerHello {
    pub async fn read<D: Digest, T: AsyncRead>(
        socket: &mut T,
        content_length: usize,
        digest: &mut D,
    ) -> Result<ServerHello, TlsError> {
        log::info!("parsing ServerHello");

        let mut buf = Vec::<u8, U1024>::new();
        buf.resize(content_length, 0);
        let mut pos = 0;

        loop {
            pos += socket.read(&mut buf[pos..content_length as usize]).await?;
            if pos == content_length {
                break;
            }
        }

        log::info!("server hello hash [{:x?}]", &buf[0..content_length]);
        digest.update(&buf);
        Self::parse(&mut ParseBuffer::new(&mut buf))
    }

    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, TlsError> {
        //let mut buf = ParseBuffer::new(&buf[0..content_length]);
        //let mut buf = ParseBuffer::new(&buf);

        let version = buf.read_u16().map_err(|_| TlsError::InvalidHandshake)?;

        let mut random = [0; 32];
        buf.fill(&mut random);

        let session_id_length = buf
            .read_u8()
            .map_err(|_| TlsError::InvalidSessionIdLength)?;

        //log::info!("sh 1");

        let mut session_id = Vec::<u8, U32>::new();
        buf.copy(&mut session_id, session_id_length as usize)
            .map_err(|_| TlsError::InvalidSessionIdLength)?;
        //log::info!("sh 2");

        let cipher_suite = buf.read_u16().map_err(|_| TlsError::InvalidCipherSuite)?;
        let cipher_suite = CipherSuite::of(cipher_suite).ok_or(TlsError::InvalidCipherSuite)?;

        ////log::info!("sh 3");
        // skip compression method, it's 0.
        buf.read_u8();

        //log::info!("sh 4");
        let extensions_length = buf
            .read_u16()
            .map_err(|_| TlsError::InvalidExtensionsLength)?;
        //log::info!("sh 5 {}", extensions_length);

        let extensions = ServerExtension::parse_vector(buf)?;
        //log::info!("sh 6");

        log::info!("server random {:x?}", random);
        log::info!("server session-id {:x?}", session_id);
        log::info!("server cipher_suite {:x?}", cipher_suite);
        log::info!("server extensions {:?}", extensions);

        Ok(Self {
            random,
            legacy_session_id_echo: session_id,
            cipher_suite,
            extensions,
        })
    }

    pub fn key_share(&self) -> Option<KeyShareEntry> {
        let key_share = self
            .extensions
            .iter()
            .find(|e| matches!(e, ServerExtension::KeyShare(..)))?;

        match key_share {
            ServerExtension::KeyShare(key_share) => Some(key_share.0.clone()),
            _ => None,
        }
    }

    pub fn calculate_shared_secret(&self, secret: &EphemeralSecret) -> Option<SharedSecret> {
        let server_key_share = self.key_share()?;
        let server_public_key =
            PublicKey::from_sec1_bytes(server_key_share.opaque.as_ref()).ok()?;
        Some(secret.diffie_hellman(&server_public_key))
    }

    pub fn initialize_crypto_engine(&self, secret: EphemeralSecret) -> Option<CryptoEngine> {
        let server_key_share = self.key_share()?;

        let group = server_key_share.group;

        let server_public_key =
            PublicKey::from_sec1_bytes(server_key_share.opaque.as_ref()).ok()?;
        let shared = secret.diffie_hellman(&server_public_key);

        Some(CryptoEngine::new(group, shared))
    }
}
