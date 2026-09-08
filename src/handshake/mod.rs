//use p256::elliptic_curve::AffinePoint;
use crate::CertificateVerify;
use crate::TlsError;
use crate::crypto_traits::TlsHash;
use crate::handshake::certificate::CertificateRef;
use crate::handshake::certificate_request::CertificateRequestRef;
use crate::handshake::certificate_verify::CertificateVerifyRef;
use crate::handshake::client_hello::ClientHello;
use crate::handshake::encrypted_extensions::EncryptedExtensions;
use crate::handshake::finished::Finished;
use crate::handshake::new_session_ticket::NewSessionTicket;
use crate::handshake::server_hello::ServerHello;
use crate::key_schedule::ProviderHashOutputSize;
use crate::parse_buffer::{ParseBuffer, ParseError};
use crate::{CryptoProvider, buffer::CryptoBuffer, key_schedule::WriteKeySchedule};
use core::fmt::{Debug, Formatter};

pub mod binder;
pub mod certificate;
pub mod certificate_request;
pub mod certificate_verify;
pub mod client_hello;
pub mod encrypted_extensions;
pub mod finished;
pub mod new_session_ticket;
pub mod server_hello;

const LEGACY_VERSION: u16 = 0x0303;

type Random = [u8; 32];

#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
}

impl HandshakeType {
    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        match buf.read_u8()? {
            1 => Ok(HandshakeType::ClientHello),
            2 => Ok(HandshakeType::ServerHello),
            4 => Ok(HandshakeType::NewSessionTicket),
            5 => Ok(HandshakeType::EndOfEarlyData),
            8 => Ok(HandshakeType::EncryptedExtensions),
            11 => Ok(HandshakeType::Certificate),
            13 => Ok(HandshakeType::CertificateRequest),
            15 => Ok(HandshakeType::CertificateVerify),
            20 => Ok(HandshakeType::Finished),
            24 => Ok(HandshakeType::KeyUpdate),
            254 => Ok(HandshakeType::MessageHash),
            _ => Err(ParseError::InvalidData),
        }
    }

    #[allow(dead_code)]
    pub fn encode(self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.push(self as u8).map_err(|_| TlsError::EncodeError)
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ClientHandshake<'config, 'a, Provider>
where
    Provider: CryptoProvider,
{
    ClientHello(ClientHello<'config, Provider::CipherSuite>),
    ClientCertificate(CertificateRef<'a>),
    ClientCertificateVerify(CertificateVerify),
    Finished(Finished<ProviderHashOutputSize<Provider>>),
}

impl<Provider> ClientHandshake<'_, '_, Provider>
where
    Provider: CryptoProvider,
{
    #[allow(dead_code)]
    pub fn handshake_type(&self) -> HandshakeType {
        match self {
            ClientHandshake::ClientHello(_) => HandshakeType::ClientHello,
            ClientHandshake::Finished(_) => HandshakeType::Finished,
            ClientHandshake::ClientCertificate(_) => HandshakeType::Certificate,
            ClientHandshake::ClientCertificateVerify(_) => HandshakeType::CertificateVerify,
        }
    }

    fn encode_inner(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        match self {
            ClientHandshake::ClientHello(inner) => inner.encode(buf),
            ClientHandshake::Finished(inner) => inner.encode(buf),
            ClientHandshake::ClientCertificate(inner) => inner.encode(buf),
            ClientHandshake::ClientCertificateVerify(inner) => inner.encode(buf),
        }
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.push(self.handshake_type() as u8)
            .map_err(|_| TlsError::EncodeError)?;

        buf.with_u24_length(|buf| self.encode_inner(buf))
    }

    pub fn finalize(
        &self,
        buf: &mut CryptoBuffer,
        transcript: &mut Provider::Hash,
        write_key_schedule: &mut WriteKeySchedule<Provider>,
    ) -> Result<(), TlsError> {
        let enc_buf = buf.as_mut_slice();
        if let ClientHandshake::ClientHello(hello) = self {
            hello.finalize(enc_buf, transcript, write_key_schedule)
        } else {
            transcript.update(enc_buf);
            Ok(())
        }
    }

    pub fn finalize_encrypted(buf: &mut CryptoBuffer, transcript: &mut Provider::Hash) {
        let enc_buf = buf.as_slice();
        let end = enc_buf.len();
        transcript.update(&enc_buf[0..end]);
    }
}

#[allow(clippy::large_enum_variant)]
pub enum ServerHandshake<'a, Provider: CryptoProvider> {
    ServerHello(ServerHello<'a>),
    EncryptedExtensions(EncryptedExtensions<'a>),
    NewSessionTicket(NewSessionTicket<'a>),
    Certificate(CertificateRef<'a>),
    CertificateRequest(CertificateRequestRef<'a>),
    CertificateVerify(CertificateVerifyRef<'a>),
    Finished(Finished<ProviderHashOutputSize<Provider>>),
}

impl<Provider: CryptoProvider> ServerHandshake<'_, Provider> {
    #[allow(dead_code)]
    pub fn handshake_type(&self) -> HandshakeType {
        match self {
            ServerHandshake::ServerHello(_) => HandshakeType::ServerHello,
            ServerHandshake::EncryptedExtensions(_) => HandshakeType::EncryptedExtensions,
            ServerHandshake::NewSessionTicket(_) => HandshakeType::NewSessionTicket,
            ServerHandshake::Certificate(_) => HandshakeType::Certificate,
            ServerHandshake::CertificateRequest(_) => HandshakeType::CertificateRequest,
            ServerHandshake::CertificateVerify(_) => HandshakeType::CertificateVerify,
            ServerHandshake::Finished(_) => HandshakeType::Finished,
        }
    }
}

impl<Provider: CryptoProvider> Debug for ServerHandshake<'_, Provider> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            ServerHandshake::ServerHello(inner) => Debug::fmt(inner, f),
            ServerHandshake::EncryptedExtensions(inner) => Debug::fmt(inner, f),
            ServerHandshake::Certificate(inner) => Debug::fmt(inner, f),
            ServerHandshake::CertificateRequest(inner) => Debug::fmt(inner, f),
            ServerHandshake::CertificateVerify(inner) => Debug::fmt(inner, f),
            ServerHandshake::Finished(inner) => Debug::fmt(inner, f),
            ServerHandshake::NewSessionTicket(inner) => Debug::fmt(inner, f),
        }
    }
}

#[cfg(feature = "defmt")]
impl<'a, Provider: CryptoProvider> defmt::Format for ServerHandshake<'a, Provider> {
    fn format(&self, f: defmt::Formatter<'_>) {
        match self {
            ServerHandshake::ServerHello(inner) => defmt::write!(f, "{}", inner),
            ServerHandshake::EncryptedExtensions(inner) => defmt::write!(f, "{}", inner),
            ServerHandshake::Certificate(inner) => defmt::write!(f, "{}", inner),
            ServerHandshake::CertificateRequest(inner) => defmt::write!(f, "{}", inner),
            ServerHandshake::CertificateVerify(inner) => defmt::write!(f, "{}", inner),
            ServerHandshake::Finished(inner) => defmt::write!(f, "{}", inner),
            ServerHandshake::NewSessionTicket(inner) => defmt::write!(f, "{}", inner),
        }
    }
}

impl<'a, Provider: CryptoProvider> ServerHandshake<'a, Provider> {
    pub fn read(buf: &mut ParseBuffer<'a>, digest: &mut Provider::Hash) -> Result<Self, TlsError> {
        let handshake_start = buf.offset();
        let mut handshake = Self::parse(buf)?;
        let handshake_end = buf.offset();

        if let ServerHandshake::Finished(finished) = &mut handshake {
            let hash = digest.clone();
            let mut out = Default::default();
            hash.finalize_into(&mut out);
            finished.hash.replace(out);
        }

        digest.update(&buf.as_slice()[handshake_start..handshake_end]);

        Ok(handshake)
    }

    fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, TlsError> {
        let handshake_type = HandshakeType::parse(buf).map_err(|_| TlsError::InvalidHandshake)?;

        trace!("handshake = {:?}", handshake_type);

        let content_len = buf.read_u24().map_err(|_| TlsError::InvalidHandshake)?;

        let handshake = match handshake_type {
            //HandshakeType::ClientHello => {}
            HandshakeType::ServerHello => ServerHandshake::ServerHello(ServerHello::parse(buf)?),
            HandshakeType::NewSessionTicket => {
                ServerHandshake::NewSessionTicket(NewSessionTicket::parse(buf)?)
            }
            //HandshakeType::EndOfEarlyData => {}
            HandshakeType::EncryptedExtensions => {
                ServerHandshake::EncryptedExtensions(EncryptedExtensions::parse(buf)?)
            }
            HandshakeType::Certificate => ServerHandshake::Certificate(CertificateRef::parse(buf)?),

            HandshakeType::CertificateRequest => {
                ServerHandshake::CertificateRequest(CertificateRequestRef::parse(buf)?)
            }

            HandshakeType::CertificateVerify => {
                ServerHandshake::CertificateVerify(CertificateVerifyRef::parse(buf)?)
            }
            HandshakeType::Finished => {
                ServerHandshake::Finished(Finished::parse(buf, content_len)?)
            }
            //HandshakeType::KeyUpdate => {}
            //HandshakeType::MessageHash => {}
            t => {
                warn!("Unimplemented handshake type: {:?}", t);
                return Err(TlsError::Unimplemented);
            }
        };

        Ok(handshake)
    }
}
