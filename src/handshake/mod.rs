use generic_array::ArrayLength;

//use p256::elliptic_curve::AffinePoint;
use crate::buffer::*;
use crate::config::TlsCipherSuite;
use crate::handshake::certificate::CertificateRef;
use crate::handshake::certificate_request::CertificateRequestRef;
use crate::handshake::certificate_verify::CertificateVerify;
use crate::handshake::client_hello::ClientHello;
use crate::handshake::encrypted_extensions::EncryptedExtensions;
use crate::handshake::finished::Finished;
use crate::handshake::new_session_ticket::NewSessionTicket;
use crate::handshake::server_hello::ServerHello;
use crate::key_schedule::HashOutputSize;
use crate::parse_buffer::ParseBuffer;
use crate::TlsError;
use core::fmt::{Debug, Formatter};
use sha2::Digest;

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
    pub fn of(num: u8) -> Option<Self> {
        match num {
            1 => Some(HandshakeType::ClientHello),
            2 => Some(HandshakeType::ServerHello),
            4 => Some(HandshakeType::NewSessionTicket),
            5 => Some(HandshakeType::EndOfEarlyData),
            8 => Some(HandshakeType::EncryptedExtensions),
            11 => Some(HandshakeType::Certificate),
            13 => Some(HandshakeType::CertificateRequest),
            15 => Some(HandshakeType::CertificateVerify),
            20 => Some(HandshakeType::Finished),
            24 => Some(HandshakeType::KeyUpdate),
            254 => Some(HandshakeType::MessageHash),
            _ => None,
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub enum ClientHandshake<'config, 'a, CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    ClientCert(CertificateRef<'a>),
    ClientHello(ClientHello<'config, CipherSuite>),
    Finished(Finished<HashOutputSize<CipherSuite>>),
}

impl<'config, 'a, CipherSuite> ClientHandshake<'config, 'a, CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    fn handshake_type(&self) -> HandshakeType {
        match self {
            ClientHandshake::ClientHello(_) => HandshakeType::ClientHello,
            ClientHandshake::Finished(_) => HandshakeType::Finished,
            ClientHandshake::ClientCert(_) => HandshakeType::Certificate,
        }
    }

    fn encode_inner(&self, buf: &mut CryptoBuffer<'_>) -> Result<(), TlsError> {
        match self {
            ClientHandshake::ClientHello(inner) => inner.encode(buf),
            ClientHandshake::Finished(inner) => inner.encode(buf),
            ClientHandshake::ClientCert(inner) => inner.encode(buf),
        }
    }

    pub(crate) fn encode(&self, buf: &mut CryptoBuffer<'_>) -> Result<(), TlsError> {
        buf.push(self.handshake_type() as u8)
            .map_err(|_| TlsError::EncodeError)?;

        let content_length_marker = buf.len();
        buf.push_u24(0).map_err(|_| TlsError::EncodeError)?;

        self.encode_inner(buf)?;

        let content_length = (buf.len() - content_length_marker) as u32 - 3;
        buf.set_u24(content_length_marker, content_length)
            .map_err(|_| TlsError::EncodeError)?;

        //info!("hash [{:x?}]", &buf[content_marker..]);
        //digest.update(&buf[content_marker..]);

        Ok(())
    }
}

pub enum ServerHandshake<'a, N: ArrayLength<u8>> {
    ServerHello(ServerHello<'a>),
    EncryptedExtensions(EncryptedExtensions<'a>),
    NewSessionTicket(NewSessionTicket<'a>),
    Certificate(CertificateRef<'a>),
    CertificateRequest(CertificateRequestRef<'a>),
    CertificateVerify(CertificateVerify<'a>),
    Finished(Finished<N>),
}

impl<'a, N: ArrayLength<u8>> Debug for ServerHandshake<'a, N> {
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
impl<'a, N: ArrayLength<u8>> defmt::Format for ServerHandshake<'a, N> {
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

impl<'a, N: ArrayLength<u8>> ServerHandshake<'a, N> {
    pub fn read<D: Digest>(
        rx_buf: &'a mut [u8],
        digest: &mut D,
    ) -> Result<ServerHandshake<'a, N>, TlsError> {
        let header = rx_buf.get(0..4).ok_or(TlsError::InvalidHandshake)?;
        match HandshakeType::of(header[0]) {
            None => Err(TlsError::InvalidHandshake),
            Some(handshake_type) => {
                let length = u32::from_be_bytes([0, header[1], header[2], header[3]]) as usize;
                match handshake_type {
                    HandshakeType::ServerHello => {
                        // info!("hash [{:x?}]", &header);
                        digest.update(header);
                        Ok(ServerHandshake::ServerHello(ServerHello::read(
                            rx_buf
                                .get(4..length + 4)
                                .ok_or(TlsError::InvalidHandshake)?,
                            digest,
                        )?))
                    }
                    _ => Err(TlsError::Unimplemented), /*
                                                       HandshakeType::ClientHello => Err(TlsError::Unimplemented),
                                                       HandshakeType::NewSessionTicket => Err(TlsError::Unimplemented),
                                                       HandshakeType::EndOfEarlyData => Err(TlsError::Unimplemented),
                                                       HandshakeType::EncryptedExtensions => Err(TlsError::Unimplemented),
                                                       HandshakeType::Certificate => Err(TlsError::Unimplemented),
                                                       HandshakeType::CertificateRequest => Err(TlsError::Unimplemented),
                                                       HandshakeType::CertificateVerify => Err(TlsError::Unimplemented),
                                                       HandshakeType::Finished => Err(TlsError::Unimplemented),
                                                       HandshakeType::KeyUpdate => Err(TlsError::Unimplemented),
                                                       HandshakeType::MessageHash => Err(TlsError::Unimplemented),
                                                       */
                }
            }
        }
    }

    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<ServerHandshake<'a, N>, TlsError> {
        let handshake_type =
            HandshakeType::of(buf.read_u8().map_err(|_| TlsError::InvalidHandshake)?)
                .ok_or(TlsError::InvalidHandshake)?;

        // info!("Handshake type {:?}", handshake_type);

        let content_len = buf.read_u24().map_err(|_| TlsError::InvalidHandshake)?;

        match handshake_type {
            //HandshakeType::ClientHello => {}
            //HandshakeType::ServerHello => {}
            HandshakeType::NewSessionTicket => Ok(ServerHandshake::NewSessionTicket(
                NewSessionTicket::parse(buf)?,
            )),
            //HandshakeType::EndOfEarlyData => {}
            HandshakeType::EncryptedExtensions => {
                // todo, move digesting up
                Ok(ServerHandshake::EncryptedExtensions(
                    EncryptedExtensions::parse(buf)?,
                ))
            }
            HandshakeType::Certificate => {
                Ok(ServerHandshake::Certificate(CertificateRef::parse(buf)?))
            }

            HandshakeType::CertificateRequest => Ok(ServerHandshake::CertificateRequest(
                CertificateRequestRef::parse(buf)?,
            )),

            HandshakeType::CertificateVerify => Ok(ServerHandshake::CertificateVerify(
                CertificateVerify::parse(buf)?,
            )),
            HandshakeType::Finished => Ok(ServerHandshake::Finished(Finished::parse(
                buf,
                content_len,
            )?)),
            //HandshakeType::KeyUpdate => {}
            //HandshakeType::MessageHash => {}
            t => {
                warn!("Unimplemented handshake type: {:?}", t);
                Err(TlsError::Unimplemented)
            }
        }
    }
}
