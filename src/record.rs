use crate::application_data::ApplicationData;
use crate::change_cipher_spec::ChangeCipherSpec;
use crate::config::{Config, TlsCipherSuite};
use crate::content_types::ContentType;
use crate::handshake::client_hello::ClientHello;
use crate::handshake::{ClientHandshake, ServerHandshake};
use crate::{AsyncRead, AsyncWrite, TlsError};
use core::ops::Range;
use heapless::{ArrayLength, Vec};
use rand_core::{CryptoRng, RngCore};
use sha2::Digest;

pub enum ClientRecord<'config, R, CipherSuite>
where
    R: CryptoRng + RngCore + Copy,
    // N: ArrayLength<u8>,
    CipherSuite: TlsCipherSuite,
{
    Handshake(ClientHandshake<'config, R, CipherSuite>),
    ApplicationData(ApplicationData<'config>),
}

impl<'config, RNG, CipherSuite> ClientRecord<'config, RNG, CipherSuite>
where
    RNG: CryptoRng + RngCore + Copy,
    //N: ArrayLength<u8>,
    CipherSuite: TlsCipherSuite,
{
    pub fn content_type(&self) -> ContentType {
        match self {
            ClientRecord::Handshake(_) => ContentType::Handshake,
            ClientRecord::ApplicationData(_) => ContentType::ApplicationData,
        }
    }

    pub fn client_hello(config: &'config Config<RNG, CipherSuite>) -> Self {
        ClientRecord::Handshake(ClientHandshake::ClientHello(ClientHello::new(config)))
    }

    pub fn encode<O: ArrayLength<u8>>(
        &self,
        buf: &mut Vec<u8, O>,
    ) -> Result<Option<Range<usize>>, TlsError> {
        match self {
            ClientRecord::Handshake(_) => {
                buf.push(ContentType::Handshake as u8)
                    .map_err(|_| TlsError::EncodeError)?;
                buf.extend_from_slice(&[0x03, 0x01])
                    .map_err(|_| TlsError::EncodeError)?;
            }
            ClientRecord::ApplicationData(_) => {
                buf.push(ContentType::ApplicationData as u8)
                    .map_err(|_| TlsError::EncodeError)?;
                buf.extend_from_slice(&[0x03, 0x03])
                    .map_err(|_| TlsError::EncodeError)?;
            }
        }

        let record_length_marker = buf.len();
        buf.push(0).map_err(|_| TlsError::EncodeError)?;
        buf.push(0).map_err(|_| TlsError::EncodeError)?;

        let range = match self {
            ClientRecord::Handshake(handshake) => Some(handshake.encode(buf)?),
            ClientRecord::ApplicationData(application_data) => {
                info!("Enoding record data {:?}", application_data.data);
                buf.extend(application_data.data.iter());
                None
            }
        };

        let record_length = (buf.len() as u16 - record_length_marker as u16) - 2;

        info!("record len {}", record_length);

        buf[record_length_marker] = record_length.to_be_bytes()[0];
        buf[record_length_marker + 1] = record_length.to_be_bytes()[1];

        Ok(range)
    }
}

#[derive(Debug)]
pub enum ServerRecord<'a, N: ArrayLength<u8>> {
    Handshake(ServerHandshake<N>),
    ChangeCipherSpec(ChangeCipherSpec),
    Alert,
    ApplicationData(ApplicationData<'a>),
}

impl<'a, N: ArrayLength<u8>> ServerRecord<'a, N> {
    pub async fn read<T: AsyncWrite + AsyncRead, D: Digest>(
        socket: &mut T,
        rx_buf: &'a mut [u8],
        digest: &mut D,
    ) -> Result<ServerRecord<'a, N>, TlsError> {
        let mut pos: usize = 0;
        let mut header: [u8; 5] = [0; 5];
        loop {
            pos += socket.read(&mut header[pos..5]).await?;
            if pos == 5 {
                break;
            }
        }

        info!("receive header {:x?}", &header);

        match ContentType::of(header[0]) {
            None => Err(TlsError::InvalidRecord),
            Some(content_type) => {
                let content_length = u16::from_be_bytes([header[3], header[4]]) as usize;
                if content_length > rx_buf.len() - pos {
                    return Err(TlsError::InsufficientSpace);
                }

                let rx_buf = &mut rx_buf[pos..];
                let mut pos = 0;
                while pos < content_length {
                    pos += socket
                        .read(&mut rx_buf[pos..content_length])
                        .await
                        .map_err(|_| TlsError::InvalidRecord)?;
                }

                match content_type {
                    ContentType::Invalid => Err(TlsError::Unimplemented),
                    ContentType::ChangeCipherSpec => Ok(ServerRecord::ChangeCipherSpec(
                        ChangeCipherSpec::read(&mut rx_buf[..content_length]).await?,
                    )),
                    ContentType::Alert => Err(TlsError::Unimplemented),
                    ContentType::Handshake => Ok(ServerRecord::Handshake(
                        ServerHandshake::read(&mut rx_buf[..content_length], digest).await?,
                    )),
                    ContentType::ApplicationData => Ok(ServerRecord::ApplicationData(
                        ApplicationData::new(&mut rx_buf[..content_length], header),
                    )),
                }
            }
        }
    }

    //pub fn parse<D: Digest>(buf: &[u8]) -> Result<Self, TlsError> {}
}
