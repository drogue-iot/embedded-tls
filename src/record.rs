use crate::alert::*;
use crate::application_data::ApplicationData;
use crate::buffer::*;
use crate::change_cipher_spec::ChangeCipherSpec;
use crate::config::{TlsCipherSuite, TlsConfig};
use crate::content_types::ContentType;
use crate::handshake::client_hello::ClientHello;
use crate::handshake::{ClientHandshake, ServerHandshake};
use crate::{AsyncRead, AsyncWrite, TlsError};
use core::fmt::Debug;
use core::ops::Range;
use digest::{BlockInput, FixedOutput, Reset, Update};
use heapless::ArrayLength;
use rand_core::{CryptoRng, RngCore};
use sha2::Digest;

pub enum ClientRecord<'config, 'a, CipherSuite>
where
    // N: ArrayLength<u8>,
    CipherSuite: TlsCipherSuite,
{
    Handshake(ClientHandshake<'config, 'a, CipherSuite>),
    EncryptedHandshake(ClientHandshake<'config, 'a, CipherSuite>),
    ChangeCipherSpec(ChangeCipherSpec),
    ApplicationData(&'a [u8]),
}

impl<'config, 'a, CipherSuite> ClientRecord<'config, 'a, CipherSuite>
where
    //N: ArrayLength<u8>,
    CipherSuite: TlsCipherSuite,
{
    pub fn content_type(&self) -> ContentType {
        match self {
            ClientRecord::Handshake(_) => ContentType::Handshake,
            ClientRecord::EncryptedHandshake(_) => ContentType::ApplicationData,
            ClientRecord::ApplicationData(_) => ContentType::ApplicationData,
            ClientRecord::ChangeCipherSpec(_) => ContentType::ChangeCipherSpec,
        }
    }

    pub fn client_hello<RNG>(
        config: &'config TlsConfig<'config, CipherSuite>,
        rng: &mut RNG,
    ) -> Self
    where
        RNG: CryptoRng + RngCore,
    {
        ClientRecord::Handshake(ClientHandshake::ClientHello(ClientHello::new(config, rng)))
    }

    pub(crate) fn encode<
        N: Update + BlockInput + FixedOutput + Reset + Default + Clone,
        F: FnMut(&mut CryptoBuffer<'_>) -> Result<usize, TlsError>,
    >(
        &self,
        enc_buf: &mut [u8],
        transcript: &mut N,
        mut encrypt_fn: F,
    ) -> Result<(usize, Option<Range<usize>>), TlsError> {
        let mut buf = CryptoBuffer::wrap(enc_buf);
        match self {
            ClientRecord::Handshake(_) => {
                buf.push(ContentType::Handshake as u8)
                    .map_err(|_| TlsError::EncodeError)?;
                buf.extend_from_slice(&[0x03, 0x01])
                    .map_err(|_| TlsError::EncodeError)?;
            }
            ClientRecord::EncryptedHandshake(_) => {
                buf.push(ContentType::ApplicationData as u8)
                    .map_err(|_| TlsError::EncodeError)?;
                buf.extend_from_slice(&[0x03, 0x03])
                    .map_err(|_| TlsError::EncodeError)?;
            }
            ClientRecord::ApplicationData(_) => {
                buf.push(ContentType::ApplicationData as u8)
                    .map_err(|_| TlsError::EncodeError)?;
                buf.extend_from_slice(&[0x03, 0x03])
                    .map_err(|_| TlsError::EncodeError)?;
            }
            ClientRecord::ChangeCipherSpec(_) => {
                buf.push(ContentType::ChangeCipherSpec as u8)
                    .map_err(|_| TlsError::EncodeError)?;
                buf.extend_from_slice(&[0x03, 0x03])
                    .map_err(|_| TlsError::EncodeError)?;
            }
        }

        let record_length_marker = buf.len();
        buf.push(0).map_err(|_| TlsError::EncodeError)?;
        buf.push(0).map_err(|_| TlsError::EncodeError)?;

        let (range, mut buf) = match self {
            ClientRecord::Handshake(handshake) => {
                let range = handshake.encode(&mut buf)?;
                (Some(range), buf)
            }
            ClientRecord::EncryptedHandshake(handshake) => {
                let mut wrapped = buf.forward();

                let range = handshake.encode(&mut wrapped)?;
                N::update(transcript, &wrapped.as_slice()[range]);
                wrapped
                    .push(ContentType::Handshake as u8)
                    .map_err(|_| TlsError::EncodeError)?;

                let _ = encrypt_fn(&mut wrapped)?;
                (None, wrapped.rewind())
            }
            ClientRecord::ApplicationData(data) => {
                let mut wrapped = buf.forward();
                wrapped
                    .extend_from_slice(data)
                    .map_err(|_| TlsError::EncodeError)?;
                wrapped
                    .push(ContentType::ApplicationData as u8)
                    .map_err(|_| TlsError::EncodeError)?;

                let _ = encrypt_fn(&mut wrapped)?;
                (None, wrapped.rewind())
            }
            ClientRecord::ChangeCipherSpec(spec) => {
                spec.encode(&mut buf)?;
                (None, buf)
            }
        };

        let record_length = (buf.len() as u16 - record_length_marker as u16) - 2;

        // trace!("record len {}", record_length);

        buf.set(record_length_marker, record_length.to_be_bytes()[0])
            .map_err(|_| TlsError::EncodeError)?;
        buf.set(record_length_marker + 1, record_length.to_be_bytes()[1])
            .map_err(|_| TlsError::EncodeError)?;

        Ok((buf.len(), range))
    }
}

#[derive(Debug)]
pub enum ServerRecord<'a, N: ArrayLength<u8>> {
    Handshake(ServerHandshake<'a, N>),
    ChangeCipherSpec(ChangeCipherSpec),
    Alert(Alert),
    ApplicationData(ApplicationData<'a>),
}

impl<N: ArrayLength<u8>> ServerRecord<'_, N> {
    pub async fn read<'m, T: AsyncWrite + AsyncRead, D: Digest>(
        socket: &mut T,
        rx_buf: &'m mut [u8],
        digest: &mut D,
    ) -> Result<ServerRecord<'m, N>, TlsError> {
        let mut pos: usize = 0;
        let mut header: [u8; 5] = [0; 5];
        loop {
            pos += socket.read(&mut header[pos..5]).await?;
            if pos == 5 {
                break;
            }
        }

        // info!("receive header {:x?}", &header);

        match ContentType::of(header[0]) {
            None => Err(TlsError::InvalidRecord),
            Some(content_type) => {
                let content_length = u16::from_be_bytes([header[3], header[4]]) as usize;
                /*info!(
                    "Content length: {}, rx_buf: {}, pos: {}",
                    content_length,
                    rx_buf.len(),
                    pos
                );*/
                if content_length > rx_buf.len() - pos {
                    return Err(TlsError::InsufficientSpace);
                }

                let rx_buf = &mut rx_buf[pos..];
                let mut pos = 0;
                while pos < content_length {
                    let read = socket
                        .read(&mut rx_buf[pos..content_length])
                        .await
                        .map_err(|_| TlsError::InvalidRecord)?;
                    pos += read;
                    /*info!(
                        "Read block of {} bytes. Remaining: {}",
                        read,
                        content_length - pos
                    );*/
                }
                // info!("Read {} bytes", content_length);

                match content_type {
                    ContentType::Invalid => Err(TlsError::Unimplemented),
                    ContentType::ChangeCipherSpec => Ok(ServerRecord::ChangeCipherSpec(
                        ChangeCipherSpec::read(&mut rx_buf[..content_length]).await?,
                    )),
                    ContentType::Alert => Err(TlsError::Unimplemented),
                    ContentType::Handshake => Ok(ServerRecord::Handshake(
                        ServerHandshake::read(&mut rx_buf[..content_length], digest).await?,
                    )),
                    ContentType::ApplicationData => {
                        let mut buf = CryptoBuffer::wrap(rx_buf);
                        buf.truncate(content_length);

                        Ok(ServerRecord::ApplicationData(ApplicationData::new(
                            buf, header,
                        )))
                    }
                }
            }
        }
    }

    //pub fn parse<D: Digest>(buf: &[u8]) -> Result<Self, TlsError> {}
}