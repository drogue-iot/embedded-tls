use crate::application_data::ApplicationData;
use crate::buffer::*;
use crate::change_cipher_spec::ChangeCipherSpec;
use crate::config::{Config, TlsCipherSuite};
use crate::content_types::ContentType;
use crate::handshake::client_hello::ClientHello;
use crate::handshake::{ClientHandshake, ServerHandshake};
use crate::key_schedule::KeySchedule;
use crate::{AsyncRead, AsyncWrite, TlsError};
use aes_gcm::aead::Buffer;
use aes_gcm::aead::{AeadInPlace, NewAead};
use core::fmt::{Debug, Formatter};
use core::ops::Range;
use digest::generic_array::typenum::Unsigned;
use digest::FixedOutput;
use heapless::{consts::*, ArrayLength, Vec};
use p256::ecdh::EphemeralSecret;
use rand_core::{CryptoRng, RngCore};
use sha2::Digest;

pub enum ClientRecord<'config, 'a, R, CipherSuite>
where
    R: CryptoRng + RngCore + Copy,
    // N: ArrayLength<u8>,
    CipherSuite: TlsCipherSuite,
{
    Handshake(ClientHandshake<'config, R, CipherSuite>),
    EncryptedHandshake(ClientHandshake<'config, R, CipherSuite>),
    ApplicationData(&'a [u8]),
}

impl<'config, 'a, RNG, CipherSuite> ClientRecord<'config, 'a, RNG, CipherSuite>
where
    RNG: CryptoRng + RngCore + Copy,
    //N: ArrayLength<u8>,
    CipherSuite: TlsCipherSuite,
{
    pub fn content_type(&self) -> ContentType {
        match self {
            ClientRecord::Handshake(_) => ContentType::Handshake,
            ClientRecord::EncryptedHandshake(_) => ContentType::ApplicationData,
            ClientRecord::ApplicationData(_) => ContentType::ApplicationData,
        }
    }

    pub fn client_hello(config: &'config Config<RNG, CipherSuite>) -> Self {
        ClientRecord::Handshake(ClientHandshake::ClientHello(ClientHello::new(config)))
    }

    pub(crate) fn encode(
        &self,
        enc_buf: &mut [u8],
        key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
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
                let pos = buf.len();
                buf.release();

                let mut wrapped = CryptoBuffer::wrap(&mut enc_buf[pos..]);
                handshake.encode(&mut wrapped)?;
                wrapped
                    .push(ContentType::Handshake as u8)
                    .map_err(|_| TlsError::EncodeError)?;

                let client_key = key_schedule.get_client_key()?;
                let nonce = &key_schedule.get_client_nonce()?;
                info!("encrypt key {:02x?}", client_key);
                info!("encrypt nonce {:02x?}", nonce);
                info!("plaintext {} {:02x?}", wrapped.len(), wrapped.as_slice(),);
                //let crypto = Aes128Gcm::new_varkey(&self.key_schedule.get_client_key()).unwrap();
                let crypto = CipherSuite::Cipher::new(&client_key);
                let len = wrapped.len() + <CipherSuite::Cipher as AeadInPlace>::TagSize::to_usize();

                if len > wrapped.capacity() {
                    return Err(TlsError::InsufficientSpace);
                }

                info!(
                    "output size {}",
                    <CipherSuite::Cipher as AeadInPlace>::TagSize::to_usize()
                );
                let len_bytes = (len as u16).to_be_bytes();
                let additional_data = [
                    ContentType::ApplicationData as u8,
                    0x03,
                    0x03,
                    len_bytes[0],
                    len_bytes[1],
                ];

                crypto
                    .encrypt_in_place(nonce, &additional_data, &mut wrapped)
                    .map_err(|_| TlsError::InvalidApplicationData)?;
                let enc_len = wrapped.len();
                wrapped.release();

                (
                    None,
                    CryptoBuffer::wrap_with_pos(&mut enc_buf[..], pos + enc_len),
                )
            }
            ClientRecord::ApplicationData(data) => {
                let pos = buf.len();
                buf.release();

                let mut wrapped = CryptoBuffer::wrap(&mut enc_buf[pos..]);
                wrapped
                    .extend_from_slice(data)
                    .map_err(|_| TlsError::EncodeError)?;
                wrapped
                    .push(ContentType::ApplicationData as u8)
                    .map_err(|_| TlsError::EncodeError)?;

                let client_key = key_schedule.get_client_key()?;
                let nonce = &key_schedule.get_client_nonce()?;
                info!("encrypt key {:02x?}", client_key);
                info!("encrypt nonce {:02x?}", nonce);
                info!("plaintext {} {:02x?}", wrapped.len(), wrapped.as_slice(),);
                //let crypto = Aes128Gcm::new_varkey(&self.key_schedule.get_client_key()).unwrap();
                let crypto = CipherSuite::Cipher::new(&client_key);
                let len = wrapped.len() + <CipherSuite::Cipher as AeadInPlace>::TagSize::to_usize();

                if len > wrapped.capacity() {
                    return Err(TlsError::InsufficientSpace);
                }

                info!(
                    "output size {}",
                    <CipherSuite::Cipher as AeadInPlace>::TagSize::to_usize()
                );
                let len_bytes = (len as u16).to_be_bytes();
                let additional_data = [
                    ContentType::ApplicationData as u8,
                    0x03,
                    0x03,
                    len_bytes[0],
                    len_bytes[1],
                ];

                crypto
                    .encrypt_in_place(nonce, &additional_data, &mut wrapped)
                    .map_err(|_| TlsError::InvalidApplicationData)?;
                let enc_len = wrapped.len();
                wrapped.release();

                (
                    None,
                    CryptoBuffer::wrap_with_pos(&mut enc_buf[..], pos + enc_len),
                )
            }
        };

        let record_length = (buf.len() as u16 - record_length_marker as u16) - 2;

        info!("record len {}", record_length);

        buf.set(record_length_marker, record_length.to_be_bytes()[0])
            .map_err(|_| TlsError::EncodeError)?;
        buf.set(record_length_marker + 1, record_length.to_be_bytes()[1])
            .map_err(|_| TlsError::EncodeError)?;

        Ok((buf.len(), range))
    }

    /*
    fn encrypt<'m>(
        key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
        buf: CryptoBuffer<'m>,
    ) -> Result<ApplicationData<'m>, TlsError> {
        let client_key = key_schedule.get_client_key()?;
        let nonce = &key_schedule.get_client_nonce()?;
        info!("encrypt key {:02x?}", client_key);
        info!("encrypt nonce {:02x?}", nonce);
        info!("plaintext {} {:02x?}", buf.len(), buf.as_slice(),);
        //let crypto = Aes128Gcm::new_varkey(&self.key_schedule.get_client_key()).unwrap();
        let crypto = CipherSuite::Cipher::new(&client_key);
        let len = buf.len() + <CipherSuite::Cipher as AeadInPlace>::TagSize::to_usize();

        if len > buf.capacity() {
            return Err(TlsError::InsufficientSpace);
        }

        info!(
            "output size {}",
            <CipherSuite::Cipher as AeadInPlace>::TagSize::to_usize()
        );
        let len_bytes = (len as u16).to_be_bytes();
        let additional_data = [
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            len_bytes[0],
            len_bytes[1],
        ];

        crypto
            .encrypt_in_place(nonce, &additional_data, &mut buf)
            .map_err(|_| TlsError::InvalidApplicationData)?;

        info!("aad {:x?}", additional_data);
        //        info!("encrypted data: {:x?}", &buf[..content_length]);
        //        info!("ciphertext ## {} ## {:x?}", , &buf);
        //Ok(())
        Ok(ApplicationData::new(buf, additional_data))
        //let result =
        //crypto.decrypt_in_place(&self.key_schedule.get_server_nonce(), &header, &mut data);
        //Ok(())
    }
    */
}

#[derive(Debug)]
pub enum ServerRecord<'a, N: ArrayLength<u8>> {
    Handshake(ServerHandshake<N>),
    ChangeCipherSpec(ChangeCipherSpec),
    Alert,
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

        info!("receive header {:x?}", &header);

        match ContentType::of(header[0]) {
            None => Err(TlsError::InvalidRecord),
            Some(content_type) => {
                let content_length = u16::from_be_bytes([header[3], header[4]]) as usize;
                info!(
                    "Content length: {}, rx_buf: {}, pos: {}",
                    content_length,
                    rx_buf.len(),
                    pos
                );
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
