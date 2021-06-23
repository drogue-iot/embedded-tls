use crate::config::{Config, TlsCipherSuite};
use crate::handshake::{ClientHandshake, ServerHandshake};
use crate::key_schedule::KeySchedule;
use crate::record::{ClientRecord, ServerRecord};
use crate::{AsyncRead, AsyncWrite, TlsError};
use aes_gcm::aead::Buffer;
use core::fmt::{Debug, Formatter};
use digest::generic_array::typenum::Unsigned;
use heapless::spsc::Queue;
use heapless::{consts::*, ArrayLength, Vec};
use p256::ecdh::EphemeralSecret;
use rand_core::{CryptoRng, RngCore};
use sha2::Digest;

use crate::application_data::ApplicationData;
use crate::buffer::CryptoBuffer;
use crate::content_types::ContentType;
use crate::parse_buffer::ParseBuffer;
use aes_gcm::aead::{AeadInPlace, NewAead};
use digest::FixedOutput;

enum State {
    ClientHello,
    ServerHello(EphemeralSecret),
    ServerCert,
    ServerCertVerify,
    ServerFinished,
    ClientFinished,
    ApplicationData,
}

impl Debug for State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match &self {
            State::ClientHello => write!(f, "ClientHello"),
            State::ServerHello(_) => write!(f, "ServerHello"),
            State::ServerCert => write!(f, "ServerCert"),
            State::ServerCertVerify => write!(f, "ServerCertVerify"),
            State::ServerFinished => write!(f, "ServerFinished"),
            State::ClientFinished => write!(f, "ClientFinished"),
            State::ApplicationData => write!(f, "ApplicationData"),
        }
    }
}

pub struct TlsConnection<'a, RNG, Socket, CipherSuite, TxBufLen, RxBufLen>
where
    RNG: CryptoRng + RngCore + Copy + 'static,
    Socket: AsyncRead + AsyncWrite + 'static,
    CipherSuite: TlsCipherSuite + 'static,
    TxBufLen: ArrayLength<u8>,
    RxBufLen: ArrayLength<u8>,
{
    delegate: Socket,
    config: &'a Config<RNG, CipherSuite>,
    state: Option<State>,
    key_schedule: KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
    tx_buf: Vec<u8, TxBufLen>,
    rx_buf: Vec<u8, RxBufLen>,
    queue: Queue<ServerRecord<'a, <CipherSuite::Hash as FixedOutput>::OutputSize>, U4>,
}

impl<'a, RNG, Socket, CipherSuite, TxBufLen, RxBufLen>
    TlsConnection<'a, RNG, Socket, CipherSuite, TxBufLen, RxBufLen>
where
    RNG: CryptoRng + RngCore + Copy + 'static,
    Socket: AsyncRead + AsyncWrite + 'static,
    CipherSuite: TlsCipherSuite,
    TxBufLen: ArrayLength<u8>,
    RxBufLen: ArrayLength<u8>,
{
    pub fn new(config: &'a Config<RNG, CipherSuite>, delegate: Socket) -> Self {
        Self {
            delegate,
            config,
            state: Some(State::ClientHello),
            key_schedule: KeySchedule::new(),
            tx_buf: Vec::new(),
            rx_buf: Vec::new(),
            queue: Queue::new(),
        }
    }

    fn encrypt<'m>(
        &self,
        buf: &'m mut [u8],
        content_length: usize,
    ) -> Result<ApplicationData<'m>, TlsError> {
        let client_key = self.key_schedule.get_client_key()?;
        let nonce = &self.key_schedule.get_client_nonce()?;
        info!("encrypt key {:02x?}", client_key);
        info!("encrypt nonce {:02x?}", nonce);
        info!(
            "plaintext {} {:02x?}",
            content_length,
            &buf[..content_length]
        );
        //let crypto = Aes128Gcm::new_varkey(&self.key_schedule.get_client_key()).unwrap();
        let crypto = CipherSuite::Cipher::new(&client_key);
        let len = content_length + <CipherSuite::Cipher as AeadInPlace>::TagSize::to_usize();

        if len > buf.len() {
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

        let mut crypto_buffer = CryptoBuffer::wrap(buf);
        crypto
            .encrypt_in_place(nonce, &additional_data, &mut crypto_buffer)
            .map_err(|_| TlsError::InvalidApplicationData)?;

        let encoded_length = crypto_buffer.len();
        info!("aad {:x?}", additional_data);
        //        info!("encrypted data: {:x?}", &buf[..content_length]);
        //        info!("ciphertext ## {} ## {:x?}", , &buf);
        //Ok(())
        Ok(ApplicationData::new(
            &mut buf[..encoded_length],
            additional_data,
        ))
        //let result =
        //crypto.decrypt_in_place(&self.key_schedule.get_server_nonce(), &header, &mut data);
        //Ok(())
    }

    async fn transmit(
        &mut self,
        record: &ClientRecord<'_, RNG, CipherSuite>,
    ) -> Result<(), TlsError> {
        self.tx_buf.clear();
        let range = record.encode(&mut self.tx_buf)?;
        if let Some(range) = range {
            Digest::update(self.key_schedule.transcript_hash(), &self.tx_buf[range]);
        }
        trace!(
            "**** transmit, hash={:x?}",
            self.key_schedule.transcript_hash().clone().finalize()
        );

        self.delegate.write(&self.tx_buf).await.map(|_| ())?;

        self.key_schedule.increment_write_counter();
        self.tx_buf.clear();
        Ok(())
    }

    async fn next_record(
        &mut self,
        encrypted: bool,
    ) -> Result<ServerRecord<'a, <CipherSuite::Hash as FixedOutput>::OutputSize>, TlsError> {
        if let Some(queued) = self.queue.dequeue() {
            return Ok(queued);
        }

        let mut record = ServerRecord::read(
            &mut self.delegate,
            &mut self.rx_buf,
            self.key_schedule.transcript_hash(),
        )
        .await?;

        if encrypted {
            if let ServerRecord::ApplicationData(ApplicationData {
                header,
                data: app_data,
            }) = record
            {
                trace!("decrypting {:x?} with {}", &header, app_data.len());
                //let crypto = Aes128Gcm::new(&self.key_schedule.get_server_key());
                let crypto = CipherSuite::Cipher::new(&self.key_schedule.get_server_key()?);
                let nonce = &self.key_schedule.get_server_nonce();
                trace!("server write nonce {:x?}", nonce);
                crypto
                    .decrypt_in_place(
                        &self.key_schedule.get_server_nonce()?,
                        &header,
                        &mut CryptoBuffer::wrap(app_data),
                    )
                    .map_err(|_| TlsError::CryptoError)?;
                trace!("decrypted with padding {:x?}", app_data);

                let padding = app_data.iter().enumerate().rfind(|(_, b)| **b != 0);
                let data = if let Some((index, _)) = padding {
                    &mut app_data[..index + 1]
                } else {
                    &mut app_data[..]
                };
                let data_len = data.len();

                trace!("decrypted {:x?}", data);

                let content_type =
                    ContentType::of(*data.last().unwrap()).ok_or(TlsError::InvalidRecord)?;

                match content_type {
                    ContentType::Handshake => {
                        let mut buf = ParseBuffer::new(&data[..data.len() - 1]);
                        while buf.remaining() > 1 {
                            let mut inner = ServerHandshake::parse(&mut buf);
                            if let Ok(ServerHandshake::Finished(ref mut finished)) = inner {
                                info!("Server finished hash: {:x?}", finished.hash);
                                finished.hash.replace(
                                    self.key_schedule.transcript_hash().clone().finalize(),
                                );
                            }
                            info!("===> inner ==> {:?}", inner);
                            record = ServerRecord::Handshake(inner.unwrap());
                            //if hash_later {
                            Digest::update(
                                self.key_schedule.transcript_hash(),
                                &data[..data.len() - 1],
                            );
                            info!("hash {:02x?}", &data[..data.len() - 1]);
                            //self.queue.enqueue(record).map_err(|_| TlsError::IoError)?;
                        }
                        //}
                    }
                    ContentType::ApplicationData => {
                        let inner = ApplicationData::new(&mut data[..data_len - 1], header);
                        record = ServerRecord::ApplicationData(inner);
                        info!("Enqueued some data");
                        //self.queue.enqueue(record).map_err(|_| TlsError::IoError)?;
                    }
                    _ => {
                        return Err(TlsError::InvalidHandshake);
                    }
                }
                //debug!("decrypted {:?} --> {:x?}", content_type, data);
                self.key_schedule.increment_read_counter();
            } else {
                //self.queue.enqueue(record).map_err(|_| TlsError::IoError)?;
            }
        } else {
            //self.queue.enqueue(record).map_err(|_| TlsError::IoError)?;
        }
        info!(
            "**** receive, hash={:02x?}",
            self.key_schedule.transcript_hash().clone().finalize()
        );
        if let Some(queued) = self.queue.dequeue() {
            Ok(queued)
        } else {
            Err(TlsError::InvalidApplicationData)
        }
    }

    pub async fn open(&mut self) -> Result<(), TlsError> {
        loop {
            if let Some(state) = self.state.take() {
                let next_state = self.handshake(&state).await?;
                info!("[handshake] {:?} -> {:?}", state, next_state);
                if let State::ApplicationData = next_state {
                    self.state.replace(next_state);
                    break;
                }
                self.state.replace(next_state);
            } else {
                return Err(TlsError::UnableToInitializeCryptoEngine);
            }
        }
        Ok(())
    }

    async fn handshake(&mut self, state: &State) -> Result<State, TlsError> {
        match state {
            State::ClientHello => {
                self.key_schedule.initialize_early_secret()?;
                let client_hello = ClientRecord::client_hello(&self.config);
                self.transmit(&client_hello).await?;
                info!("sent client hello");
                if let ClientRecord::Handshake(ClientHandshake::ClientHello(client_hello)) =
                    client_hello
                {
                    Ok(State::ServerHello(client_hello.secret))
                } else {
                    Err(TlsError::UnableToInitializeCryptoEngine)
                }
            }
            State::ServerHello(secret) => match self.next_record(false).await? {
                ServerRecord::Handshake(handshake) => match handshake {
                    ServerHandshake::ServerHello(server_hello) => {
                        info!("********* ServerHello");
                        let shared = server_hello
                            .calculate_shared_secret(&secret)
                            .ok_or(TlsError::InvalidKeyShare)?;

                        self.key_schedule
                            .initialize_handshake_secret(shared.as_bytes())?;

                        Ok(State::ServerCert)
                    }
                    _ => Err(TlsError::InvalidHandshake),
                },
                _ => Err(TlsError::InvalidRecord),
            },
            State::ServerCert => match self.next_record(true).await? {
                ServerRecord::Handshake(handshake) => match handshake {
                    ServerHandshake::EncryptedExtensions(_) => Ok(State::ServerCert),
                    ServerHandshake::Certificate(_) => Ok(State::ServerCertVerify),
                    _ => Err(TlsError::InvalidHandshake),
                },
                ServerRecord::ChangeCipherSpec(_) => Ok(State::ServerCert),
                _ => Err(TlsError::InvalidRecord),
            },
            State::ServerCertVerify => match self.next_record(true).await? {
                ServerRecord::Handshake(handshake) => match handshake {
                    ServerHandshake::CertificateVerify(_) => Ok(State::ServerFinished),
                    _ => Err(TlsError::InvalidHandshake),
                },
                _ => Err(TlsError::InvalidRecord),
            },
            State::ServerFinished => match self.next_record(true).await? {
                ServerRecord::Handshake(handshake) => match handshake {
                    ServerHandshake::Finished(finished) => {
                        info!("************* Finished");
                        let verified = self.key_schedule.verify_server_finished(&finished)?;
                        if verified {
                            info!("FINISHED! server verified {}", verified);
                            Ok(State::ClientFinished)
                        } else {
                            Err(TlsError::InvalidSignature)
                        }
                    }
                    _ => Err(TlsError::InvalidHandshake),
                },
                _ => Err(TlsError::InvalidRecord),
            },
            State::ClientFinished => {
                let client_finished = self
                    .key_schedule
                    .create_client_finished()
                    .map_err(|_| TlsError::InvalidHandshake)?;

                let client_finished =
                    ClientHandshake::<RNG, CipherSuite>::Finished(client_finished);

                let mut buf = Vec::<u8, U128>::new();
                let _ = client_finished.encode(&mut buf)?;

                buf.push(ContentType::Handshake as u8)
                    .map_err(|_| TlsError::EncodeError)?;
                let len = buf.len();
                let client_finished = self.encrypt(&mut buf, len)?;
                let client_finished = ClientRecord::ApplicationData(client_finished);

                self.transmit(&client_finished).await?;
                self.key_schedule.initialize_master_secret()?;
                Ok(State::ApplicationData)
            }
            State::ApplicationData => Ok(State::ApplicationData),
        }
    }

    pub async fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        match self.state.take().unwrap() {
            State::ApplicationData => {
                self.state.replace(State::ApplicationData);
                info!("Writing {} bytes", buf.len());

                let mut v: Vec<u8, U4096> = Vec::new();
                v.extend_from_slice(buf)
                    .map_err(|_| TlsError::EncodeError)?;
                v.push(ContentType::ApplicationData as u8)
                    .map_err(|_| TlsError::EncodeError)?;
                let len = v.len();
                let data = self.encrypt(&mut v, len)?;
                info!("Encrypted data: {:02x?}", data);
                self.transmit(&ClientRecord::ApplicationData(data)).await?;
                Ok(buf.len())
            }
            _ => Err(TlsError::MissingHandshake),
        }
    }

    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        match self.state.take().unwrap() {
            State::ApplicationData => {
                self.state.replace(State::ApplicationData);
                let record = self.next_record(true).await?;
                match record {
                    ServerRecord::ApplicationData(ApplicationData { header: _, data }) => {
                        info!("Got application data record");
                        if buf.len() < data.len() {
                            warn!("Passed buffer is too small");
                            Err(TlsError::EncodeError)
                        } else {
                            buf[0..data.len()].copy_from_slice(&data[0..data.len()]);
                            Ok(data.len())
                        }
                    }
                    _ => Err(TlsError::InvalidApplicationData),
                }
            }
            _ => Err(TlsError::MissingHandshake),
        }
    }

    pub fn delegate_socket(&mut self) -> &mut Socket {
        &mut self.delegate
    }
}
