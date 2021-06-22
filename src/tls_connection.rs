use crate::drivers::tls::config::{Config, TlsCipherSuite};
use crate::drivers::tls::handshake::{ClientHandshake, HandshakeType, ServerHandshake};
use crate::drivers::tls::key_schedule::KeySchedule;
use crate::drivers::tls::record::{ClientRecord, ServerRecord};
use crate::drivers::tls::{AsyncRead, AsyncWrite, TlsError};
use crate::traits::ip::{IpProtocol, SocketAddress};
use crate::traits::tcp::{TcpError, TcpSocket};
use digest::generic_array::typenum::Unsigned;
use heapless::{consts::*, ArrayLength, Vec};
use hkdf::Hkdf;
use hmac::Hmac;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use crate::drivers::tls::application_data::ApplicationData;
use crate::drivers::tls::buffer::CryptoBuffer;
use crate::drivers::tls::content_types::ContentType;
use crate::drivers::tls::handshake::HandshakeType::Finished;
use crate::drivers::tls::parse_buffer::ParseBuffer;
use aes_gcm::aead::{generic_array::GenericArray, AeadInPlace, Buffer, NewAead};
use aes_gcm::Error;
use digest::{BlockInput, FixedOutput, Reset, Update};
use heapless::spsc::Queue;

enum State {
    Unencrypted,
    Encrypted,
}

pub struct TlsConnection<RNG, Socket, CipherSuite, TxBufLen, RxBufLen>
where
    RNG: CryptoRng + RngCore + Copy + 'static,
    Socket: AsyncRead + AsyncWrite + 'static,
    CipherSuite: TlsCipherSuite + 'static,
    TxBufLen: ArrayLength<u8>,
    RxBufLen: ArrayLength<u8>,
{
    delegate: Socket,
    config: &'static Config<RNG, CipherSuite>,
    state: State,
    key_schedule: KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
    tx_buf: Vec<u8, TxBufLen>,
    rx_buf: Vec<u8, RxBufLen>,
    queue: Queue<ServerRecord<<CipherSuite::Hash as FixedOutput>::OutputSize>, U4>,
}

impl<RNG, Socket, CipherSuite, TxBufLen, RxBufLen>
    TlsConnection<RNG, Socket, CipherSuite, TxBufLen, RxBufLen>
where
    RNG: CryptoRng + RngCore + Copy + 'static,
    Socket: AsyncRead + AsyncWrite + 'static,
    CipherSuite: TlsCipherSuite,
    TxBufLen: ArrayLength<u8>,
    RxBufLen: ArrayLength<u8>,
{
    pub fn new(config: &'static Config<RNG, CipherSuite>, delegate: Socket) -> Self {
        Self {
            delegate,
            config,
            state: State::Unencrypted,
            key_schedule: KeySchedule::new(),
            tx_buf: Vec::new(),
            rx_buf: Vec::new(),
            queue: Queue::new(),
        }
    }

    fn encrypt<N: ArrayLength<u8>>(
        &self,
        buf: &mut Vec<u8, N>,
    ) -> Result<ApplicationData, TlsError> {
        //unimplemented!()
        let client_key = self.key_schedule.get_client_key();
        let nonce = &self.key_schedule.get_client_nonce();
        log::info!("encrypt key {:02x?}", client_key);
        log::info!("encrypt nonce {:02x?}", nonce);
        log::info!("plaintext {} {:02x?}", buf.len(), buf);
        //let crypto = Aes128Gcm::new_varkey(&self.key_schedule.get_client_key()).unwrap();
        let crypto = CipherSuite::Cipher::new(&client_key);
        let initial_len = buf.len();
        let len = (buf.len() + <CipherSuite::Cipher as AeadInPlace>::TagSize::to_usize());
        log::info!(
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
            .encrypt_in_place(nonce, &additional_data, &mut CryptoBuffer::wrap(buf))
            .map_err(|_| TlsError::InvalidApplicationData)?;
        log::info!("aad {:x?}", additional_data);
        log::info!("encrypted data: {:x?}", &buf[..initial_len]);
        log::info!("ciphertext ## {} ## {:x?}", buf.len(), buf);
        //Ok(())
        let mut header = Vec::new();
        header.extend_from_slice(&additional_data);
        let mut data = Vec::new();
        data.extend(buf.iter());
        Ok(ApplicationData { header, data })
        //let result =
        //crypto.decrypt_in_place(&self.key_schedule.get_server_nonce(), &header, &mut data);
        //Ok(())
    }

    async fn transmit(
        &mut self,
        record: &ClientRecord<'_, RNG, CipherSuite>,
    ) -> Result<(), TlsError> {
        log::info!("TRANSMIT");
        self.tx_buf.clear();
        let range = record.encode(&mut self.tx_buf)?;
        if let Some(range) = range {
            log::info!("Update range {:?}", range);
            Digest::update(self.key_schedule.transcript_hash(), &self.tx_buf[range]);
        }
        log::info!(
            "**** transmit, hash={:x?}",
            self.key_schedule.transcript_hash().clone().finalize()
        );

        log::info!("Writing record: {:x?}", &self.tx_buf);

        self.delegate.write(&self.tx_buf).await.map(|_| ())?;

        self.key_schedule.increment_write_counter();
        self.tx_buf.clear();
        Ok(())
    }

    async fn receive(
        &mut self,
    ) -> Result<ServerRecord<<CipherSuite::Hash as FixedOutput>::OutputSize>, TlsError> {
        log::info!("RECEIVE");
        if let Some(queued) = self.queue.dequeue() {
            return Ok(queued);
        }

        let mut record =
            ServerRecord::read(&mut self.delegate, self.key_schedule.transcript_hash()).await?;

        //if let State::Handhshaking = self.state {
        /*if let ServerRecord::Handshake(ServerHandshake::ServerHello(_)) = record {
            log::info!("Got sever hello handshake record");
            return Ok(record);
        }*/

        if let State::Encrypted = self.state {
            if let ServerRecord::ApplicationData(ApplicationData { header, mut data }) = record {
                log::info!("decrypting {:x?} with {}", &header, data.len());
                //let crypto = Aes128Gcm::new(&self.key_schedule.get_server_key());
                let crypto = CipherSuite::Cipher::new(&self.key_schedule.get_server_key());
                let nonce = &self.key_schedule.get_server_nonce();
                log::info!("server write nonce {:x?}", nonce);
                crypto
                    .decrypt_in_place(
                        &self.key_schedule.get_server_nonce(),
                        &header,
                        &mut CryptoBuffer::wrap(&mut data),
                    )
                    .map_err(|_| TlsError::CryptoError)?;
                log::info!("decrypted with padding {:x?}", data);

                let padding = data.iter().enumerate().rfind(|(index, b)| **b != 0);
                if let Some((index, _)) = padding {
                    data.truncate(index + 1);
                }

                log::info!("decrypted {:x?}", data);

                let content_type =
                    ContentType::of(*data.last().unwrap()).ok_or(TlsError::InvalidRecord)?;

                match content_type {
                    ContentType::Handshake => {
                        let mut buf = ParseBuffer::new(&data[..data.len() - 1]);
                        while buf.remaining() > 1 {
                            let mut inner = ServerHandshake::parse(&mut buf);
                            if let Ok(ServerHandshake::Finished(ref mut finished)) = inner {
                                log::info!("Server finished hash: {:x?}", finished.hash);
                                finished.hash.replace(
                                    self.key_schedule.transcript_hash().clone().finalize(),
                                );
                            }
                            log::info!("===> inner ==> {:?}", inner);
                            record = ServerRecord::Handshake(inner.unwrap());
                            //if hash_later {
                            Digest::update(
                                self.key_schedule.transcript_hash(),
                                &data[..data.len() - 1],
                            );
                            log::info!("hash {:02x?}", &data[..data.len() - 1]);
                            self.queue.enqueue(record);
                        }
                        //}
                    }
                    ContentType::ApplicationData => {
                        let mut buf = ParseBuffer::new(&data[..data.len() - 1]);
                        while buf.remaining() > 1 {
                            let inner = ApplicationData::parse(&mut buf)?;
                            record = ServerRecord::ApplicationData(inner);
                            log::info!("Enqueued some data");
                            self.queue.enqueue(record);
                        }
                    }
                    _ => {
                        return Err(TlsError::InvalidHandshake);
                    }
                }
                //log::debug!("decrypted {:?} --> {:x?}", content_type, data);
                self.key_schedule.increment_read_counter();
            } else {
                return Ok(record);
            }
        } else {
            log::info!("NOt encrypted state record");
            return Ok(record);
        }
        log::info!(
            "**** receive, hash={:02x?}",
            self.key_schedule.transcript_hash().clone().finalize()
        );
        if let Some(queued) = self.queue.dequeue() {
            return Ok(queued);
        } else {
            Err(TlsError::InvalidApplicationData)
        }
        //Ok(record)
    }

    pub async fn handshake(&mut self) -> Result<(), TlsError> {
        self.key_schedule.initialize_early_secret();
        let client_hello = ClientRecord::client_hello(&self.config);
        self.transmit(&client_hello).await;
        log::info!("sent client hello");

        loop {
            let record = self.receive().await?;

            match record {
                ServerRecord::Handshake(handshake) => match handshake {
                    ServerHandshake::ServerHello(server_hello) => {
                        log::info!("********* ServerHello");
                        if let ClientRecord::Handshake(ClientHandshake::ClientHello(
                            ref client_hello,
                        )) = client_hello
                        {
                            let shared = server_hello
                                .calculate_shared_secret(&client_hello.secret)
                                .ok_or(TlsError::InvalidKeyShare)?;

                            self.key_schedule
                                .initialize_handshake_secret(shared.as_bytes());

                            self.state = State::Encrypted;
                        }
                    }
                    ServerHandshake::EncryptedExtensions(_) => {}
                    ServerHandshake::Certificate(_) => {}
                    ServerHandshake::CertificateVerify(_) => {}
                    ServerHandshake::Finished(finished) => {
                        log::info!("************* Finished");
                        let verified = self.key_schedule.verify_server_finished(&finished);
                        if verified {
                            log::info!("FINISHED! server verified {}", verified);
                            let client_finished = self
                                .key_schedule
                                .create_client_finished()
                                .map_err(|_| TlsError::InvalidHandshake)?;

                            let client_finished =
                                ClientHandshake::<RNG, CipherSuite>::Finished(client_finished);

                            let mut buf = Vec::<u8, U128>::new();
                            // let mut next_hash = self.key_schedule.transcript_hash().clone();
                            let range = client_finished.encode(&mut buf)?;
                            //  Update::update(&mut next_hash, &buf[range]);

                            buf.push(ContentType::Handshake as u8);
                            let client_finished = self.encrypt(&mut buf)?;
                            let client_finished = ClientRecord::ApplicationData(client_finished);

                            log::info!(
                                "sending client FINISH. current hash {:02x?}",
                                self.key_schedule.transcript_hash().clone().finalize()
                            );
                            self.transmit(&client_finished).await?;
                            /*
                            self.key_schedule.replace_transcript_hash(next_hash);
                            log::info!(
                                "sending client FINISH. updated hash {:02x?}",
                                self.key_schedule.transcript_hash().clone().finalize()
                            );*/
                            self.key_schedule.initialize_master_secret();
                        }
                        break;
                    }
                },
                ServerRecord::Alert => {
                    unimplemented!("alert not handled")
                }
                ServerRecord::ApplicationData(application_data) => {
                    /*
                    match application_data {
                        ApplicationData { header, mut data } => {
                            log::info!("decrypting {:x?}", &header);
                            let crypto = Aes128Gcm::new(&self.key_schedule.get_server_key());
                            let nonce = &self.key_schedule.get_server_nonce();
                            log::info!("server write nonce {:x?}", nonce);
                            let result = crypto.decrypt_in_place(
                                &self.key_schedule.get_server_nonce(),
                                &header,
                                &mut data,
                            );

                            let content_type = ContentType::of(*data.last().unwrap())
                                .ok_or(TlsError::InvalidRecord)?;

                            match content_type {
                                ContentType::Invalid => {}
                                ContentType::ChangeCipherSpec => {}
                                ContentType::Alert => {}
                                ContentType::Handshake => {
                                    let mut buf = ParseBuffer::new(&data[..data.len() - 1]);
                                    //let inner = ServerHandshake::parse(&data[..data.len() - 1]);
                                    let inner = ServerHandshake::parse(&mut buf);
                                    log::debug!("===> inner ==> {:?}", inner);
                                }
                                ContentType::ApplicationData => {}
                            }
                            log::debug!("decrypt result {:?}", result);
                            log::debug!("decrypted {:?} --> {:x?}", content_type, data);
                        }
                    }
                    self.key_schedule.increment_read_counter();
                     */
                }
                ServerRecord::ChangeCipherSpec(..) => {
                    // ignore fake CCS
                }
            }
        }

        Ok(())
    }

    pub async fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        log::info!("Writing {} bytes", buf.len());

        let mut v: Vec<u8, U4096> = Vec::new();
        v.extend_from_slice(buf);
        v.push(ContentType::ApplicationData as u8);
        let data = self.encrypt(&mut v)?;
        log::info!("Encrypted data: {:02x?}", data);
        self.transmit(&ClientRecord::ApplicationData(data)).await?;
        Ok(buf.len())
    }

    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        let record = self.receive().await?;
        match record {
            ServerRecord::ApplicationData(ApplicationData { header, data }) => {
                log::info!("Got application data record");
                if buf.len() < data.len() {
                    log::warn!("Passed buffer is too small");
                    return Err(TlsError::IoError);
                } else {
                    buf[0..data.len()].copy_from_slice(&data[0..data.len()]);
                    return Ok(data.len());
                }
            }
            _ => return Err(TlsError::InvalidApplicationData),
        }
    }

    pub fn delegate_socket(&mut self) -> &mut Socket {
        &mut self.delegate
    }
}
