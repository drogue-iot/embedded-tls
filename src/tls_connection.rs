use crate::config::{Config, TlsCipherSuite};
use crate::handshake::{ClientHandshake, ServerHandshake};
use crate::key_schedule::KeySchedule;
use crate::record::{ClientRecord, ServerRecord};
use crate::{AsyncRead, AsyncWrite, TlsError};
use aes_gcm::aead::Buffer;
use core::fmt::{Debug, Formatter};
use core::ops::Range;
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
use generic_array::GenericArray;

#[derive(Copy, Clone, Debug, PartialEq)]
enum State {
    ClientHello,
    ServerHello,
    ServerCert,
    ServerCertVerify,
    ServerFinished,
    ClientFinished,
    ApplicationData,
}

/*
impl Debug for State {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match &self {
            State::ClientHello => write!(f, "ClientHello"),
            State::ServerHello => write!(f, "ServerHello"),
            State::ServerCert => write!(f, "ServerCert"),
            State::ServerCertVerify => write!(f, "ServerCertVerify"),
            State::ServerFinished => write!(f, "ServerFinished"),
            State::ClientFinished => write!(f, "ClientFinished"),
            State::ApplicationData => write!(f, "ApplicationData"),
        }
    }
}
*/

pub struct TlsConnection<'a, RNG, Socket, CipherSuite, const TxBufLen: usize, const RxBufLen: usize>
where
    RNG: CryptoRng + RngCore + Copy + 'static,
    Socket: AsyncRead + AsyncWrite + 'static,
    CipherSuite: TlsCipherSuite + 'static,
{
    delegate: Socket,
    config: &'a Config<RNG, CipherSuite>,
    key_schedule: KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
    tx_buf: [u8; TxBufLen],
    rx_buf: [u8; RxBufLen],
    state: State,
}

impl<'a, RNG, Socket, CipherSuite, const TxBufLen: usize, const RxBufLen: usize>
    TlsConnection<'a, RNG, Socket, CipherSuite, TxBufLen, RxBufLen>
where
    RNG: CryptoRng + RngCore + Copy + 'static,
    Socket: AsyncRead + AsyncWrite + 'static,
    CipherSuite: TlsCipherSuite,
{
    pub fn new(config: &'a Config<RNG, CipherSuite>, delegate: Socket) -> Self {
        Self {
            delegate,
            config,
            state: State::ClientHello,
            key_schedule: KeySchedule::new(),
            tx_buf: [0; TxBufLen],
            rx_buf: [0; RxBufLen],
        }
    }

    async fn transmit<'m>(
        delegate: &mut Socket,
        key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
        buf: &'m [u8],
        range: Option<Range<usize>>,
    ) -> Result<(), TlsError> {
        if let Some(range) = range {
            Digest::update(key_schedule.transcript_hash(), &buf[range]);
        }
        trace!(
            "**** transmit, hash={:x?}",
            key_schedule.transcript_hash().clone().finalize()
        );

        delegate.write(buf).await.map(|_| ())?;

        key_schedule.increment_write_counter();
        Ok(())
    }

    fn decrypt_record<
        'm,
        F: FnMut(
            &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
            ServerRecord<'m, <CipherSuite::Hash as FixedOutput>::OutputSize>,
        ) -> Result<(), TlsError>,
    >(
        key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
        record: ServerRecord<'m, <CipherSuite::Hash as FixedOutput>::OutputSize>,
        mut processor: F,
    ) -> Result<(), TlsError>
    where
        'a: 'm,
    {
        if let ServerRecord::ApplicationData(ApplicationData {
            header,
            data: mut app_data,
        }) = record
        {
            trace!("decrypting {:x?} with {}", &header, app_data.len());
            //let crypto = Aes128Gcm::new(&self.key_schedule.get_server_key());
            let crypto = CipherSuite::Cipher::new(&key_schedule.get_server_key()?);
            let nonce = &key_schedule.get_server_nonce();
            trace!("server write nonce {:x?}", nonce);
            crypto
                .decrypt_in_place(&key_schedule.get_server_nonce()?, &header, &mut app_data)
                .map_err(|_| TlsError::CryptoError)?;
            //            trace!("decrypted with padding {:x?}", app_data);
            let padding = app_data
                .as_slice()
                .iter()
                .enumerate()
                .rfind(|(_, b)| **b != 0);
            if let Some((index, _)) = padding {
                app_data.truncate(index + 1);
            };
            let data_len = app_data.len();

            //trace!("decrypted {:x?}", data);

            let content_type = ContentType::of(*app_data.as_slice().last().unwrap())
                .ok_or(TlsError::InvalidRecord)?;

            match content_type {
                ContentType::Handshake => {
                    // Decode potentially coaleced handshake messages
                    let data = &app_data.as_slice()[..app_data.len() - 1];
                    let mut buf = ParseBuffer::new(data);
                    while buf.remaining() > 1 {
                        let mut inner = ServerHandshake::parse(&mut buf);
                        if let Ok(ServerHandshake::Finished(ref mut finished)) = inner {
                            info!("Server finished hash: {:x?}", finished.hash);
                            finished
                                .hash
                                .replace(key_schedule.transcript_hash().clone().finalize());
                        }
                        info!("===> inner ==> {:?}", inner);
                        //if hash_later {
                        Digest::update(key_schedule.transcript_hash(), &data[..data.len()]);
                        info!("hash {:02x?}", &data[..data.len()]);
                        processor(key_schedule, ServerRecord::Handshake(inner.unwrap()))?;
                    }
                    //}
                }
                ContentType::ApplicationData => {
                    app_data.truncate(app_data.len() - 1);
                    let inner = ApplicationData::new(app_data, header);
                    processor(key_schedule, ServerRecord::ApplicationData(inner))?;
                }
                _ => {
                    return Err(TlsError::InvalidHandshake);
                }
            }
            //debug!("decrypted {:?} --> {:x?}", content_type, data);
            key_schedule.increment_read_counter();
        } else {
            processor(key_schedule, record)?;
        }
        Ok(())
    }

    async fn fetch_record<'m>(
        delegate: &'m mut Socket,
        rx_buf: &'m mut [u8],
        key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
    ) -> Result<ServerRecord<'m, <CipherSuite::Hash as FixedOutput>::OutputSize>, TlsError> {
        info!("Fetch record with rx buf len {}", rx_buf.len());
        Ok(ServerRecord::read(delegate, rx_buf, key_schedule.transcript_hash()).await?)
    }

    async fn next_record<
        'm,
        N: ArrayLength<ServerRecord<'m, <CipherSuite::Hash as FixedOutput>::OutputSize>>,
    >(
        &mut self,
        encrypted: bool,
        queue: &mut Queue<ServerRecord<'m, <CipherSuite::Hash as FixedOutput>::OutputSize>, N>,
    ) -> Result<ServerRecord<'m, <CipherSuite::Hash as FixedOutput>::OutputSize>, TlsError>
    where
        'a: 'm,
    {
        /*
        if let Some(queued) = queue.dequeue() {
            return Ok(queued);
        }

        let mut record = self.fetch_record().await?;

        if encrypted {
            self.decrypt_record(record, |record| {
                //queue.enqueue(record).map_err(|_| TlsError::IoError)?;
                Ok(())
            });
        } else {
            return Ok(record);
        }
        info!(
            "**** receive, hash={:02x?}",
            self.key_schedule.transcript_hash().clone().finalize()
        );
        if let Some(queued) = queue.dequeue() {
            Ok(queued)
        } else {
            Err(TlsError::InvalidApplicationData)
        }*/
        Err(TlsError::InvalidApplicationData)
    }

    pub async fn open<'m>(&mut self) -> Result<(), TlsError>
    where
        'a: 'm,
    {
        self.state = State::ClientHello;
        self.key_schedule.initialize_early_secret()?;
        let client_hello = ClientRecord::client_hello(&self.config);

        let (len, range) = client_hello.encode(&mut self.tx_buf[..], &mut self.key_schedule)?;

        Self::transmit(
            &mut self.delegate,
            &mut self.key_schedule,
            &self.tx_buf[..len],
            range,
        )
        .await?;

        info!("sent client hello");

        // Expecting server hello
        self.state = State::ServerHello;
        match Self::fetch_record(&mut self.delegate, &mut self.rx_buf, &mut self.key_schedule)
            .await?
        {
            ServerRecord::Handshake(handshake) => match handshake {
                ServerHandshake::ServerHello(server_hello) => {
                    info!("********* ServerHello");
                    if let ClientRecord::Handshake(ClientHandshake::ClientHello(client_hello)) =
                        client_hello
                    {
                        let shared = server_hello
                            .calculate_shared_secret(&client_hello.secret)
                            .ok_or(TlsError::InvalidKeyShare)?;

                        self.key_schedule
                            .initialize_handshake_secret(shared.as_bytes())?;
                    } else {
                        return Err(TlsError::InvalidHandshake);
                    }
                }
                _ => return Err(TlsError::InvalidHandshake),
            },
            _ => return Err(TlsError::InvalidRecord),
        }

        self.state = State::ServerCert;
        // Server handshake processing
        loop {
            if self.state == State::ApplicationData || self.state == State::ClientFinished {
                break;
            }

            log::info!("Processing handshake in state {:?}", self.state);

            // Handle encrypted traffic with coaleced records
            let state = &mut self.state;
            let rx_buf = &mut self.rx_buf;
            let socket = &mut self.delegate;
            let key_schedule = &mut self.key_schedule;
            let record = Self::fetch_record(socket, rx_buf, key_schedule).await?;
            Self::decrypt_record(key_schedule, record, |key_schedule, record| {
                let next_state = match *state {
                    State::ServerCert => match record {
                        ServerRecord::Handshake(handshake) => match handshake {
                            ServerHandshake::EncryptedExtensions(_) => Ok(State::ServerCert),
                            ServerHandshake::Certificate(_) => Ok(State::ServerCertVerify),
                            _ => Err(TlsError::InvalidHandshake),
                        },
                        ServerRecord::ChangeCipherSpec(_) => Ok(State::ServerCert),
                        _ => Err(TlsError::InvalidRecord),
                    },
                    State::ServerCertVerify => match record {
                        ServerRecord::Handshake(handshake) => match handshake {
                            ServerHandshake::CertificateVerify(_) => Ok(State::ServerFinished),
                            _ => Err(TlsError::InvalidHandshake),
                        },
                        _ => Err(TlsError::InvalidRecord),
                    },
                    State::ServerFinished => match record {
                        ServerRecord::Handshake(handshake) => match handshake {
                            ServerHandshake::Finished(finished) => {
                                info!("************* Finished");
                                let verified = key_schedule.verify_server_finished(&finished)?;
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
                    state => Ok(state),
                }?;
                log::info!("State {:?} -> {:?}", *state, next_state);
                *state = next_state;
                Ok(())
            })?;
        }

        log::info!("Sending client finish");
        let client_finished = self
            .key_schedule
            .create_client_finished()
            .map_err(|_| TlsError::InvalidHandshake)?;

        let client_finished = ClientHandshake::<RNG, CipherSuite>::Finished(client_finished);

        /*
        let mut buf = CryptoBuffer::wrap(&mut self.tx_buf);
        let _ = client_finished.encode(&mut buf)?;

        buf.push(ContentType::Handshake as u8)
            .map_err(|_| TlsError::EncodeError)?;
        let client_finished = Self::encrypt(buf)?;
        */
        let client_finished = ClientRecord::EncryptedHandshake(client_finished);

        let (len, range) = client_finished.encode(&mut self.tx_buf[..], &mut self.key_schedule)?;

        Self::transmit(
            &mut self.delegate,
            &mut self.key_schedule,
            &mut self.tx_buf[..len],
            range,
        )
        .await?;

        self.key_schedule.initialize_master_secret()?;
        self.state = State::ApplicationData;
        log::info!("Handshake complete!");
        /*
        State::ClientFinished => {
            Ok(

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
            Ok(())
        })?;
                */

        /*
            ServerRecord::Handshake(handshake) => match handshake {
                ServerHandshake::EncryptedExtensions(_) => Ok(()),
                ServerHandshake::Certificate(_) => Ok(()),
                ServerHandshake::CertificateVerify(_) => Ok(()),
                ServerHandshake::Finished(finished) => {
                    info!("************* Finished");
                    let verified = self.key_schedule.verify_server_finished(&finished)?;
                    if verified {
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
                        Ok(())
                    } else {
                        Err(TlsError::InvalidSignature)
                    }
                }
                _ => Err(TlsError::InvalidHandshake),
            },
            ServerRecord::ChangeCipherSpec(_) => Ok(()),
            _ => Err(TlsError::InvalidRecord),
        })?;
            */
        /*
        loop {
            if let Some(state) = self.state.take() {
                let next_state = self.handshake(&state, &mut queue).await?;
                info!("[handshake] {:?} -> {:?}", state, next_state);
                if let State::ApplicationData = next_state {
                    self.state.replace(next_state);
                    break;
                }
                self.state.replace(next_state);
            } else {
                return Err(TlsError::UnableToInitializeCryptoEngine);
            }
        }*/
        Ok(())
    }

    /*
    async fn handshake<
        'm,
        N: ArrayLength<ServerRecord<'m, <CipherSuite::Hash as FixedOutput>::OutputSize>>,
    >(
        &mut self,
        state: &State,
        queue: &mut Queue<ServerRecord<'m, <CipherSuite::Hash as FixedOutput>::OutputSize>, N>,
    ) -> Result<State, TlsError>
    where
        'a: 'm,
    {
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
            State::ServerHello(secret) => match self.fetch_record().await? {
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
            State::ServerCert => match self.next_record(true, queue).await? {
                ServerRecord::Handshake(handshake) => match handshake {
                    ServerHandshake::EncryptedExtensions(_) => Ok(State::ServerCert),
                    ServerHandshake::Certificate(_) => Ok(State::ServerCertVerify),
                    _ => Err(TlsError::InvalidHandshake),
                },
                ServerRecord::ChangeCipherSpec(_) => Ok(State::ServerCert),
                _ => Err(TlsError::InvalidRecord),
            },
            State::ServerCertVerify => match self.next_record(true, queue).await? {
                ServerRecord::Handshake(handshake) => match handshake {
                    ServerHandshake::CertificateVerify(_) => Ok(State::ServerFinished),
                    _ => Err(TlsError::InvalidHandshake),
                },
                _ => Err(TlsError::InvalidRecord),
            },
            State::ServerFinished => match self.next_record(true, queue).await? {
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
    */

    pub async fn write<'m>(&mut self, buf: &'m [u8]) -> Result<usize, TlsError> {
        if self.state != State::ApplicationData {
            return Err(TlsError::MissingHandshake);
        }

        info!("Writing {} bytes", buf.len());
        let record: ClientRecord<'a, 'm, RNG, CipherSuite> = ClientRecord::ApplicationData(buf);
        let initial_len = buf.len();
        let (len, range) = record.encode(&mut self.tx_buf[..], &mut self.key_schedule)?;

        Self::transmit(
            &mut self.delegate,
            &mut self.key_schedule,
            &self.tx_buf[..len],
            range,
        )
        .await?;
        Ok(initial_len)
    }

    pub async fn read<'m>(&mut self, buf: &mut [u8]) -> Result<usize, TlsError>
    where
        'a: 'm,
    {
        if self.state != State::ApplicationData {
            return Err(TlsError::MissingHandshake);
        }

        let rx_buf = &mut self.rx_buf[..];
        let socket = &mut self.delegate;
        let key_schedule = &mut self.key_schedule;
        let record = Self::fetch_record(socket, rx_buf, key_schedule).await?;
        let mut copied = 0;
        Self::decrypt_record(key_schedule, record, |_, record| match record {
            ServerRecord::ApplicationData(ApplicationData { header: _, data }) => {
                info!("Got application data record");
                if buf.len() < data.len() {
                    warn!("Passed buffer is too small");
                    Err(TlsError::EncodeError)
                } else {
                    buf[0..data.len()].copy_from_slice(data.as_slice());
                    copied = data.len();
                    Ok(())
                }
            }
            _ => Err(TlsError::InvalidApplicationData),
        })?;
        Ok(copied)
    }

    pub fn delegate_socket(&mut self) -> &mut Socket {
        &mut self.delegate
    }
}
