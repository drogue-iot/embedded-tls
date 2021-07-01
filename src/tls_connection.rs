use crate::handshake::{ClientHandshake, ServerHandshake};
use crate::key_schedule::KeySchedule;
use crate::record::{ClientRecord, ServerRecord};
use crate::{alert::*, handshake::certificate::Certificate};
use crate::{
    buffer::CryptoBuffer,
    config::{TlsCipherSuite, TlsConfig, TlsContext},
};
use crate::{
    traits::{AsyncRead, AsyncWrite},
    TlsError,
};
use core::fmt::Debug;
use digest::generic_array::typenum::Unsigned;
use p256::ecdh::EphemeralSecret;
use rand_core::{CryptoRng, RngCore};
use sha2::Digest;

use crate::application_data::ApplicationData;
use crate::content_types::ContentType;
// use crate::handshake::certificate_request::CertificateRequest;
// use crate::handshake::certificate_verify::CertificateVerify;
// use crate::handshake::encrypted_extensions::EncryptedExtensions;
// use crate::handshake::finished::Finished;
// use crate::handshake::new_session_ticket::NewSessionTicket;
// use crate::handshake::server_hello::ServerHello;
use crate::parse_buffer::ParseBuffer;
use aes_gcm::aead::{AeadInPlace, NewAead};
use core::fmt::Formatter;
use digest::FixedOutput;
use heapless::{consts, spsc::Queue};

enum State {
    ClientHello,
    ServerHello(EphemeralSecret),
    ServerCert,
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
            State::ServerFinished => write!(f, "ServerFinished"),
            State::ClientFinished => write!(f, "ClientFinished"),
            State::ApplicationData => write!(f, "ApplicationData"),
        }
    }
}

// Split records at 8k of data
const RECORD_MTU: usize = 8192;

pub struct TlsConnection<'a, RNG, Socket, CipherSuite>
where
    RNG: CryptoRng + RngCore + 'static,
    Socket: AsyncRead + AsyncWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    delegate: Socket,
    rng: RNG,
    config: TlsConfig<'a, CipherSuite>,
    key_schedule: KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
    record_buf: &'a mut [u8],
    cert_requested: bool,
    state: Option<State>,
}

impl<'a, RNG, Socket, CipherSuite> TlsConnection<'a, RNG, Socket, CipherSuite>
where
    RNG: CryptoRng + RngCore + 'static,
    Socket: AsyncRead + AsyncWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    /// Create a new TLS connection with the provided config, a random generator and a async I/O implementation
    pub fn new(context: TlsContext<'a, CipherSuite, RNG>, delegate: Socket) -> Self {
        Self {
            delegate,
            config: context.config,
            rng: context.rng,
            state: Some(State::ClientHello),
            key_schedule: KeySchedule::new(),
            record_buf: context.record_buf,
            cert_requested: false,
        }
    }

    /// Close a connection instance, returning the ownership of the config, random generator and the async I/O provider.
    pub async fn close(self) -> Result<(TlsContext<'a, CipherSuite, RNG>, Socket), TlsError> {
        let record = if let Some(State::ApplicationData) = self.state {
            ClientRecord::Alert(
                Alert::new(AlertLevel::Warning, AlertDescription::CloseNotify),
                true,
            )
        } else {
            ClientRecord::Alert(
                Alert::new(AlertLevel::Warning, AlertDescription::CloseNotify),
                false,
            )
        };

        let mut key_schedule = self.key_schedule;
        let mut delegate = self.delegate;
        let record_buf = self.record_buf;
        let rng = self.rng;
        let config = self.config;

        Self::transmit(
            &mut delegate,
            &mut record_buf[..],
            &mut key_schedule,
            &record,
            false,
        )
        .await?;

        Ok((
            TlsContext::new_with_config(rng, record_buf, config),
            delegate,
        ))
    }

    async fn transmit<'m>(
        delegate: &mut Socket,
        tx_buf: &mut [u8],
        key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
        record: &ClientRecord<'_, 'm, CipherSuite>,
        update_hash: bool,
    ) -> Result<(), TlsError> {
        let mut next_hash = key_schedule.transcript_hash().clone();

        let (len, range) = record.encode(tx_buf, &mut next_hash, |buf| {
            Self::encrypt(key_schedule, buf)
        })?;

        if let Some(range) = range {
            Digest::update(key_schedule.transcript_hash(), &tx_buf[range]);
        }
        /*trace!(
            "**** transmit {} bytes, hash={:x?}",
            len,
            key_schedule.transcript_hash().clone().finalize()
        );*/

        delegate.write(&tx_buf[..len]).await?;

        key_schedule.increment_write_counter();

        if update_hash {
            key_schedule.replace_transcript_hash(next_hash);
        }
        Ok(())
    }

    fn encrypt(
        key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
        buf: &mut CryptoBuffer<'_>,
    ) -> Result<usize, TlsError> {
        let client_key = key_schedule.get_client_key()?;
        let nonce = &key_schedule.get_client_nonce()?;
        // trace!("encrypt key {:02x?}", client_key);
        // trace!("encrypt nonce {:02x?}", nonce);
        // trace!("plaintext {} {:02x?}", buf.len(), buf.as_slice(),);
        //let crypto = Aes128Gcm::new_varkey(&self.key_schedule.get_client_key()).unwrap();
        let crypto = CipherSuite::Cipher::new(&client_key);
        let len = buf.len() + <CipherSuite::Cipher as AeadInPlace>::TagSize::to_usize();

        if len > buf.capacity() {
            return Err(TlsError::InsufficientSpace);
        }

        trace!(
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
            .encrypt_in_place(nonce, &additional_data, buf)
            .map_err(|_| TlsError::InvalidApplicationData)?;
        Ok(buf.len())
    }

    fn decrypt_record<'m>(
        key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
        records: &mut Queue<
            ServerRecord<'m, <CipherSuite::Hash as FixedOutput>::OutputSize>,
            consts::U4,
        >,
        record: ServerRecord<'m, <CipherSuite::Hash as FixedOutput>::OutputSize>,
    ) -> Result<(), TlsError>
    where
        'a: 'm,
    {
        if let ServerRecord::ApplicationData(ApplicationData {
            header,
            data: mut app_data,
        }) = record
        {
            // info!("decrypting {:x?} with {}", &header, app_data.len());
            //let crypto = Aes128Gcm::new(&self.key_schedule.get_server_key());
            let crypto = CipherSuite::Cipher::new(&key_schedule.get_server_key()?);
            // let nonce = &key_schedule.get_server_nonce();
            // info!("server write nonce {:x?}", nonce);
            crypto
                .decrypt_in_place(&key_schedule.get_server_nonce()?, &header, &mut app_data)
                .map_err(|_| TlsError::CryptoError)?;
            // info!("decrypted with padding {:x?}", app_data.as_slice());
            let padding = app_data
                .as_slice()
                .iter()
                .enumerate()
                .rfind(|(_, b)| **b != 0);
            if let Some((index, _)) = padding {
                app_data.truncate(index + 1);
            };
            //trace!("decrypted {:x?}", data);

            let content_type = ContentType::of(*app_data.as_slice().last().unwrap())
                .ok_or(TlsError::InvalidRecord)?;

            match content_type {
                ContentType::Handshake => {
                    // Decode potentially coaleced handshake messages
                    let (data, offset, len) = app_data.release();
                    let data = &data[offset..offset + len - 1];
                    let mut buf: ParseBuffer<'m> = ParseBuffer::new(data);
                    while buf.remaining() > 1 {
                        let mut inner = ServerHandshake::parse(&mut buf);
                        if let Ok(ServerHandshake::Finished(ref mut finished)) = inner {
                            // trace!("Server finished hash: {:x?}", finished.hash);
                            finished
                                .hash
                                .replace(key_schedule.transcript_hash().clone().finalize());
                        }
                        //info!("===> inner ==> {:?}", inner);
                        //if hash_later {
                        Digest::update(key_schedule.transcript_hash(), &data[..data.len()]);
                        // info!("hash {:02x?}", &data[..data.len()]);
                        records
                            .enqueue(ServerRecord::Handshake(inner.unwrap()))
                            .map_err(|_| TlsError::EncodeError)?
                    }
                    //}
                }
                ContentType::ApplicationData => {
                    app_data.truncate(app_data.len() - 1);
                    let inner = ApplicationData::new(app_data, header);
                    records
                        .enqueue(ServerRecord::ApplicationData(inner))
                        .map_err(|_| TlsError::EncodeError)?
                }
                ContentType::Alert => {
                    let data = &app_data.as_slice()[..app_data.len() - 1];
                    let mut buf = ParseBuffer::new(data);
                    let alert = Alert::parse(&mut buf)?;
                    records
                        .enqueue(ServerRecord::Alert(alert))
                        .map_err(|_| TlsError::EncodeError)?
                }
                _ => return Err(TlsError::Unimplemented),
            }
            //debug!("decrypted {:?} --> {:x?}", content_type, data);
            key_schedule.increment_read_counter();
        } else {
            //info!("Not encapsulated in app data");
            records.enqueue(record).map_err(|_| TlsError::EncodeError)?
        }
        Ok(())
    }

    async fn fetch_records<'m>(
        delegate: &mut Socket,
        rx_buf: &'m mut [u8],
        records: &mut Queue<
            ServerRecord<'m, <CipherSuite::Hash as FixedOutput>::OutputSize>,
            consts::U4,
        >,
        key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
    ) -> Result<ServerRecord<'m, <CipherSuite::Hash as FixedOutput>::OutputSize>, TlsError>
    where
        'a: 'm,
    {
        if let Some(record) = records.dequeue() {
            Ok(record)
        } else {
            let record = Self::fetch_record(delegate, rx_buf, key_schedule).await?;
            Self::decrypt_record(key_schedule, records, record)?;
            if let Some(record) = records.dequeue() {
                Ok(record)
            } else {
                Err(TlsError::DecodeError)
            }
        }
    }

    async fn fetch_record<'m>(
        delegate: &mut Socket,
        rx_buf: &'m mut [u8],
        key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
    ) -> Result<ServerRecord<'m, <CipherSuite::Hash as FixedOutput>::OutputSize>, TlsError> {
        Ok(ServerRecord::read(delegate, rx_buf, key_schedule.transcript_hash()).await?)
    }

    /// Open a TLS connection, performing the handshake with the configuration provided when creating
    /// the connection instance.
    ///
    /// Returns an error if the handshake does not proceed. If an error occurs, the connection instance
    /// must be recreated.
    pub async fn open<'m>(&mut self) -> Result<(), TlsError>
    where
        'a: 'm,
    {
        loop {
            let state = self.state.take().unwrap();
            trace!("From: {:?}", &state);
            let next_state = self.handshake(state).await?;
            trace!("To: {:?}", &next_state);
            self.state.replace(next_state);
            if let Some(State::ApplicationData) = self.state {
                break;
            }
        }

        Ok(())
    }

    async fn handshake<'m>(&mut self, state: State) -> Result<State, TlsError>
    where
        'a: 'm,
    {
        match state {
            State::ClientHello => {
                let key_schedule = &mut self.key_schedule;
                let delegate = &mut self.delegate;
                let frame_buf = &mut self.record_buf;
                let config = &self.config;
                let rng = &mut self.rng;
                key_schedule.initialize_early_secret()?;
                let client_hello = ClientRecord::client_hello(config, rng);

                Self::transmit(delegate, frame_buf, key_schedule, &client_hello, false).await?;

                if let ClientRecord::Handshake(ClientHandshake::ClientHello(client_hello), _) =
                    client_hello
                {
                    Ok(State::ServerHello(client_hello.secret))
                } else {
                    Err(TlsError::EncodeError)
                }
            }
            State::ServerHello(secret) => {
                let key_schedule = &mut self.key_schedule;
                let delegate = &mut self.delegate;
                let frame_buf = &mut self.record_buf;
                let record = Self::fetch_record(delegate, frame_buf, key_schedule).await?;
                /*info!(
                    "SIZE of server record : {}",
                    core::mem::size_of_val(&record)
                );*/
                match record {
                    ServerRecord::Handshake(handshake) => {
                        /*info!(
                            "SIZE of server handshake: {}",
                            core::mem::size_of_val(&handshake)
                        );
                        info!(
                            "SIZE of server hello: {}",
                            core::mem::size_of::<ServerHello>()
                        );
                        info!(
                            "SIZE of encrypted extensions: {}",
                            core::mem::size_of::<EncryptedExtensions>()
                        );
                        info!("SIZE of NST: {}", core::mem::size_of::<NewSessionTicket>());
                        info!(
                            "SIZE of Certificate: {}",
                            core::mem::size_of::<Certificate<'a>>()
                        );
                        info!(
                            "SIZE of CertificateReq: {}",
                            core::mem::size_of::<CertificateRequest>()
                        );
                        info!(
                            "SIZE of CertificateVerify: {}",
                            core::mem::size_of::<CertificateVerify>()
                        );
                        info!(
                            "SIZE of CertificateFinished: {}",
                            core::mem::size_of::<
                                Finished<<CipherSuite::Hash as FixedOutput>::OutputSize>,
                            >()
                        );*/
                        match handshake {
                            ServerHandshake::ServerHello(server_hello) => {
                                trace!("********* ServerHello");
                                let shared = server_hello
                                    .calculate_shared_secret(&secret)
                                    .ok_or(TlsError::InvalidKeyShare)?;
                                key_schedule.initialize_handshake_secret(shared.as_bytes())?;
                                Ok(State::ServerCert)
                            }
                            _ => Err(TlsError::InvalidHandshake),
                        }
                    }
                    _ => Err(TlsError::InvalidRecord),
                }
            }
            State::ClientFinished => {
                /*
                self.transmit(
                    &ClientRecord::ChangeCipherSpec(ChangeCipherSpec::new()),
                    false,
                )
                .await?;*/
                let key_schedule = &mut self.key_schedule;
                let delegate = &mut self.delegate;
                let frame_buf = &mut self.record_buf;
                let hash_after_handshake = key_schedule.transcript_hash().clone();
                if self.cert_requested {
                    let handshake = ClientHandshake::ClientCert(Certificate::new());
                    let client_cert: ClientRecord<'a, '_, CipherSuite> =
                        ClientRecord::Handshake(handshake, true);

                    Self::transmit(delegate, frame_buf, key_schedule, &client_cert, true).await?;
                }

                let client_finished = key_schedule
                    .create_client_finished()
                    .map_err(|_| TlsError::InvalidHandshake)?;

                let client_finished = ClientHandshake::<CipherSuite>::Finished(client_finished);
                let client_finished = ClientRecord::Handshake(client_finished, true);

                Self::transmit(delegate, frame_buf, key_schedule, &client_finished, false).await?;

                key_schedule.replace_transcript_hash(hash_after_handshake);
                key_schedule.initialize_master_secret()?;
                Ok(State::ApplicationData)
            }
            State::ApplicationData => Ok(State::ApplicationData),
            state => {
                let key_schedule = &mut self.key_schedule;
                let delegate = &mut self.delegate;
                let frame_buf = &mut self.record_buf;
                let mut records = Queue::new();
                /*info!(
                    "SIZE of server record queue : {}",
                    core::mem::size_of_val(&records)
                );*/
                let record = Self::fetch_record(delegate, frame_buf, key_schedule).await?;
                Self::decrypt_record(key_schedule, &mut records, record)?;

                let mut state = Some(state);
                while let Some(record) = records.dequeue() {
                    let next_state = match state.take().unwrap() {
                        State::ServerCert => match record {
                            ServerRecord::Handshake(handshake) => match handshake {
                                ServerHandshake::EncryptedExtensions(_) => Ok(State::ServerCert),
                                ServerHandshake::Certificate(_) => Ok(State::ServerCert),
                                ServerHandshake::CertificateVerify(_) => Ok(State::ServerFinished),
                                ServerHandshake::CertificateRequest(_) => {
                                    // TODO: Implement client cert
                                    self.cert_requested = true;
                                    Ok(State::ServerCert)
                                }
                                _ => Err(TlsError::InvalidHandshake),
                            },
                            ServerRecord::ChangeCipherSpec(_) => Ok(State::ServerCert),
                            _ => Err(TlsError::InvalidRecord),
                        },
                        State::ServerFinished => match record {
                            ServerRecord::Handshake(handshake) => match handshake {
                                ServerHandshake::Finished(finished) => {
                                    trace!("************* Finished");
                                    let verified =
                                        key_schedule.verify_server_finished(&finished)?;
                                    if verified {
                                        // trace!("server verified {}", verified);
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
                    trace!("State {:?} -> {:?}", &state, &next_state);
                    state.replace(next_state);
                }
                Ok(state.unwrap())
            }
        }
    }

    /// Encrypt and send the provided slice over the connection. The connection
    /// must be opened before writing.
    ///
    /// Returns the number of bytes written.
    pub async fn write<'m>(&mut self, buf: &'m [u8]) -> Result<usize, TlsError> {
        if let Some(State::ApplicationData) = self.state {
            /*
            {
                let rx_buf = &mut self.frame_buf[..];
                let socket = &mut self.delegate;
                let key_schedule = &mut self.key_schedule;
                info!("Fetching record");
                let record = Self::fetch_record(socket, rx_buf, key_schedule).await?;
                info!("Received record!");
                let mut records = Queue::new();
                Self::decrypt_record(key_schedule, &mut records, record)?;
                info!("Received {} records", records.len());
                while let Some(record) = records.dequeue() {}
            }
            */

            let mut wp = 0;
            let mut remaining = buf.len();

            while remaining > 0 {
                let delegate = &mut self.delegate;
                let frame_buf = &mut self.record_buf;
                let key_schedule = &mut self.key_schedule;
                let to_write = core::cmp::min(remaining, RECORD_MTU);
                // trace!("Writing {} bytes", buf.len());
                /*info!(
                    "SIZE of client handhake : {}",
                    core::mem::size_of::<ClientHandshake<'a, 'm, CipherSuite>>()
                );*/
                let record: ClientRecord<'a, '_, CipherSuite> =
                    ClientRecord::ApplicationData(&buf[wp..to_write]);
                /*info!(
                    "SIZE of client record : {}",
                    core::mem::size_of_val(&record)
                );*/
                let trans = Self::transmit(delegate, frame_buf, key_schedule, &record, false);
                /*info!(
                    "SIZE of transmit future: {}",
                    core::mem::size_of_val(&trans)
                );*/

                trans.await?;
                wp += to_write;
                remaining -= to_write;
            }

            Ok(buf.len())
        } else {
            Err(TlsError::MissingHandshake)
        }
    }

    /// Read and decrypt data filling the provided slice. The slice must be able to
    /// keep the expected amount of data that can be received in one record to avoid
    /// loosing data.
    pub async fn read<'m>(&mut self, buf: &mut [u8]) -> Result<usize, TlsError>
    where
        'a: 'm,
    {
        if let Some(State::ApplicationData) = self.state {
            let mut remaining = buf.len();
            while remaining == buf.len() {
                let rx_buf = &mut self.record_buf[..];
                let socket = &mut self.delegate;
                let key_schedule = &mut self.key_schedule;
                let record = Self::fetch_record(socket, rx_buf, key_schedule).await?;
                let mut records = Queue::new();
                Self::decrypt_record(key_schedule, &mut records, record)?;
                while let Some(record) = records.dequeue() {
                    match record {
                        ServerRecord::ApplicationData(ApplicationData { header: _, data }) => {
                            trace!("Got application data record");
                            if buf.len() < data.len() {
                                warn!("Passed buffer is too small");
                                Err(TlsError::EncodeError)
                            } else {
                                let to_copy = core::cmp::min(data.len(), buf.len());
                                // TODO Need to buffer data not consumed
                                trace!("Got {} bytes to copy", to_copy);
                                buf[..to_copy].copy_from_slice(&data.as_slice()[..to_copy]);
                                remaining -= to_copy;
                                Ok(())
                            }
                        }
                        ServerRecord::Alert(_) => Err(TlsError::InternalError),
                        ServerRecord::ChangeCipherSpec(_) => Err(TlsError::InternalError),
                        ServerRecord::Handshake(ServerHandshake::NewSessionTicket(_)) => {
                            // Ignore
                            Ok(())
                        }
                        _ => {
                            unimplemented!()
                        }
                    }?;
                }
            }
            Ok(buf.len() - remaining)
        } else {
            Err(TlsError::MissingHandshake)
        }
    }
}
