use crate::handshake::{ClientHandshake, ServerHandshake};
use crate::key_schedule::KeySchedule;
use crate::record::{ClientRecord, ServerRecord};
use crate::{
    buffer::CryptoBuffer,
    config::{Config, TlsCipherSuite},
};
use crate::{AsyncRead, AsyncWrite, TlsError};
use core::fmt::Debug;
use digest::generic_array::typenum::Unsigned;
use rand_core::{CryptoRng, RngCore};
use sha2::Digest;

use crate::application_data::ApplicationData;
use crate::content_types::ContentType;
use crate::parse_buffer::ParseBuffer;
use aes_gcm::aead::{AeadInPlace, NewAead};
use digest::FixedOutput;

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

pub struct TlsConnection<
    'a,
    RNG,
    Socket,
    CipherSuite,
    const TX_BUF_LEN: usize,
    const RX_BUF_LEN: usize,
> where
    RNG: CryptoRng + RngCore + Copy + 'static,
    Socket: AsyncRead + AsyncWrite + 'static,
    CipherSuite: TlsCipherSuite + 'static,
{
    delegate: Socket,
    config: &'a Config<RNG, CipherSuite>,
    key_schedule: KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
    tx_buf: [u8; TX_BUF_LEN],
    rx_buf: [u8; RX_BUF_LEN],
    state: State,
}

impl<'a, RNG, Socket, CipherSuite, const TX_BUF_LEN: usize, const RX_BUF_LEN: usize>
    TlsConnection<'a, RNG, Socket, CipherSuite, TX_BUF_LEN, RX_BUF_LEN>
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
            tx_buf: [0; TX_BUF_LEN],
            rx_buf: [0; RX_BUF_LEN],
        }
    }

    async fn transmit<'m>(
        &mut self,
        record: &ClientRecord<'_, 'm, RNG, CipherSuite>,
    ) -> Result<(), TlsError> {
        let tx_buf = &mut self.tx_buf[..];
        let key_schedule = &mut self.key_schedule;
        let delegate = &mut self.delegate;

        let (len, range) = record.encode(tx_buf, |buf| Self::encrypt(key_schedule, buf))?;

        if let Some(range) = range {
            Digest::update(key_schedule.transcript_hash(), &tx_buf[range]);
        }
        trace!(
            "**** transmit {} bytes, hash={:x?}",
            len,
            key_schedule.transcript_hash().clone().finalize()
        );

        delegate.write(&tx_buf[..len]).await?;

        key_schedule.increment_write_counter();
        Ok(())
    }

    fn encrypt(
        key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
        buf: &mut CryptoBuffer<'_>,
    ) -> Result<usize, TlsError> {
        let client_key = key_schedule.get_client_key()?;
        let nonce = &key_schedule.get_client_nonce()?;
        trace!("encrypt key {:02x?}", client_key);
        trace!("encrypt nonce {:02x?}", nonce);
        trace!("plaintext {} {:02x?}", buf.len(), buf.as_slice(),);
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
                            trace!("Server finished hash: {:x?}", finished.hash);
                            finished
                                .hash
                                .replace(key_schedule.transcript_hash().clone().finalize());
                        }
                        trace!("===> inner ==> {:?}", inner);
                        //if hash_later {
                        Digest::update(key_schedule.transcript_hash(), &data[..data.len()]);
                        trace!("hash {:02x?}", &data[..data.len()]);
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
        Ok(ServerRecord::read(delegate, rx_buf, key_schedule.transcript_hash()).await?)
    }

    pub async fn open<'m>(&mut self) -> Result<(), TlsError>
    where
        'a: 'm,
    {
        self.state = State::ClientHello;
        self.key_schedule.initialize_early_secret()?;
        let client_hello = ClientRecord::client_hello(&self.config);

        self.transmit(&client_hello).await?;

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
                                    debug!("server verified {}", verified);
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
                debug!("State {:?} -> {:?}", *state, next_state);
                *state = next_state;
                Ok(())
            })?;
        }

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

        self.transmit(&client_finished).await?;

        self.key_schedule.initialize_master_secret()?;
        self.state = State::ApplicationData;
        Ok(())
    }

    pub async fn write<'m>(&mut self, buf: &'m [u8]) -> Result<usize, TlsError> {
        if self.state != State::ApplicationData {
            return Err(TlsError::MissingHandshake);
        }

        info!("Writing {} bytes", buf.len());
        let record: ClientRecord<'a, 'm, RNG, CipherSuite> = ClientRecord::ApplicationData(buf);
        self.transmit(&record).await?;
        Ok(buf.len())
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
