use crate::config::{TlsCipherSuite, TlsConfig};
use crate::handshake::{ClientHandshake, ServerHandshake};
use crate::key_schedule::KeySchedule;
use crate::record::{ClientRecord, ServerRecord};
use crate::{alert::*, handshake::certificate::Certificate};
use crate::{
    traits::{AsyncRead, AsyncWrite},
    TlsError,
};
use core::fmt::Debug;
use rand_core::{CryptoRng, RngCore};

use crate::application_data::ApplicationData;
// use crate::handshake::certificate_request::CertificateRequest;
// use crate::handshake::certificate_verify::CertificateVerify;
// use crate::handshake::encrypted_extensions::EncryptedExtensions;
// use crate::handshake::finished::Finished;
// use crate::handshake::new_session_ticket::NewSessionTicket;
// use crate::handshake::server_hello::ServerHello;
use crate::buffer::CryptoBuffer;
use digest::generic_array::typenum::Unsigned;
use p256::ecdh::EphemeralSecret;
use sha2::Digest;

use crate::content_types::ContentType;
// use crate::handshake::certificate_request::CertificateRequest;
// use crate::handshake::certificate_verify::CertificateVerify;
// use crate::handshake::encrypted_extensions::EncryptedExtensions;
// use crate::handshake::finished::Finished;
// use crate::handshake::new_session_ticket::NewSessionTicket;
// use crate::handshake::server_hello::ServerHello;
use crate::parse_buffer::ParseBuffer;
use aes_gcm::aead::{AeadInPlace, NewAead};
use digest::FixedOutput;
use heapless::{consts, spsc::Queue};

pub(crate) fn decrypt_record<'m, CipherSuite>(
    key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
    records: &mut Queue<
        ServerRecord<'m, <CipherSuite::Hash as FixedOutput>::OutputSize>,
        consts::U4,
    >,
    record: ServerRecord<'m, <CipherSuite::Hash as FixedOutput>::OutputSize>,
) -> Result<(), TlsError>
where
    CipherSuite: TlsCipherSuite + 'static,
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

        let content_type =
            ContentType::of(*app_data.as_slice().last().unwrap()).ok_or(TlsError::InvalidRecord)?;

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

pub(crate) fn encrypt<CipherSuite>(
    key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
    buf: &mut CryptoBuffer<'_>,
) -> Result<usize, TlsError>
where
    CipherSuite: TlsCipherSuite + 'static,
{
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

pub async fn transmit<'m, W, CipherSuite>(
    delegate: &mut W,
    tx_buf: &mut [u8],
    key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
    record: &ClientRecord<'_, 'm, CipherSuite>,
    update_hash: bool,
) -> Result<(), TlsError>
where
    W: AsyncWrite + 'm,
    CipherSuite: TlsCipherSuite + 'static,
{
    let mut next_hash = key_schedule.transcript_hash().clone();

    let (len, range) = record.encode(tx_buf, &mut next_hash, |buf| {
        encrypt::<CipherSuite>(key_schedule, buf)
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

pub async fn fetch_record<'m, Transport, CipherSuite>(
    transport: &mut Transport,
    rx_buf: &'m mut [u8],
    key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
) -> Result<ServerRecord<'m, <CipherSuite::Hash as FixedOutput>::OutputSize>, TlsError>
where
    Transport: AsyncWrite + AsyncRead + 'm,
    CipherSuite: TlsCipherSuite + 'static,
{
    Ok(ServerRecord::read(transport, rx_buf, key_schedule.transcript_hash()).await?)
}

pub struct Handshake<CipherSuite>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    traffic_hash: Option<CipherSuite::Hash>,
    secret: Option<EphemeralSecret>,
}

impl<'a, CipherSuite> Handshake<CipherSuite>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    pub fn new() -> Handshake<CipherSuite> {
        Handshake {
            traffic_hash: None,
            secret: None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum State {
    ClientHello,
    ServerHello,
    ServerVerify,
    ClientCert,
    ClientFinished,
    ApplicationData,
}

impl<'a> State {
    pub async fn process<Transport, CipherSuite, RNG>(
        self,
        transport: &mut Transport,
        handshake: &mut Handshake<CipherSuite>,
        record_buf: &mut [u8],
        key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
        config: &TlsConfig<'a, CipherSuite>,
        rng: &mut RNG,
    ) -> Result<State, TlsError>
    where
        Transport: AsyncRead + AsyncWrite + 'a,
        RNG: CryptoRng + RngCore + 'static,
        CipherSuite: TlsCipherSuite + 'static,
    {
        match self {
            State::ClientHello => {
                key_schedule.initialize_early_secret()?;
                let client_hello = ClientRecord::client_hello(config, rng);

                transmit(transport, record_buf, key_schedule, &client_hello, false).await?;

                if let ClientRecord::Handshake(ClientHandshake::ClientHello(client_hello), _) =
                    client_hello
                {
                    handshake.secret.replace(client_hello.secret);
                    Ok(State::ServerHello)
                } else {
                    Err(TlsError::EncodeError)
                }
            }
            State::ServerHello => {
                let record =
                    fetch_record::<Transport, CipherSuite>(transport, record_buf, key_schedule)
                        .await?;
                match record {
                    ServerRecord::Handshake(server_handshake) => match server_handshake {
                        ServerHandshake::ServerHello(server_hello) => {
                            trace!("********* ServerHello");
                            let secret =
                                handshake.secret.take().ok_or(TlsError::InvalidHandshake)?;
                            let shared = server_hello
                                .calculate_shared_secret(&secret)
                                .ok_or(TlsError::InvalidKeyShare)?;
                            key_schedule.initialize_handshake_secret(shared.as_bytes())?;
                            Ok(State::ServerVerify)
                        }
                        _ => Err(TlsError::InvalidHandshake),
                    },
                    _ => Err(TlsError::InvalidRecord),
                }
            }
            State::ServerVerify => {
                let mut records = Queue::new();
                /*info!(
                    "SIZE of server record queue : {}",
                    core::mem::size_of_val(&records)
                );*/
                let record =
                    fetch_record::<Transport, CipherSuite>(transport, record_buf, key_schedule)
                        .await?;
                let mut cert_requested = false;
                decrypt_record::<CipherSuite>(key_schedule, &mut records, record)?;

                let mut state = self;

                while let Some(record) = records.dequeue() {
                    if let State::ServerVerify = state {
                        let result = match record {
                            ServerRecord::Handshake(server_handshake) => match server_handshake {
                                ServerHandshake::EncryptedExtensions(_) => Ok(State::ServerVerify),
                                ServerHandshake::Certificate(_) => Ok(State::ServerVerify),
                                ServerHandshake::CertificateVerify(_) => Ok(State::ServerVerify),
                                ServerHandshake::CertificateRequest(_) => {
                                    cert_requested = true;
                                    Ok(State::ServerVerify)
                                }
                                ServerHandshake::Finished(finished) => {
                                    trace!("************* Finished");
                                    let verified =
                                        key_schedule.verify_server_finished(&finished)?;
                                    if verified {
                                        // trace!("server verified {}", verified);
                                        if cert_requested {
                                            Ok(State::ClientCert)
                                        } else {
                                            handshake
                                                .traffic_hash
                                                .replace(key_schedule.transcript_hash().clone());
                                            Ok(State::ClientFinished)
                                        }
                                    } else {
                                        Err(TlsError::InvalidSignature)
                                    }
                                }
                                _ => Err(TlsError::InvalidHandshake),
                            },
                            ServerRecord::ChangeCipherSpec(_) => Ok(State::ServerVerify),
                            _ => Err(TlsError::InvalidRecord),
                        }?;
                        state = result;
                    }
                }
                Ok(state)
            }
            State::ClientCert => {
                handshake
                    .traffic_hash
                    .replace(key_schedule.transcript_hash().clone());

                let client_handshake = ClientHandshake::ClientCert(Certificate::new());
                let client_cert: ClientRecord<'a, '_, CipherSuite> =
                    ClientRecord::Handshake(client_handshake, true);
                transmit(transport, record_buf, key_schedule, &client_cert, true).await?;
                Ok(State::ClientFinished)
            }
            State::ClientFinished => {
                let client_finished = key_schedule
                    .create_client_finished()
                    .map_err(|_| TlsError::InvalidHandshake)?;

                let client_finished = ClientHandshake::<CipherSuite>::Finished(client_finished);
                let client_finished = ClientRecord::Handshake(client_finished, true);

                transmit(transport, record_buf, key_schedule, &client_finished, false).await?;

                key_schedule.replace_transcript_hash(
                    handshake
                        .traffic_hash
                        .take()
                        .ok_or(TlsError::InvalidHandshake)?,
                );
                key_schedule.initialize_master_secret()?;

                Ok(State::ApplicationData)
            }
            State::ApplicationData => Ok(State::ApplicationData),
        }
    }
}
