use crate::config::{TlsCipherSuite, TlsConfig, TlsVerifier};
use crate::handshake::{ClientHandshake, ServerHandshake};
use crate::key_schedule::KeySchedule;
use crate::record::{encode_application_data_in_place, ClientRecord, ServerRecord};
use crate::record_reader::RecordReader;
use crate::TlsError;
use crate::{
    alert::*,
    handshake::{certificate::CertificateRef, certificate_request::CertificateRequest},
};
use core::fmt::Debug;
use core::ops::ControlFlow;
use embedded_io::Error as _;
use rand_core::{CryptoRng, RngCore};

use embedded_io::blocking::{Read as BlockingRead, Write as BlockingWrite};

#[cfg(feature = "async")]
use embedded_io::asynch::{Read as AsyncRead, Write as AsyncWrite};

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
use aes_gcm::aead::{AeadCore, AeadInPlace, KeyInit};
use digest::OutputSizeUser;

pub(crate) fn decrypt_record_in_place<'m, CipherSuite, R>(
    key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
    record: ServerRecord<'m, <CipherSuite::Hash as OutputSizeUser>::OutputSize>,
    default: R,
    mut cb: impl FnMut(
        &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
        ServerRecord<'m, <CipherSuite::Hash as OutputSizeUser>::OutputSize>,
    ) -> Result<ControlFlow<R>, TlsError>,
) -> Result<R, TlsError>
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
        let crypto = <CipherSuite::Cipher as KeyInit>::new(&key_schedule.get_server_key()?);
        // let nonce = &key_schedule.get_server_nonce();
        // info!("server write nonce {:x?}", nonce);
        crypto
            .decrypt_in_place(
                &key_schedule.get_server_nonce()?,
                header.data(),
                &mut app_data,
            )
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

        trace!("Decrypting content type = {:?}", content_type);

        match content_type {
            ContentType::Handshake => {
                // Decode potentially coaleced handshake messages
                let (data, offset, len) = app_data.release();
                let data = &data[offset..offset + len - 1];
                let mut buf: ParseBuffer<'m> = ParseBuffer::new(data);
                while buf.remaining() > 1 {
                    let mut inner = ServerHandshake::parse(&mut buf)?;
                    if let ServerHandshake::Finished(ref mut finished) = inner {
                        // trace!("Server finished hash: {:x?}", finished.hash);
                        finished
                            .hash
                            .replace(key_schedule.transcript_hash().clone().finalize());
                    }
                    //info!("===> inner ==> {:?}", inner);
                    //if hash_later {
                    Digest::update(key_schedule.transcript_hash(), &data[..data.len()]);
                    // info!("hash {:02x?}", &data[..data.len()]);
                    if let ControlFlow::Break(val) =
                        cb(key_schedule, ServerRecord::Handshake(inner))?
                    {
                        return Ok(val);
                    }
                }
                //}
            }
            ContentType::ApplicationData => {
                app_data.truncate(app_data.len() - 1);
                let inner = ApplicationData::new(app_data, header);
                if let ControlFlow::Break(val) =
                    cb(key_schedule, ServerRecord::ApplicationData(inner))?
                {
                    return Ok(val);
                }
            }
            ContentType::Alert => {
                let data = &app_data.as_slice()[..app_data.len() - 1];
                let mut buf = ParseBuffer::new(data);
                let alert = Alert::parse(&mut buf)?;
                if let ControlFlow::Break(val) = cb(key_schedule, ServerRecord::Alert(alert))? {
                    return Ok(val);
                }
            }
            _ => return Err(TlsError::Unimplemented),
        }
        //debug!("decrypted {:?} --> {:x?}", content_type, data);
        key_schedule.increment_read_counter();
    } else {
        debug!("Not decrypting: Not encapsulated in app data");
        if let ControlFlow::Break(val) = cb(key_schedule, record)? {
            return Ok(val);
        }
    }
    Ok(default)
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
    let crypto = <CipherSuite::Cipher as KeyInit>::new(&client_key);
    let len = buf.len() + <CipherSuite::Cipher as AeadCore>::TagSize::to_usize();

    if len > buf.capacity() {
        return Err(TlsError::InsufficientSpace);
    }

    trace!(
        "output size {}",
        <CipherSuite::Cipher as AeadCore>::TagSize::to_usize()
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

pub fn encode_record<'m, CipherSuite>(
    tx_buf: &mut [u8],
    key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
    record: &ClientRecord<'_, 'm, CipherSuite>,
) -> Result<(CipherSuite::Hash, usize), TlsError>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    let mut next_hash = key_schedule.transcript_hash().clone();

    let (len, range) = record.encode(tx_buf, &mut next_hash, |buf| {
        encrypt::<CipherSuite>(key_schedule, buf)
    })?;

    if let Some(range) = range {
        if let ClientRecord::Handshake(ClientHandshake::ClientHello(hello), false) = record {
            // Special case for PSK which needs to:
            //
            // 1. Add the client hello without the binders to the transcript
            // 2. Create the binders for each identity using the transcript
            // 3. Add the rest of the client hello.
            //
            // This causes a few issues since lengths must be correctly inside the payload,
            // but won't actually be added to the record buffer until the end.
            if let Some((_, identities)) = &hello.config.psk {
                let binders_len =
                    identities.len() * (1 + <CipherSuite::Hash as OutputSizeUser>::output_size());

                // NOTE: Exclude the binders_len itself from the digest
                Digest::update(
                    key_schedule.transcript_hash(),
                    &tx_buf[range.start..range.end - binders_len - 2],
                );

                // Append after the client hello data. Sizes have already been set.
                let mut buf = CryptoBuffer::wrap(&mut tx_buf[range.end - binders_len..]);
                // Create a binder and encode for each identity
                for _id in identities {
                    let binder = key_schedule.create_psk_binder()?;
                    binder.encode(&mut buf)?;
                }

                Digest::update(
                    key_schedule.transcript_hash(),
                    &tx_buf[range.end - binders_len - 2..range.end],
                );
            } else {
                Digest::update(key_schedule.transcript_hash(), &tx_buf[range]);
            }
        } else {
            Digest::update(key_schedule.transcript_hash(), &tx_buf[range]);
        }
    }

    Ok((next_hash, len))
}

pub fn encode_application_data_record_in_place<CipherSuite>(
    tx_buf: &mut [u8],
    data_len: usize,
    key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
) -> Result<usize, TlsError>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    encode_application_data_in_place(tx_buf, data_len, |buf| {
        encrypt::<CipherSuite>(key_schedule, buf)
    })
}

pub struct Handshake<CipherSuite, Verifier>
where
    CipherSuite: TlsCipherSuite + 'static,
    Verifier: TlsVerifier<CipherSuite>,
{
    traffic_hash: Option<CipherSuite::Hash>,
    secret: Option<EphemeralSecret>,
    certificate_request: Option<CertificateRequest>,
    verifier: Verifier,
}

impl<CipherSuite, Verifier> Handshake<CipherSuite, Verifier>
where
    CipherSuite: TlsCipherSuite + 'static,
    Verifier: TlsVerifier<CipherSuite>,
{
    pub fn new(verifier: Verifier) -> Handshake<CipherSuite, Verifier> {
        Handshake {
            traffic_hash: None,
            secret: None,
            certificate_request: None,
            verifier,
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum State {
    ClientHello,
    ServerHello,
    ServerVerify,
    ClientCert,
    ClientFinished,
    ApplicationData,
}

impl<'a> State {
    #[cfg(feature = "async")]
    #[allow(clippy::too_many_arguments)]
    pub async fn process<Transport, CipherSuite, RNG, Verifier>(
        self,
        transport: &mut Transport,
        handshake: &mut Handshake<CipherSuite, Verifier>,
        record_reader: &mut RecordReader<'_, CipherSuite>,
        tx_buf: &mut [u8],
        key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
        config: &TlsConfig<'a, CipherSuite>,
        rng: &mut RNG,
    ) -> Result<State, TlsError>
    where
        Transport: AsyncRead + AsyncWrite + 'a,
        RNG: CryptoRng + RngCore + 'a,
        CipherSuite: TlsCipherSuite + 'static,
        Verifier: TlsVerifier<CipherSuite>,
    {
        match self {
            State::ClientHello => {
                key_schedule.initialize_early_secret(config.psk.as_ref().map(|p| p.0))?;
                let client_hello = ClientRecord::client_hello(config, rng);
                let (_, len) = encode_record(tx_buf, key_schedule, &client_hello)?;

                transport
                    .write_all(&tx_buf[..len])
                    .await
                    .map_err(|e| TlsError::Io(e.kind()))?;

                key_schedule.increment_write_counter();
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
                let record = record_reader.read(transport, key_schedule).await?;
                process_server_hello(handshake, key_schedule, record)?;
                Ok(State::ServerVerify)
            }
            State::ServerVerify => {
                /*info!(
                    "SIZE of server record queue : {}",
                    core::mem::size_of_val(&records)
                );*/
                let record = record_reader.read(transport, key_schedule).await?;

                process_server_verify::<_, Verifier>(handshake, key_schedule, config, record)
            }
            State::ClientCert => {
                handshake
                    .traffic_hash
                    .replace(key_schedule.transcript_hash().clone());

                let request_context = &handshake
                    .certificate_request
                    .as_ref()
                    .ok_or(TlsError::InvalidHandshake)?
                    .request_context;

                let certificate = if let Some(cert) = &config.cert {
                    let mut certificate = CertificateRef::with_context(request_context);
                    certificate.add(cert.into())?;
                    certificate
                } else {
                    CertificateRef::with_context(&[])
                };

                let client_handshake = ClientHandshake::ClientCert(certificate);
                let client_cert: ClientRecord<'a, '_, CipherSuite> =
                    ClientRecord::Handshake(client_handshake, true);

                let (next_hash, len) = encode_record(tx_buf, key_schedule, &client_cert)?;
                transport
                    .write_all(&tx_buf[..len])
                    .await
                    .map_err(|e| TlsError::Io(e.kind()))?;
                key_schedule.increment_write_counter();
                key_schedule.replace_transcript_hash(next_hash);
                Ok(State::ClientFinished)
            }
            State::ClientFinished => {
                let client_finished = key_schedule
                    .create_client_finished()
                    .map_err(|_| TlsError::InvalidHandshake)?;

                let client_finished = ClientHandshake::<CipherSuite>::Finished(client_finished);
                let client_finished = ClientRecord::Handshake(client_finished, true);

                let (_, len) = encode_record(tx_buf, key_schedule, &client_finished)?;
                transport
                    .write_all(&tx_buf[..len])
                    .await
                    .map_err(|e| TlsError::Io(e.kind()))?;
                key_schedule.increment_write_counter();

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

    #[allow(clippy::too_many_arguments)]
    pub fn process_blocking<Transport, CipherSuite, RNG, Verifier>(
        self,
        transport: &mut Transport,
        handshake: &mut Handshake<CipherSuite, Verifier>,
        record_reader: &mut RecordReader<'_, CipherSuite>,
        tx_buf: &mut [u8],
        key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
        config: &TlsConfig<'a, CipherSuite>,
        rng: &mut RNG,
    ) -> Result<State, TlsError>
    where
        Transport: BlockingRead + BlockingWrite + 'a,
        RNG: CryptoRng + RngCore,
        CipherSuite: TlsCipherSuite + 'static,
        Verifier: TlsVerifier<CipherSuite>,
    {
        match self {
            State::ClientHello => {
                key_schedule.initialize_early_secret(config.psk.as_ref().map(|p| p.0))?;
                let client_hello = ClientRecord::client_hello(config, rng);
                let (_, len) = encode_record(tx_buf, key_schedule, &client_hello)?;

                transport
                    .write_all(&tx_buf[..len])
                    .map_err(|e| TlsError::Io(e.kind()))?;

                key_schedule.increment_write_counter();
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
                let record = record_reader.read_blocking(transport, key_schedule)?;
                process_server_hello(handshake, key_schedule, record)?;
                Ok(State::ServerVerify)
            }
            State::ServerVerify => {
                /*info!(
                    "SIZE of server record queue : {}",
                    core::mem::size_of_val(&records)
                );*/
                let record = record_reader.read_blocking(transport, key_schedule)?;

                process_server_verify::<_, Verifier>(handshake, key_schedule, config, record)
            }
            State::ClientCert => {
                handshake
                    .traffic_hash
                    .replace(key_schedule.transcript_hash().clone());

                let request_context = &handshake
                    .certificate_request
                    .as_ref()
                    .ok_or(TlsError::InvalidHandshake)?
                    .request_context;

                let mut certificate = CertificateRef::with_context(request_context);
                if let Some(cert) = &config.cert {
                    certificate.add(cert.into())?;
                }
                let client_handshake = ClientHandshake::ClientCert(certificate);
                let client_cert: ClientRecord<'a, '_, CipherSuite> =
                    ClientRecord::Handshake(client_handshake, true);

                let (next_hash, len) = encode_record(tx_buf, key_schedule, &client_cert)?;
                transport
                    .write_all(&tx_buf[..len])
                    .map_err(|e| TlsError::Io(e.kind()))?;
                key_schedule.increment_write_counter();
                key_schedule.replace_transcript_hash(next_hash);
                Ok(State::ClientFinished)
            }
            State::ClientFinished => {
                let client_finished = key_schedule
                    .create_client_finished()
                    .map_err(|_| TlsError::InvalidHandshake)?;

                let client_finished = ClientHandshake::<CipherSuite>::Finished(client_finished);
                let client_finished = ClientRecord::Handshake(client_finished, true);

                let (_, len) = encode_record(tx_buf, key_schedule, &client_finished)?;
                transport
                    .write_all(&tx_buf[..len])
                    .map_err(|e| TlsError::Io(e.kind()))?;
                key_schedule.increment_write_counter();

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

fn process_server_hello<CipherSuite, Verifier>(
    handshake: &mut Handshake<CipherSuite, Verifier>,
    key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
    record: ServerRecord<'_, <CipherSuite::Hash as OutputSizeUser>::OutputSize>,
) -> Result<(), TlsError>
where
    CipherSuite: TlsCipherSuite + 'static,
    Verifier: TlsVerifier<CipherSuite>,
{
    {
        match record {
            ServerRecord::Handshake(server_handshake) => match server_handshake {
                ServerHandshake::ServerHello(server_hello) => {
                    trace!("********* ServerHello");
                    let secret = handshake.secret.take().ok_or(TlsError::InvalidHandshake)?;
                    let shared = server_hello
                        .calculate_shared_secret(&secret)
                        .ok_or(TlsError::InvalidKeyShare)?;
                    key_schedule.initialize_handshake_secret(shared.raw_secret_bytes())?;
                    Ok(())
                }
                _ => Err(TlsError::InvalidHandshake),
            },
            ServerRecord::Alert(alert) => {
                Err(TlsError::HandshakeAborted(alert.level, alert.description))
            }
            _ => Err(TlsError::InvalidRecord),
        }
    }
}

fn process_server_verify<'a, CipherSuite, Verifier>(
    handshake: &mut Handshake<CipherSuite, Verifier>,
    key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
    config: &TlsConfig<'a, CipherSuite>,
    record: ServerRecord<'_, <CipherSuite::Hash as OutputSizeUser>::OutputSize>,
) -> Result<State, TlsError>
where
    CipherSuite: TlsCipherSuite + 'static,
    Verifier: TlsVerifier<CipherSuite>,
{
    decrypt_record_in_place::<CipherSuite, _>(
        key_schedule,
        record,
        State::ServerVerify,
        |key_schedule, record| {
            match record {
                ServerRecord::Handshake(server_handshake) => match server_handshake {
                    ServerHandshake::EncryptedExtensions(_) => {}
                    ServerHandshake::Certificate(certificate) => {
                        trace!("Verifying certificate!");
                        let transcript = key_schedule.transcript_hash();
                        handshake.verifier.verify_certificate(
                            transcript,
                            &config.ca,
                            certificate,
                        )?;
                        trace!("Certificate verified!");
                    }
                    ServerHandshake::CertificateVerify(verify) => {
                        trace!("Verifying signature!");
                        handshake.verifier.verify_signature(verify)?;
                        trace!("Signature verified!");
                    }
                    ServerHandshake::CertificateRequest(request) => {
                        trace!("Certificate requested");
                        handshake.certificate_request.replace(request.try_into()?);
                    }
                    ServerHandshake::Finished(finished) => {
                        trace!("************* Finished");
                        let verified = key_schedule.verify_server_finished(&finished)?;
                        if !verified {
                            return Err(TlsError::InvalidSignature);
                        }

                        // trace!("server verified {}", verified);
                        let state = if handshake.certificate_request.is_some() {
                            State::ClientCert
                        } else {
                            handshake
                                .traffic_hash
                                .replace(key_schedule.transcript_hash().clone());
                            State::ClientFinished
                        };

                        return Ok(ControlFlow::Break(state));
                    }
                    _ => return Err(TlsError::InvalidHandshake),
                },
                ServerRecord::ChangeCipherSpec(_) => {}
                _ => return Err(TlsError::InvalidRecord),
            }

            Ok(ControlFlow::Continue(()))
        },
    )
}
