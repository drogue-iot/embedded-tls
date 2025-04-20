use crate::config::{TlsCipherSuite, TlsConfig};
use crate::handshake::{ClientHandshake, ServerHandshake};
use crate::key_schedule::{KeySchedule, ReadKeySchedule, WriteKeySchedule};
use crate::record::{ClientRecord, ServerRecord};
use crate::record_reader::RecordReader;
use crate::write_buffer::WriteBuffer;
use crate::{
    alert::{Alert, AlertDescription, AlertLevel},
    handshake::{certificate::CertificateRef, certificate_request::CertificateRequest},
};
use crate::{CertificateVerify, CryptoProvider, TlsError, TlsVerifier};
use core::fmt::Debug;
use digest::Digest;
use embedded_io::Error as _;
use embedded_io::{Read as BlockingRead, Write as BlockingWrite};
use embedded_io_async::{Read as AsyncRead, Write as AsyncWrite};

use crate::application_data::ApplicationData;
use crate::buffer::CryptoBuffer;
use digest::generic_array::typenum::Unsigned;
use p256::ecdh::EphemeralSecret;
use signature::SignerMut;

use crate::content_types::ContentType;
use crate::parse_buffer::ParseBuffer;
use aes_gcm::aead::{AeadCore, AeadInPlace, KeyInit};

pub(crate) fn decrypt_record<CipherSuite>(
    key_schedule: &mut ReadKeySchedule<CipherSuite>,
    record: ServerRecord<'_, CipherSuite>,
    mut cb: impl FnMut(
        &mut ReadKeySchedule<CipherSuite>,
        ServerRecord<'_, CipherSuite>,
    ) -> Result<(), TlsError>,
) -> Result<(), TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    if let ServerRecord::ApplicationData(ApplicationData {
        header,
        data: mut app_data,
    }) = record
    {
        let server_key = key_schedule.get_key()?;
        let nonce = key_schedule.get_nonce()?;

        let crypto = <CipherSuite::Cipher as KeyInit>::new(&server_key);
        crypto
            .decrypt_in_place(&nonce, header.data(), &mut app_data)
            .map_err(|_| TlsError::CryptoError)?;

        let padding = app_data
            .as_slice()
            .iter()
            .enumerate()
            .rfind(|(_, b)| **b != 0);
        if let Some((index, _)) = padding {
            app_data.truncate(index + 1);
        };

        let content_type =
            ContentType::of(*app_data.as_slice().last().unwrap()).ok_or(TlsError::InvalidRecord)?;

        trace!("Decrypting: content type = {:?}", content_type);

        // Remove the content type
        app_data.truncate(app_data.len() - 1);

        let mut buf = ParseBuffer::new(app_data.as_slice());
        match content_type {
            ContentType::Handshake => {
                // Decode potentially coalesced handshake messages
                while buf.remaining() > 0 {
                    let inner = ServerHandshake::read(&mut buf, key_schedule.transcript_hash())?;
                    cb(key_schedule, ServerRecord::Handshake(inner))?;
                }
            }
            ContentType::ApplicationData => {
                let inner = ApplicationData::new(app_data, header);
                cb(key_schedule, ServerRecord::ApplicationData(inner))?;
            }
            ContentType::Alert => {
                let alert = Alert::parse(&mut buf)?;
                cb(key_schedule, ServerRecord::Alert(alert))?;
            }
            _ => return Err(TlsError::Unimplemented),
        }
        key_schedule.increment_counter();
    } else {
        trace!("Not decrypting: content_type = {:?}", record.content_type());
        cb(key_schedule, record)?;
    }
    Ok(())
}

pub(crate) fn encrypt<CipherSuite>(
    key_schedule: &WriteKeySchedule<CipherSuite>,
    buf: &mut CryptoBuffer<'_>,
) -> Result<(), TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    let client_key = key_schedule.get_key()?;
    let nonce = key_schedule.get_nonce()?;
    // trace!("encrypt key {:02x?}", client_key);
    // trace!("encrypt nonce {:02x?}", nonce);
    // trace!("plaintext {} {:02x?}", buf.len(), buf.as_slice(),);
    //let crypto = Aes128Gcm::new_varkey(&self.key_schedule.get_client_key()).unwrap();
    let crypto = <CipherSuite::Cipher as KeyInit>::new(&client_key);
    let len = buf.len() + <CipherSuite::Cipher as AeadCore>::TagSize::to_usize();

    if len > buf.capacity() {
        return Err(TlsError::InsufficientSpace);
    }

    trace!("output size {}", len);
    let len_bytes = (len as u16).to_be_bytes();
    let additional_data = [
        ContentType::ApplicationData as u8,
        0x03,
        0x03,
        len_bytes[0],
        len_bytes[1],
    ];

    crypto
        .encrypt_in_place(&nonce, &additional_data, buf)
        .map_err(|_| TlsError::InvalidApplicationData)
}

pub struct Handshake<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    traffic_hash: Option<CipherSuite::Hash>,
    secret: Option<EphemeralSecret>,
    certificate_request: Option<CertificateRequest>,
}

impl<CipherSuite> Handshake<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub fn new() -> Handshake<CipherSuite> {
        Handshake {
            traffic_hash: None,
            secret: None,
            certificate_request: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum State {
    ClientHello,
    ServerHello,
    ServerVerify,
    ClientCert,
    ClientCertVerify,
    ClientFinished,
    ApplicationData,
}

impl<'a> State {
    #[allow(clippy::too_many_arguments)]
    pub async fn process<'v, Transport, Provider>(
        self,
        transport: &mut Transport,
        handshake: &mut Handshake<Provider::CipherSuite>,
        record_reader: &mut RecordReader<'_>,
        tx_buf: &mut WriteBuffer<'_>,
        key_schedule: &mut KeySchedule<Provider::CipherSuite>,
        config: &TlsConfig<'a>,
        crypto_provider: &mut Provider,
    ) -> Result<State, TlsError>
    where
        Transport: AsyncRead + AsyncWrite + 'a,
        Provider: CryptoProvider,
    {
        match self {
            State::ClientHello => {
                let (state, tx) =
                    client_hello(key_schedule, config, crypto_provider, tx_buf, handshake)?;

                respond(tx, transport, key_schedule).await?;

                Ok(state)
            }
            State::ServerHello => {
                let record = record_reader
                    .read(transport, key_schedule.read_state())
                    .await?;

                let result = process_server_hello(handshake, key_schedule, record);

                handle_processing_error(result, transport, key_schedule, tx_buf).await
            }
            State::ServerVerify => {
                let record = record_reader
                    .read(transport, key_schedule.read_state())
                    .await?;

                let result =
                    process_server_verify(handshake, key_schedule, config, crypto_provider, record);

                handle_processing_error(result, transport, key_schedule, tx_buf).await
            }
            State::ClientCert => {
                let (state, tx) = client_cert(handshake, key_schedule, config, tx_buf)?;

                respond(tx, transport, key_schedule).await?;

                Ok(state)
            }
            State::ClientCertVerify => {
                let (result, tx) =
                    client_cert_verify(key_schedule, config, crypto_provider, tx_buf)?;

                respond(tx, transport, key_schedule).await?;

                result
            }
            State::ClientFinished => {
                let tx = client_finished(key_schedule, tx_buf)?;

                respond(tx, transport, key_schedule).await?;

                client_finished_finalize(key_schedule, handshake)
            }
            State::ApplicationData => Ok(State::ApplicationData),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn process_blocking<'v, Transport, Provider>(
        self,
        transport: &mut Transport,
        handshake: &mut Handshake<Provider::CipherSuite>,
        record_reader: &mut RecordReader<'_>,
        tx_buf: &mut WriteBuffer,
        key_schedule: &mut KeySchedule<Provider::CipherSuite>,
        config: &TlsConfig<'a>,
        crypto_provider: &mut Provider,
    ) -> Result<State, TlsError>
    where
        Transport: BlockingRead + BlockingWrite + 'a,
        Provider: CryptoProvider,
    {
        match self {
            State::ClientHello => {
                let (state, tx) =
                    client_hello(key_schedule, config, crypto_provider, tx_buf, handshake)?;

                respond_blocking(tx, transport, key_schedule)?;

                Ok(state)
            }
            State::ServerHello => {
                let record = record_reader.read_blocking(transport, key_schedule.read_state())?;

                let result = process_server_hello(handshake, key_schedule, record);

                handle_processing_error_blocking(result, transport, key_schedule, tx_buf)
            }
            State::ServerVerify => {
                let record = record_reader.read_blocking(transport, key_schedule.read_state())?;

                let result =
                    process_server_verify(handshake, key_schedule, config, crypto_provider, record);

                handle_processing_error_blocking(result, transport, key_schedule, tx_buf)
            }
            State::ClientCert => {
                let (state, tx) = client_cert(handshake, key_schedule, config, tx_buf)?;

                respond_blocking(tx, transport, key_schedule)?;

                Ok(state)
            }
            State::ClientCertVerify => {
                let (result, tx) =
                    client_cert_verify(key_schedule, config, crypto_provider, tx_buf)?;

                respond_blocking(tx, transport, key_schedule)?;

                result
            }
            State::ClientFinished => {
                let tx = client_finished(key_schedule, tx_buf)?;

                respond_blocking(tx, transport, key_schedule)?;

                client_finished_finalize(key_schedule, handshake)
            }
            State::ApplicationData => Ok(State::ApplicationData),
        }
    }
}

fn handle_processing_error_blocking<CipherSuite>(
    result: Result<State, TlsError>,
    transport: &mut impl BlockingWrite,
    key_schedule: &mut KeySchedule<CipherSuite>,
    tx_buf: &mut WriteBuffer,
) -> Result<State, TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    if let Err(TlsError::AbortHandshake(level, description)) = result {
        let (write_key_schedule, read_key_schedule) = key_schedule.as_split();
        let tx = tx_buf.write_record(
            &ClientRecord::Alert(Alert { level, description }, false),
            write_key_schedule,
            Some(read_key_schedule),
        )?;

        respond_blocking(tx, transport, key_schedule)?;
    }

    result
}

fn respond_blocking<CipherSuite>(
    tx: &[u8],
    transport: &mut impl BlockingWrite,
    key_schedule: &mut KeySchedule<CipherSuite>,
) -> Result<(), TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    transport
        .write_all(tx)
        .map_err(|e| TlsError::Io(e.kind()))?;

    key_schedule.write_state().increment_counter();

    transport.flush().map_err(|e| TlsError::Io(e.kind()))?;

    Ok(())
}

async fn handle_processing_error<CipherSuite>(
    result: Result<State, TlsError>,
    transport: &mut impl AsyncWrite,
    key_schedule: &mut KeySchedule<CipherSuite>,
    tx_buf: &mut WriteBuffer<'_>,
) -> Result<State, TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    if let Err(TlsError::AbortHandshake(level, description)) = result {
        let (write_key_schedule, read_key_schedule) = key_schedule.as_split();
        let tx = tx_buf.write_record(
            &ClientRecord::Alert(Alert { level, description }, false),
            write_key_schedule,
            Some(read_key_schedule),
        )?;

        respond(tx, transport, key_schedule).await?;
    }

    result
}

async fn respond<CipherSuite>(
    tx: &[u8],
    transport: &mut impl AsyncWrite,
    key_schedule: &mut KeySchedule<CipherSuite>,
) -> Result<(), TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    transport
        .write_all(tx)
        .await
        .map_err(|e| TlsError::Io(e.kind()))?;

    key_schedule.write_state().increment_counter();

    transport
        .flush()
        .await
        .map_err(|e| TlsError::Io(e.kind()))?;

    Ok(())
}

fn client_hello<'r, Provider>(
    key_schedule: &mut KeySchedule<Provider::CipherSuite>,
    config: &TlsConfig,
    crypto_provider: &mut Provider,
    tx_buf: &'r mut WriteBuffer,
    handshake: &mut Handshake<Provider::CipherSuite>,
) -> Result<(State, &'r [u8]), TlsError>
where
    Provider: CryptoProvider,
{
    key_schedule.initialize_early_secret(config.psk.as_ref().map(|p| p.0))?;
    let (write_key_schedule, read_key_schedule) = key_schedule.as_split();
    let client_hello = ClientRecord::client_hello(config, crypto_provider);
    let slice = tx_buf.write_record(&client_hello, write_key_schedule, Some(read_key_schedule))?;

    if let ClientRecord::Handshake(ClientHandshake::ClientHello(client_hello), _) = client_hello {
        handshake.secret.replace(client_hello.secret);
        Ok((State::ServerHello, slice))
    } else {
        Err(TlsError::EncodeError)
    }
}

fn process_server_hello<CipherSuite>(
    handshake: &mut Handshake<CipherSuite>,
    key_schedule: &mut KeySchedule<CipherSuite>,
    record: ServerRecord<'_, CipherSuite>,
) -> Result<State, TlsError>
where
    CipherSuite: TlsCipherSuite,
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
                Ok(State::ServerVerify)
            }
            _ => Err(TlsError::InvalidHandshake),
        },
        ServerRecord::Alert(alert) => {
            Err(TlsError::HandshakeAborted(alert.level, alert.description))
        }
        _ => Err(TlsError::InvalidRecord),
    }
}

fn process_server_verify<Provider>(
    handshake: &mut Handshake<Provider::CipherSuite>,
    key_schedule: &mut KeySchedule<Provider::CipherSuite>,
    config: &TlsConfig<'_>,
    crypto_provider: &mut Provider,
    record: ServerRecord<'_, Provider::CipherSuite>,
) -> Result<State, TlsError>
where
    Provider: CryptoProvider,
{
    let mut state = State::ServerVerify;
    decrypt_record(key_schedule.read_state(), record, |key_schedule, record| {
        match record {
            ServerRecord::Handshake(server_handshake) => {
                match server_handshake {
                    ServerHandshake::EncryptedExtensions(_) => {}
                    ServerHandshake::Certificate(certificate) => {
                        let transcript = key_schedule.transcript_hash();
                        if let Ok(verifier) = crypto_provider.verifier() {
                            verifier.verify_certificate(transcript, &config.ca, certificate)?;
                            debug!("Certificate verified!");
                        } else {
                            debug!("Certificate verification skipped due to no verifier!");
                        }
                    }
                    ServerHandshake::CertificateVerify(verify) => {
                        if let Ok(verifier) = crypto_provider.verifier() {
                            verifier.verify_signature(verify)?;
                            debug!("Signature verified!");
                        } else {
                            debug!("Signature verification skipped due to no verifier!");
                        }
                    }
                    ServerHandshake::CertificateRequest(request) => {
                        handshake.certificate_request.replace(request.try_into()?);
                    }
                    ServerHandshake::Finished(finished) => {
                        if !key_schedule.verify_server_finished(&finished)? {
                            warn!("Server signature verification failed");
                            return Err(TlsError::InvalidSignature);
                        }

                        // trace!("server verified {}", verified);
                        state = if handshake.certificate_request.is_some() {
                            State::ClientCert
                        } else {
                            handshake
                                .traffic_hash
                                .replace(key_schedule.transcript_hash().clone());
                            State::ClientFinished
                        };
                    }
                    _ => return Err(TlsError::InvalidHandshake),
                }
            }
            ServerRecord::ChangeCipherSpec(_) => {}
            _ => return Err(TlsError::InvalidRecord),
        }

        Ok(())
    })?;
    Ok(state)
}

fn client_cert<'r, CipherSuite>(
    handshake: &mut Handshake<CipherSuite>,
    key_schedule: &mut KeySchedule<CipherSuite>,
    config: &TlsConfig,
    buffer: &'r mut WriteBuffer,
) -> Result<(State, &'r [u8]), TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    handshake
        .traffic_hash
        .replace(key_schedule.transcript_hash().clone());

    let request_context = &handshake
        .certificate_request
        .as_ref()
        .ok_or(TlsError::InvalidHandshake)?
        .request_context;

    let mut certificate = CertificateRef::with_context(request_context);
    let next_state = if let Some(cert) = &config.cert {
        certificate.add(cert.into())?;
        State::ClientCertVerify
    } else {
        State::ClientFinished
    };
    let (write_key_schedule, read_key_schedule) = key_schedule.as_split();

    buffer
        .write_record(
            &ClientRecord::Handshake(ClientHandshake::ClientCert(certificate), true),
            write_key_schedule,
            Some(read_key_schedule),
        )
        .map(|slice| (next_state, slice))
}

fn client_cert_verify<'r, Provider>(
    key_schedule: &mut KeySchedule<Provider::CipherSuite>,
    config: &TlsConfig,
    crypto_provider: &mut Provider,
    buffer: &'r mut WriteBuffer,
) -> Result<(Result<State, TlsError>, &'r [u8]), TlsError>
where
    Provider: CryptoProvider,
{
    let (result, record) = match crypto_provider.signer(config.priv_key) {
        Ok((mut signing_key, signature_scheme)) => {
            let ctx_str = b"TLS 1.3, client CertificateVerify\x00";
            let mut msg: heapless::Vec<u8, 130> = heapless::Vec::new();
            msg.resize(64, 0x20).map_err(|()| TlsError::EncodeError)?;
            msg.extend_from_slice(ctx_str)
                .map_err(|()| TlsError::EncodeError)?;
            msg.extend_from_slice(&key_schedule.transcript_hash().clone().finalize())
                .map_err(|()| TlsError::EncodeError)?;

            let signature = signing_key.sign(&msg);

            let certificate_verify = CertificateVerify {
                signature_scheme,
                signature: heapless::Vec::from_slice(signature.as_ref()).unwrap(),
            };

            (
                Ok(State::ClientFinished),
                ClientRecord::Handshake(
                    ClientHandshake::ClientCertVerify(certificate_verify),
                    true,
                ),
            )
        }
        Err(e) => {
            error!("Failed to obtain signing key: {:?}", e);
            (
                Err(e),
                ClientRecord::Alert(
                    Alert::new(AlertLevel::Warning, AlertDescription::CloseNotify),
                    true,
                ),
            )
        }
    };

    let (write_key_schedule, read_key_schedule) = key_schedule.as_split();

    buffer
        .write_record(&record, write_key_schedule, Some(read_key_schedule))
        .map(|slice| (result, slice))
}

fn client_finished<'r, CipherSuite>(
    key_schedule: &mut KeySchedule<CipherSuite>,
    buffer: &'r mut WriteBuffer,
) -> Result<&'r [u8], TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    let client_finished = key_schedule
        .create_client_finished()
        .map_err(|_| TlsError::InvalidHandshake)?;

    let (write_key_schedule, read_key_schedule) = key_schedule.as_split();

    buffer.write_record(
        &ClientRecord::Handshake(ClientHandshake::Finished(client_finished), true),
        write_key_schedule,
        Some(read_key_schedule),
    )
}

fn client_finished_finalize<CipherSuite>(
    key_schedule: &mut KeySchedule<CipherSuite>,
    handshake: &mut Handshake<CipherSuite>,
) -> Result<State, TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    key_schedule.replace_transcript_hash(
        handshake
            .traffic_hash
            .take()
            .ok_or(TlsError::InvalidHandshake)?,
    );
    key_schedule.initialize_master_secret()?;

    Ok(State::ApplicationData)
}
