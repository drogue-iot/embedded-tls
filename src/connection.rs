use crate::config::TlsConfig;
use crate::crypto_traits::{TlsAead, TlsHash};
use crate::handshake::{ClientHandshake, ServerHandshake};
use crate::key_schedule::{KeySchedule, ReadKeySchedule, WriteKeySchedule};
use crate::record::{ClientRecord, ServerRecord};
use crate::record_reader::RecordReader;
use crate::write_buffer::WriteBuffer;
use crate::{CertificateVerify, CryptoProvider, TlsError, TlsVerifier};
use crate::{
    alert::{Alert, AlertDescription, AlertLevel},
    handshake::{certificate::CertificateRef, certificate_request::CertificateRequest},
};
use core::fmt::Debug;
use embedded_io::Error as _;
use embedded_io::{Read as BlockingRead, Write as BlockingWrite};
use embedded_io_async::{Read as AsyncRead, Write as AsyncWrite};

use crate::application_data::ApplicationData;
use crate::buffer::CryptoBuffer;
use crate::content_types::ContentType;
use crate::extensions::extension_data::supported_groups::NamedGroup;
use crate::parse_buffer::ParseBuffer;
use signature::SignerMut;

// AES-GCM tag size is always 16 bytes for the supported cipher suites
const TAG_SIZE: usize = 16;

pub(crate) fn decrypt_record<Provider>(
    key_schedule: &mut ReadKeySchedule<Provider>,
    record: ServerRecord<'_, Provider>,
    mut cb: impl FnMut(
        &mut ReadKeySchedule<Provider>,
        ServerRecord<'_, Provider>,
    ) -> Result<(), TlsError>,
) -> Result<(), TlsError>
where
    Provider: CryptoProvider,
{
    if let ServerRecord::ApplicationData(ApplicationData {
        header,
        data: mut app_data,
    }) = record
    {
        let nonce = key_schedule.get_nonce()?;

        // Split ciphertext and tag
        let ciphertext_len = app_data.len().saturating_sub(TAG_SIZE);
        if ciphertext_len == 0 {
            return Err(TlsError::InvalidRecord);
        }
        let (ciphertext, tag) = app_data.as_mut_slice().split_at_mut(ciphertext_len);

        let aead = key_schedule.get_aead().map_err(|_| TlsError::CryptoError)?;
        aead.decrypt_in_place(&nonce, header.data(), ciphertext, tag)
            .map_err(|_| TlsError::CryptoError)?;

        // After decryption, ciphertext contains plaintext
        app_data.truncate(ciphertext_len);

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

pub(crate) fn encrypt<Provider>(
    key_schedule: &mut WriteKeySchedule<Provider>,
    buf: &mut CryptoBuffer<'_>,
) -> Result<(), TlsError>
where
    Provider: CryptoProvider,
{
    let nonce = key_schedule.get_nonce()?;

    let len = buf.len() + TAG_SIZE;
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

    let aead = key_schedule.get_aead().map_err(|_| TlsError::CryptoError)?;
    let mut tag = [0u8; TAG_SIZE];
    aead.encrypt_in_place(&nonce, &additional_data, buf.as_mut_slice(), &mut tag)
        .map_err(|_| TlsError::InvalidApplicationData)?;
    buf.extend_from_slice(&tag)
        .map_err(|_| TlsError::InsufficientSpace)?;
    Ok(())
}

pub struct Handshake<Provider: CryptoProvider> {
    traffic_hash: Option<Provider::Hash>,
    secret_key: Option<[u8; 32]>,
    certificate_request: Option<CertificateRequest>,
}

impl<Provider: CryptoProvider> Handshake<Provider> {
    pub fn new() -> Handshake<Provider> {
        Handshake {
            traffic_hash: None,
            secret_key: None,
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
        handshake: &mut Handshake<Provider>,
        record_reader: &mut RecordReader<'_>,
        tx_buf: &mut WriteBuffer<'_>,
        key_schedule: &mut KeySchedule<Provider>,
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

                let result = process_server_hello(handshake, key_schedule, crypto_provider, record);

                handle_processing_error(result, transport, key_schedule, tx_buf, crypto_provider)
                    .await
            }
            State::ServerVerify => {
                let record = record_reader
                    .read(transport, key_schedule.read_state())
                    .await?;

                let result =
                    process_server_verify(handshake, key_schedule, crypto_provider, record);

                handle_processing_error(result, transport, key_schedule, tx_buf, crypto_provider)
                    .await
            }
            State::ClientCert => {
                let (state, tx) = client_cert(handshake, key_schedule, crypto_provider, tx_buf)?;

                respond(tx, transport, key_schedule).await?;

                Ok(state)
            }
            State::ClientCertVerify => {
                let (result, tx) = client_cert_verify(key_schedule, crypto_provider, tx_buf)?;

                respond(tx, transport, key_schedule).await?;

                result
            }
            State::ClientFinished => {
                let tx = client_finished(key_schedule, tx_buf)?;

                respond(tx, transport, key_schedule).await?;

                client_finished_finalize(key_schedule, handshake, crypto_provider)
            }
            State::ApplicationData => Ok(State::ApplicationData),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn process_blocking<'v, Transport, Provider>(
        self,
        transport: &mut Transport,
        handshake: &mut Handshake<Provider>,
        record_reader: &mut RecordReader<'_>,
        tx_buf: &mut WriteBuffer,
        key_schedule: &mut KeySchedule<Provider>,
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

                let result = process_server_hello(handshake, key_schedule, crypto_provider, record);

                handle_processing_error_blocking(
                    result,
                    transport,
                    key_schedule,
                    tx_buf,
                    crypto_provider,
                )
            }
            State::ServerVerify => {
                let record = record_reader.read_blocking(transport, key_schedule.read_state())?;

                let result =
                    process_server_verify(handshake, key_schedule, crypto_provider, record);

                handle_processing_error_blocking(
                    result,
                    transport,
                    key_schedule,
                    tx_buf,
                    crypto_provider,
                )
            }
            State::ClientCert => {
                let (state, tx) = client_cert(handshake, key_schedule, crypto_provider, tx_buf)?;

                respond_blocking(tx, transport, key_schedule)?;

                Ok(state)
            }
            State::ClientCertVerify => {
                let (result, tx) = client_cert_verify(key_schedule, crypto_provider, tx_buf)?;

                respond_blocking(tx, transport, key_schedule)?;

                result
            }
            State::ClientFinished => {
                let tx = client_finished(key_schedule, tx_buf)?;

                respond_blocking(tx, transport, key_schedule)?;

                client_finished_finalize(key_schedule, handshake, crypto_provider)
            }
            State::ApplicationData => Ok(State::ApplicationData),
        }
    }
}

fn handle_processing_error_blocking<Provider>(
    result: Result<State, TlsError>,
    transport: &mut impl BlockingWrite,
    key_schedule: &mut KeySchedule<Provider>,
    tx_buf: &mut WriteBuffer,
    _provider: &mut Provider,
) -> Result<State, TlsError>
where
    Provider: CryptoProvider,
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

fn respond_blocking<Provider>(
    tx: &[u8],
    transport: &mut impl BlockingWrite,
    key_schedule: &mut KeySchedule<Provider>,
) -> Result<(), TlsError>
where
    Provider: CryptoProvider,
{
    transport
        .write_all(tx)
        .map_err(|e| TlsError::Io(e.kind()))?;

    key_schedule.write_state().increment_counter();

    transport.flush().map_err(|e| TlsError::Io(e.kind()))?;

    Ok(())
}

async fn handle_processing_error<Provider>(
    result: Result<State, TlsError>,
    transport: &mut impl AsyncWrite,
    key_schedule: &mut KeySchedule<Provider>,
    tx_buf: &mut WriteBuffer<'_>,
    _provider: &mut Provider,
) -> Result<State, TlsError>
where
    Provider: CryptoProvider,
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

async fn respond<Provider>(
    tx: &[u8],
    transport: &mut impl AsyncWrite,
    key_schedule: &mut KeySchedule<Provider>,
) -> Result<(), TlsError>
where
    Provider: CryptoProvider,
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
    key_schedule: &mut KeySchedule<Provider>,
    config: &TlsConfig,
    crypto_provider: &mut Provider,
    tx_buf: &'r mut WriteBuffer,
    handshake: &mut Handshake<Provider>,
) -> Result<(State, &'r [u8]), TlsError>
where
    Provider: CryptoProvider,
{
    key_schedule.initialize_early_secret(config.psk.as_ref().map(|p| p.0))?;
    let (write_key_schedule, read_key_schedule) = key_schedule.as_split();
    let client_hello = ClientRecord::client_hello(config, crypto_provider);
    let slice = tx_buf.write_record(&client_hello, write_key_schedule, Some(read_key_schedule))?;

    if let ClientRecord::Handshake(ClientHandshake::ClientHello(client_hello), _) = client_hello {
        handshake.secret_key.replace(client_hello.secret_key);
        Ok((State::ServerHello, slice))
    } else {
        Err(TlsError::EncodeError)
    }
}

fn process_server_hello<Provider>(
    handshake: &mut Handshake<Provider>,
    key_schedule: &mut KeySchedule<Provider>,
    provider: &mut Provider,
    record: ServerRecord<'_, Provider>,
) -> Result<State, TlsError>
where
    Provider: CryptoProvider,
{
    match record {
        ServerRecord::Handshake(server_handshake) => match server_handshake {
            ServerHandshake::ServerHello(server_hello) => {
                trace!("********* ServerHello");
                let secret_key = handshake
                    .secret_key
                    .take()
                    .ok_or(TlsError::InvalidHandshake)?;
                let (group, server_public) = server_hello
                    .server_public_key()
                    .ok_or(TlsError::InvalidKeyShare)?;

                let shared_len = match group {
                    NamedGroup::Secp256r1 => 32,
                    NamedGroup::Secp384r1 => 48,
                    _ => return Err(TlsError::InvalidKeyShare),
                };
                let mut shared = [0u8; 48];
                provider.ecdh(
                    group,
                    &secret_key,
                    &server_public[1..],
                    &mut shared[..shared_len],
                )?;

                key_schedule.initialize_handshake_secret(&shared[..shared_len], provider)?;
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
    handshake: &mut Handshake<Provider>,
    key_schedule: &mut KeySchedule<Provider>,
    crypto_provider: &mut Provider,
    record: ServerRecord<'_, Provider>,
) -> Result<State, TlsError>
where
    Provider: CryptoProvider,
{
    let mut state = State::ServerVerify;
    decrypt_record(key_schedule.read_state(), record, |key_schedule, record| {
        match record {
            ServerRecord::Handshake(server_handshake) => match server_handshake {
                ServerHandshake::EncryptedExtensions(_) => {}
                ServerHandshake::Certificate(certificate) => {
                    let transcript = key_schedule.transcript_hash();
                    if let Ok(verifier) = crypto_provider.verifier() {
                        verifier.verify_certificate(transcript, certificate)?;
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
            },
            ServerRecord::ChangeCipherSpec(_) => {}
            _ => return Err(TlsError::InvalidRecord),
        }

        Ok(())
    })?;
    Ok(state)
}

fn client_cert<'r, Provider>(
    handshake: &mut Handshake<Provider>,
    key_schedule: &mut KeySchedule<Provider>,
    crypto_provider: &mut Provider,
    buffer: &'r mut WriteBuffer,
) -> Result<(State, &'r [u8]), TlsError>
where
    Provider: CryptoProvider,
{
    handshake
        .traffic_hash
        .replace(key_schedule.transcript_hash().clone());

    let request_context = &handshake
        .certificate_request
        .as_ref()
        .ok_or(TlsError::InvalidHandshake)?
        .request_context;

    // Declare cert before certificate so owned data outlives the CertificateRef that borrows it
    let cert = crypto_provider.client_cert();
    let mut certificate = CertificateRef::with_context(request_context);
    let next_state = if let Some(ref cert) = cert {
        certificate.add(cert.into())?;
        State::ClientCertVerify
    } else {
        State::ClientFinished
    };
    let (write_key_schedule, read_key_schedule) = key_schedule.as_split();

    buffer
        .write_record(
            &ClientRecord::Handshake(ClientHandshake::ClientCertificate(certificate), true),
            write_key_schedule,
            Some(read_key_schedule),
        )
        .map(|slice| (next_state, slice))
}

fn client_cert_verify<'r, Provider>(
    key_schedule: &mut KeySchedule<Provider>,
    crypto_provider: &mut Provider,
    buffer: &'r mut WriteBuffer,
) -> Result<(Result<State, TlsError>, &'r [u8]), TlsError>
where
    Provider: CryptoProvider,
{
    let (result, record) = match crypto_provider.signer() {
        Ok((mut signing_key, signature_scheme)) => {
            let ctx_str = b"TLS 1.3, client CertificateVerify\x00";

            let mut msg: heapless::Vec<u8, 146> = heapless::Vec::new();
            msg.resize(64, 0x20).map_err(|_| TlsError::EncodeError)?;
            msg.extend_from_slice(ctx_str)
                .map_err(|_| TlsError::EncodeError)?;

            let mut transcript_hash = generic_array::GenericArray::default();
            key_schedule
                .transcript_hash()
                .clone()
                .finalize_into(&mut transcript_hash);
            msg.extend_from_slice(&transcript_hash)
                .map_err(|_| TlsError::EncodeError)?;

            let signature = signing_key.sign(&msg);

            trace!(
                "Signature: {:?} ({})",
                signature.as_ref(),
                signature.as_ref().len()
            );

            let certificate_verify = CertificateVerify {
                signature_scheme,
                signature: heapless::Vec::from_slice(signature.as_ref()).unwrap(),
            };

            (
                Ok(State::ClientFinished),
                ClientRecord::Handshake(
                    ClientHandshake::ClientCertificateVerify(certificate_verify),
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

fn client_finished<'r, Provider>(
    key_schedule: &mut KeySchedule<Provider>,
    buffer: &'r mut WriteBuffer,
) -> Result<&'r [u8], TlsError>
where
    Provider: CryptoProvider,
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

fn client_finished_finalize<Provider>(
    key_schedule: &mut KeySchedule<Provider>,
    handshake: &mut Handshake<Provider>,
    provider: &mut Provider,
) -> Result<State, TlsError>
where
    Provider: CryptoProvider,
{
    key_schedule.replace_transcript_hash(
        handshake
            .traffic_hash
            .take()
            .ok_or(TlsError::InvalidHandshake)?,
    );
    key_schedule.initialize_master_secret(provider)?;

    Ok(State::ApplicationData)
}
