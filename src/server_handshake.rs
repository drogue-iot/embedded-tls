//! Driver-agnostic server handshake logic.
//!
//! The async and blocking drivers in `asynch.rs` and `blocking.rs` differ only
//! in how they read from and write to the transport. Everything else — parsing
//! the ClientHello, deriving keys, encoding the server flight, and validating
//! the client's response — lives here, so it is written once and fixed once.
//!
//! This mirrors how the client handshake is already structured: thin per-driver
//! dispatch over shared logic (see `connection::State::process`).

use crate::TlsError;
use crate::alert::{AlertDescription, AlertLevel};
use crate::config::{CryptoProvider, TlsCipherSuite};
use crate::connection::decrypt_record;
use crate::crypto_ops::TlsHash;
use crate::extensions::extension_data::key_share::KeyShareEntry;
use crate::extensions::extension_data::supported_groups::NamedGroup;
use crate::handshake::ServerHandshake as ServerHandshakeMessage;
use crate::key_schedule::KeySchedule;
use crate::record::ServerRecord;
use crate::server::{
    OwnedAlpn, OwnedKeyShare, compute_ecdh, encode_certificate, encode_certificate_request,
    encode_certificate_verify, encode_encrypted_extensions, encode_finished,
    encode_hello_retry_request, encode_server_hello,
};
use crate::server_config::TlsServerConfig;
use crate::write_buffer::WriteBuffer;
use p256::elliptic_curve::rand_core::RngCore;
use signature::SignerMut;

/// A bare ChangeCipherSpec record, sent for middlebox compatibility
/// (RFC 8446 appendix D.4).
pub(crate) const CHANGE_CIPHER_SPEC: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

/// One record of the server flight, in the order they are sent.
#[derive(Clone, Copy)]
pub(crate) enum FlightRecord {
    EncryptedExtensions,
    CertificateRequest,
    Certificate,
    CertificateVerify,
    Finished,
}

const FLIGHT_WITH_CLIENT_AUTH: [FlightRecord; 5] = [
    FlightRecord::EncryptedExtensions,
    FlightRecord::CertificateRequest,
    FlightRecord::Certificate,
    FlightRecord::CertificateVerify,
    FlightRecord::Finished,
];

const FLIGHT: [FlightRecord; 4] = [
    FlightRecord::EncryptedExtensions,
    FlightRecord::Certificate,
    FlightRecord::CertificateVerify,
    FlightRecord::Finished,
];

/// Bytes ready for the transport, plus whether sending them advances the
/// write sequence counter. Only encrypted records do.
pub(crate) struct Outgoing<'b> {
    pub bytes: &'b [u8],
    pub encrypted: bool,
}

/// Server-side handshake state that outlives individual records.
///
/// The record buffer is reused between reads, so anything taken from a
/// ClientHello must be copied out before the next read.
pub(crate) struct ServerHandshake<'a, CipherSuite: TlsCipherSuite> {
    config: &'a TlsServerConfig<'a>,
    session_id: [u8; 32],
    session_id_len: usize,
    key_share: Option<OwnedKeyShare>,
    alpn: OwnedAlpn,
    did_hrr: bool,
    server_public_key: heapless::Vec<u8, 65>,
    shared_secret: heapless::Vec<u8, 32>,
    group: NamedGroup,
    selected_alpn: Option<usize>,
    traffic_hash: Option<CipherSuite::Hash>,
}

impl<'a, CipherSuite: TlsCipherSuite> ServerHandshake<'a, CipherSuite> {
    pub(crate) fn new(config: &'a TlsServerConfig<'a>) -> Self {
        Self {
            config,
            session_id: [0u8; 32],
            session_id_len: 0,
            key_share: None,
            alpn: OwnedAlpn::new(),
            did_hrr: false,
            server_public_key: heapless::Vec::new(),
            shared_secret: heapless::Vec::new(),
            group: NamedGroup::Secp256r1,
            selected_alpn: None,
            traffic_hash: None,
        }
    }

    pub(crate) fn did_hrr(&self) -> bool {
        self.did_hrr
    }

    pub(crate) fn needs_hello_retry(&self) -> bool {
        self.key_share.is_none()
    }

    pub(crate) fn flight(&self) -> &'static [FlightRecord] {
        if self.config.client_auth {
            &FLIGHT_WITH_CLIENT_AUTH
        } else {
            &FLIGHT
        }
    }

    /// Copy everything the server needs out of the ClientHello before the
    /// record buffer is reused.
    pub(crate) fn absorb_client_hello(
        &mut self,
        record: &ServerRecord<'_, CipherSuite>,
    ) -> Result<(), TlsError> {
        #[cfg(feature = "defmt")]
        defmt::info!("TLS server: step 1 — reading ClientHello");

        let ServerRecord::Handshake(ServerHandshakeMessage::ClientHello(ch)) = record else {
            return Err(TlsError::InvalidHandshake);
        };

        self.session_id_len = ch.session_id.len().min(32);
        self.session_id[..self.session_id_len]
            .copy_from_slice(&ch.session_id[..self.session_id_len]);

        for proto in &ch.alpn_protocols {
            if self.alpn.count < 4 {
                let plen = proto.len().min(32);
                self.alpn.data[self.alpn.count][..plen].copy_from_slice(&proto[..plen]);
                self.alpn.lens[self.alpn.count] = plen;
                self.alpn.count += 1;
            }
        }

        // Prefer X25519, then P-256.
        #[cfg(feature = "x25519")]
        {
            self.key_share = take_key_share(ch, NamedGroup::X25519);
        }
        if self.key_share.is_none() {
            self.key_share = take_key_share(ch, NamedGroup::Secp256r1);
        }

        #[cfg(feature = "defmt")]
        defmt::info!(
            "TLS server: step 2 — key_share found={}",
            self.key_share.is_some()
        );

        Ok(())
    }

    /// Encode a HelloRetryRequest asking the client to retry with P-256.
    pub(crate) fn encode_hello_retry_request<'b>(
        &mut self,
        key_schedule: &mut KeySchedule<CipherSuite>,
        tx_buf: &'b mut WriteBuffer<'_>,
    ) -> Result<Outgoing<'b>, TlsError> {
        key_schedule.replace_transcript_with_message_hash()?;
        self.did_hrr = true;

        let session_id = &self.session_id[..self.session_id_len];
        let (wks, rks) = key_schedule.as_split();
        let bytes = tx_buf.write_handshake_record(false, wks, rks.transcript_hash(), |buf| {
            encode_hello_retry_request(
                buf,
                session_id,
                CipherSuite::CODE_POINT,
                NamedGroup::Secp256r1,
            )
        })?;

        Ok(Outgoing {
            bytes,
            encrypted: false,
        })
    }

    /// Handle a record received after a HelloRetryRequest. Returns true once a
    /// usable ClientHello has been absorbed.
    pub(crate) fn absorb_hello_retry_response(
        &mut self,
        record: &ServerRecord<'_, CipherSuite>,
    ) -> Result<bool, TlsError> {
        match record {
            ServerRecord::ChangeCipherSpec(_) => Ok(false),
            ServerRecord::Handshake(ServerHandshakeMessage::ClientHello(ch)) => {
                self.key_share = take_key_share(ch, NamedGroup::Secp256r1);
                if self.key_share.is_none() {
                    return Err(TlsError::InvalidKeyShare);
                }
                Ok(true)
            }
            _ => Err(TlsError::InvalidHandshake),
        }
    }

    /// Perform the key exchange and initialise the early secret.
    pub(crate) fn compute_keys<Provider>(
        &mut self,
        crypto_provider: &mut Provider,
        key_schedule: &mut KeySchedule<CipherSuite>,
    ) -> Result<(), TlsError>
    where
        Provider: CryptoProvider<CipherSuite = CipherSuite>,
    {
        #[cfg(feature = "defmt")]
        defmt::info!("TLS server: step 3 — computing ECDH");

        let key_share = self.key_share.as_ref().ok_or(TlsError::InvalidKeyShare)?;
        let entry = KeyShareEntry {
            group: key_share.group,
            opaque: &key_share.bytes[..key_share.len],
        };
        let (public_key, shared_secret, group) = compute_ecdh(&entry, &mut crypto_provider.rng())?;

        self.server_public_key = public_key;
        self.shared_secret = shared_secret;
        self.group = group;

        key_schedule.initialize_early_secret(None)
    }

    /// Encode the ServerHello. Sent unencrypted, so it does not advance the
    /// write sequence counter.
    pub(crate) fn encode_server_hello<'b, Provider>(
        &mut self,
        crypto_provider: &mut Provider,
        key_schedule: &mut KeySchedule<CipherSuite>,
        tx_buf: &'b mut WriteBuffer<'_>,
    ) -> Result<Outgoing<'b>, TlsError>
    where
        Provider: CryptoProvider<CipherSuite = CipherSuite>,
    {
        #[cfg(feature = "defmt")]
        defmt::info!("TLS server: step 4 — sending ServerHello");

        let mut server_random = [0u8; 32];
        crypto_provider.rng().fill_bytes(&mut server_random);

        let session_id = &self.session_id[..self.session_id_len];
        let public_key = &self.server_public_key;
        let group = self.group;

        let (wks, rks) = key_schedule.as_split();
        let bytes = tx_buf.write_handshake_record(false, wks, rks.transcript_hash(), |buf| {
            encode_server_hello(
                buf,
                &server_random,
                session_id,
                CipherSuite::CODE_POINT,
                public_key,
                group,
            )
        })?;

        Ok(Outgoing {
            bytes,
            encrypted: false,
        })
    }

    pub(crate) fn init_handshake_secret(
        &mut self,
        key_schedule: &mut KeySchedule<CipherSuite>,
    ) -> Result<(), TlsError> {
        key_schedule.initialize_handshake_secret_server(&self.shared_secret)
    }

    /// Pick the first server protocol the client also offered.
    pub(crate) fn negotiate_alpn(&mut self) {
        let Some(server_protocols) = self.config.alpn_protocols else {
            return;
        };
        for server_protocol in server_protocols {
            for i in 0..self.alpn.count {
                if *server_protocol == &self.alpn.data[i][..self.alpn.lens[i]] {
                    self.selected_alpn = Some(i);
                    return;
                }
            }
        }
    }

    /// Encode one record of the server flight. All are encrypted, so all
    /// advance the write sequence counter.
    pub(crate) fn encode_flight_record<'b, Provider>(
        &mut self,
        which: FlightRecord,
        crypto_provider: &mut Provider,
        key_schedule: &mut KeySchedule<CipherSuite>,
        tx_buf: &'b mut WriteBuffer<'_>,
    ) -> Result<Outgoing<'b>, TlsError>
    where
        Provider: CryptoProvider<CipherSuite = CipherSuite>,
    {
        let bytes = match which {
            FlightRecord::EncryptedExtensions => {
                let alpn: Option<&[u8]> = self
                    .selected_alpn
                    .map(|i| &self.alpn.data[i][..self.alpn.lens[i]] as &[u8]);
                let (wks, rks) = key_schedule.as_split();
                tx_buf.write_handshake_record(true, wks, rks.transcript_hash(), |buf| {
                    encode_encrypted_extensions(buf, alpn)
                })?
            }
            FlightRecord::CertificateRequest => {
                let (wks, rks) = key_schedule.as_split();
                tx_buf.write_handshake_record(
                    true,
                    wks,
                    rks.transcript_hash(),
                    encode_certificate_request,
                )?
            }
            FlightRecord::Certificate => {
                let cert_chain = self.config.cert_chain;
                let (wks, rks) = key_schedule.as_split();
                tx_buf.write_handshake_record(true, wks, rks.transcript_hash(), |buf| {
                    encode_certificate(buf, cert_chain)
                })?
            }
            FlightRecord::CertificateVerify => {
                let transcript_hash = key_schedule.transcript_hash().clone().finalize();
                let (mut signing_key, signature_scheme) = crypto_provider
                    .signer()
                    .map_err(|_| TlsError::InvalidPrivateKey)?;

                let ctx_str = b"TLS 1.3, server CertificateVerify\x00";
                let mut msg: heapless::Vec<u8, 146> = heapless::Vec::new();
                msg.resize(64, 0x20).map_err(|_| TlsError::EncodeError)?;
                msg.extend_from_slice(ctx_str)
                    .map_err(|_| TlsError::EncodeError)?;
                msg.extend_from_slice(&transcript_hash)
                    .map_err(|_| TlsError::EncodeError)?;

                let signature = signing_key.sign(&msg);
                let signature_bytes = signature.as_ref();

                let (wks, rks) = key_schedule.as_split();
                tx_buf.write_handshake_record(true, wks, rks.transcript_hash(), |buf| {
                    encode_certificate_verify(buf, signature_scheme.as_u16(), signature_bytes)
                })?
            }
            FlightRecord::Finished => {
                let finished = key_schedule.create_client_finished()?;
                let verify_data: heapless::Vec<u8, 64> =
                    heapless::Vec::from_slice(&finished.verify)
                        .map_err(|_| TlsError::EncodeError)?;
                let (wks, rks) = key_schedule.as_split();
                tx_buf.write_handshake_record(true, wks, rks.transcript_hash(), |buf| {
                    encode_finished(buf, &verify_data)
                })?
            }
        };

        Ok(Outgoing {
            bytes,
            encrypted: true,
        })
    }

    /// Capture the transcript at the end of the server flight; the application
    /// traffic secrets are derived from it, not from the post-client-Finished
    /// transcript.
    pub(crate) fn capture_traffic_hash(&mut self, key_schedule: &mut KeySchedule<CipherSuite>) {
        self.traffic_hash = Some(key_schedule.transcript_hash().clone());
    }

    /// Process one record of the client's response. Returns true once the
    /// client's Finished has been verified.
    pub(crate) fn process_client_record(
        &mut self,
        key_schedule: &mut KeySchedule<CipherSuite>,
        record: ServerRecord<'_, CipherSuite>,
    ) -> Result<bool, TlsError> {
        if let ServerRecord::ChangeCipherSpec(_) = &record {
            return Ok(false);
        }

        let mut finished_ok = false;
        decrypt_record(
            key_schedule.read_state(),
            record,
            |key_schedule, record| match record {
                ServerRecord::Handshake(ServerHandshakeMessage::Finished(finished)) => {
                    if !key_schedule.verify_server_finished(&finished)? {
                        warn!("Client Finished verification failed");
                        return Err(TlsError::InvalidSignature);
                    }
                    finished_ok = true;
                    Ok(())
                }
                ServerRecord::Handshake(ServerHandshakeMessage::Certificate(_)) => Ok(()),
                ServerRecord::Handshake(ServerHandshakeMessage::CertificateVerify(_)) => Ok(()),
                ServerRecord::ChangeCipherSpec(_) => Ok(()),
                _ => Err(TlsError::InvalidHandshake),
            },
        )?;

        Ok(finished_ok)
    }

    pub(crate) fn finalize(
        &mut self,
        key_schedule: &mut KeySchedule<CipherSuite>,
    ) -> Result<(), TlsError> {
        let traffic_hash = self.traffic_hash.take().ok_or(TlsError::InternalError)?;
        key_schedule.replace_transcript_hash(traffic_hash);
        key_schedule.initialize_master_secret_server()
    }
}

/// Copy the first key share for `group` out of the ClientHello.
fn take_key_share(
    client_hello: &crate::handshake::client_hello::ParsedClientHello<'_>,
    group: NamedGroup,
) -> Option<OwnedKeyShare> {
    for share in &client_hello.key_shares {
        if share.group == group {
            let len = share.opaque.len().min(65);
            let mut key_share = OwnedKeyShare {
                group,
                bytes: [0u8; 65],
                len,
            };
            key_share.bytes[..len].copy_from_slice(&share.opaque[..len]);
            return Some(key_share);
        }
    }
    None
}

/// Map a handshake failure onto the alert the peer should be told about.
///
/// Returns `None` for transport failures: the connection is already gone, so
/// there is nothing left to send an alert down.
pub(crate) fn alert_for(error: &TlsError) -> Option<(AlertLevel, AlertDescription)> {
    match error {
        TlsError::Io(_) | TlsError::ConnectionClosed => None,
        TlsError::AbortHandshake(level, description) => Some((*level, *description)),
        TlsError::InvalidSupportedVersions => {
            Some((AlertLevel::Fatal, AlertDescription::ProtocolVersion))
        }
        TlsError::InvalidCertificate | TlsError::InvalidCertificateEntry => {
            Some((AlertLevel::Fatal, AlertDescription::BadCertificate))
        }
        TlsError::InvalidSignature => Some((AlertLevel::Fatal, AlertDescription::DecryptError)),
        TlsError::DecodeError | TlsError::ParseError(_) => {
            Some((AlertLevel::Fatal, AlertDescription::DecodeError))
        }
        TlsError::InvalidKeyShare | TlsError::InvalidHandshake => {
            Some((AlertLevel::Fatal, AlertDescription::IllegalParameter))
        }
        _ => Some((AlertLevel::Fatal, AlertDescription::HandshakeFailure)),
    }
}
