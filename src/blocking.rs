use core::sync::atomic::Ordering;

use crate::common::decrypted_buffer_info::DecryptedBufferInfo;
use crate::common::decrypted_read_handler::DecryptedReadHandler;
use crate::connection::{Handshake, State, decrypt_record};
#[cfg(feature = "server")]
use crate::extensions::extension_data::supported_groups::NamedGroup;
use crate::flush_policy::FlushPolicy;
use crate::key_schedule::KeySchedule;
use crate::key_schedule::{ReadKeySchedule, WriteKeySchedule};
use crate::read_buffer::ReadBuffer;
#[cfg(feature = "server")]
use crate::record::ServerRecord;
use crate::record::{ClientRecord, ClientRecordHeader};
use crate::record_reader::{RecordReader, RecordReaderBorrowMut};
use crate::write_buffer::{WriteBuffer, WriteBufferBorrowMut};
use embedded_io::Error as _;
use embedded_io::{BufRead, ErrorType, Read, Write};
use portable_atomic::AtomicBool;

pub use crate::TlsError;
pub use crate::config::*;

/// Type representing a TLS connection. An instance of this type can
/// be used to establish a TLS connection, write and read encrypted data over this connection,
/// and closing to free up the underlying resources.
pub struct TlsConnection<'a, Socket, CipherSuite>
where
    Socket: Read + Write + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    delegate: Socket,
    opened: AtomicBool,
    key_schedule: KeySchedule<CipherSuite>,
    record_reader: RecordReader<'a>,
    record_write_buf: WriteBuffer<'a>,
    decrypted: DecryptedBufferInfo,
    flush_policy: FlushPolicy,
}

impl<'a, Socket, CipherSuite> TlsConnection<'a, Socket, CipherSuite>
where
    Socket: Read + Write + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    fn is_opened(&mut self) -> bool {
        *self.opened.get_mut()
    }

    /// Create a new TLS connection with the provided context and a blocking I/O implementation
    ///
    /// NOTE: The record read buffer should be sized to fit an encrypted TLS record. The size of this record
    /// depends on the server configuration, but the maximum allowed value for a TLS record is 16640 bytes,
    /// which should be a safe value to use.
    ///
    /// The write record buffer can be smaller than the read buffer. During writes [`TLS_RECORD_OVERHEAD`] bytes of
    /// overhead is added per record, so the buffer must at least be this large. Large writes are split into multiple
    /// records if depending on the size of the write buffer.
    /// The largest of the two buffers will be used to encode the TLS handshake record, hence either of the
    /// buffers must at least be large enough to encode a handshake.
    pub fn new(
        delegate: Socket,
        record_read_buf: &'a mut [u8],
        record_write_buf: &'a mut [u8],
    ) -> Self {
        Self {
            delegate,
            opened: AtomicBool::new(false),
            key_schedule: KeySchedule::new(),
            record_reader: RecordReader::new(record_read_buf),
            record_write_buf: WriteBuffer::new(record_write_buf),
            decrypted: DecryptedBufferInfo::default(),
            flush_policy: FlushPolicy::default(),
        }
    }

    /// Returns a reference to the current flush policy.
    ///
    /// The flush policy controls whether the underlying transport is flushed
    /// (via its `flush()` method) after writing a TLS record.
    #[inline]
    pub fn flush_policy(&self) -> FlushPolicy {
        self.flush_policy
    }

    /// Replace the current flush policy with the provided one.
    ///
    /// This sets how and when the connection will call `flush()` on the
    /// underlying transport after writing records.
    #[inline]
    pub fn set_flush_policy(&mut self, policy: FlushPolicy) {
        self.flush_policy = policy;
    }

    /// Open a TLS connection, performing the handshake with the configuration provided when
    /// creating the connection instance.
    ///
    /// Returns an error if the handshake does not proceed. If an error occurs, the connection
    /// instance must be recreated.
    pub fn open<Provider>(&mut self, mut context: TlsContext<Provider>) -> Result<(), TlsError>
    where
        Provider: CryptoProvider<CipherSuite = CipherSuite>,
    {
        let mut handshake: Handshake<CipherSuite> = Handshake::new();
        if let (Ok(verifier), Some(server_name)) = (
            context.crypto_provider.verifier(),
            context.config.server_name,
        ) {
            verifier.set_hostname_verification(server_name)?;
        }
        let mut state = State::ClientHello;

        while state != State::ApplicationData {
            let next_state = state.process_blocking(
                &mut self.delegate,
                &mut handshake,
                &mut self.record_reader,
                &mut self.record_write_buf,
                &mut self.key_schedule,
                context.config,
                &mut context.crypto_provider,
            )?;
            trace!("State {:?} -> {:?}", state, next_state);
            state = next_state;
        }
        *self.opened.get_mut() = true;

        Ok(())
    }

    /// Open a TLS server connection, performing the server-side handshake.
    #[cfg(feature = "server")]
    #[allow(
        clippy::too_many_lines,
        clippy::needless_continue,
        clippy::match_same_arms
    )]
    pub fn open_server<Provider>(
        &mut self,
        context: crate::server_config::TlsServerContext<'_, Provider>,
    ) -> Result<(), TlsError>
    where
        Provider: CryptoProvider<CipherSuite = CipherSuite>,
    {
        use crate::connection::decrypt_record;
        use crate::extensions::extension_data::key_share::KeyShareEntry;
        use crate::handshake::ServerHandshake;
        use crate::server::{
            OwnedAlpn, OwnedKeyShare, compute_ecdh, encode_certificate, encode_certificate_request,
            encode_certificate_verify, encode_encrypted_extensions, encode_finished,
            encode_hello_retry_request, encode_server_hello,
        };
        use p256::elliptic_curve::rand_core::RngCore;
        use signature::SignerMut;

        let crate::server_config::TlsServerContext {
            config: server_config,
            mut crypto_provider,
        } = context;

        // === Step 1: Read ClientHello, extract session_id, ALPN, find best key share ===
        let mut session_id_buf = [0u8; 32];
        let session_id_len: usize;
        let mut owned_key_share: Option<OwnedKeyShare> = None;
        let mut owned_alpn = OwnedAlpn::new();
        let mut did_hrr = false;

        {
            let record = self
                .record_reader
                .read_blocking(&mut self.delegate, self.key_schedule.read_state())?;

            match record {
                ServerRecord::Handshake(ServerHandshake::ClientHello(ref ch)) => {
                    // Copy session_id
                    session_id_len = ch.session_id.len().min(32);
                    session_id_buf[..session_id_len]
                        .copy_from_slice(&ch.session_id[..session_id_len]);

                    // Copy ALPN protocols
                    for proto in &ch.alpn_protocols {
                        if owned_alpn.count < 4 {
                            let plen = proto.len().min(32);
                            owned_alpn.data[owned_alpn.count][..plen]
                                .copy_from_slice(&proto[..plen]);
                            owned_alpn.lens[owned_alpn.count] = plen;
                            owned_alpn.count += 1;
                        }
                    }

                    // Find best key share: prefer X25519, then P-256
                    #[cfg(feature = "x25519")]
                    {
                        for share in &ch.key_shares {
                            if share.group == NamedGroup::X25519 {
                                let mut ks = OwnedKeyShare {
                                    group: NamedGroup::X25519,
                                    bytes: [0u8; 65],
                                    len: share.opaque.len().min(65),
                                };
                                ks.bytes[..ks.len].copy_from_slice(&share.opaque[..ks.len]);
                                owned_key_share = Some(ks);
                                break;
                            }
                        }
                    }
                    if owned_key_share.is_none() {
                        for share in &ch.key_shares {
                            if share.group == NamedGroup::Secp256r1 {
                                let mut ks = OwnedKeyShare {
                                    group: NamedGroup::Secp256r1,
                                    bytes: [0u8; 65],
                                    len: share.opaque.len().min(65),
                                };
                                ks.bytes[..ks.len].copy_from_slice(&share.opaque[..ks.len]);
                                owned_key_share = Some(ks);
                                break;
                            }
                        }
                    }
                }
                _ => return Err(TlsError::InvalidHandshake),
            }
        }

        // === Step 2: HRR if no supported key share found ===
        if owned_key_share.is_none() {
            // Replace transcript with message_hash construct
            self.key_schedule.replace_transcript_with_message_hash()?;

            // Send HelloRetryRequest requesting P-256
            {
                let (wks, rks) = self.key_schedule.as_split();
                let sid = &session_id_buf[..session_id_len];
                let slice = self.record_write_buf.write_handshake_record(
                    false,
                    wks,
                    rks.transcript_hash(),
                    |buf| {
                        encode_hello_retry_request(
                            buf,
                            sid,
                            CipherSuite::CODE_POINT,
                            NamedGroup::Secp256r1,
                        )
                    },
                )?;
                self.delegate
                    .write_all(slice)
                    .map_err(|e| TlsError::Io(e.kind()))?;
            }

            // Send CCS
            {
                let ccs = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
                self.delegate
                    .write_all(&ccs)
                    .map_err(|e| TlsError::Io(e.kind()))?;
                self.delegate.flush().map_err(|e| TlsError::Io(e.kind()))?;
            }
            did_hrr = true;

            // Read CH2 (may get CCS first)
            loop {
                let record = self
                    .record_reader
                    .read_blocking(&mut self.delegate, self.key_schedule.read_state())?;

                match record {
                    ServerRecord::ChangeCipherSpec(_) => continue,
                    ServerRecord::Handshake(ServerHandshake::ClientHello(ref ch)) => {
                        // Find P-256 key share in retry
                        for share in &ch.key_shares {
                            if share.group == NamedGroup::Secp256r1 {
                                let mut ks = OwnedKeyShare {
                                    group: NamedGroup::Secp256r1,
                                    bytes: [0u8; 65],
                                    len: share.opaque.len().min(65),
                                };
                                ks.bytes[..ks.len].copy_from_slice(&share.opaque[..ks.len]);
                                owned_key_share = Some(ks);
                                break;
                            }
                        }
                        if owned_key_share.is_none() {
                            return Err(TlsError::InvalidKeyShare);
                        }
                        break;
                    }
                    _ => return Err(TlsError::InvalidHandshake),
                }
            }
        }

        let key_share = owned_key_share.ok_or(TlsError::InvalidKeyShare)?;

        // === Step 3: ECDH via compute_ecdh() ===
        let ks_entry = KeyShareEntry {
            group: key_share.group,
            opaque: &key_share.bytes[..key_share.len],
        };
        let (server_pub_key, shared_secret, group) =
            compute_ecdh(&ks_entry, &mut crypto_provider.rng())?;

        // === Step 3b: Initialize early secret ===
        self.key_schedule.initialize_early_secret(None)?;

        // === Step 4: Send ServerHello (6-arg with NamedGroup) ===
        let mut server_random = [0u8; 32];
        crypto_provider.rng().fill_bytes(&mut server_random);
        {
            let (wks, rks) = self.key_schedule.as_split();
            let sid = &session_id_buf[..session_id_len];
            let slice = self.record_write_buf.write_handshake_record(
                false,
                wks,
                rks.transcript_hash(),
                |buf| {
                    encode_server_hello(
                        buf,
                        &server_random,
                        sid,
                        CipherSuite::CODE_POINT,
                        &server_pub_key,
                        group,
                    )
                },
            )?;
            self.delegate
                .write_all(slice)
                .map_err(|e| TlsError::Io(e.kind()))?;
            self.delegate.flush().map_err(|e| TlsError::Io(e.kind()))?;
        }

        // === Step 5: Initialize handshake secret (server mode) ===
        self.key_schedule
            .initialize_handshake_secret_server(&shared_secret)?;

        // === Step 6: Send CCS (if not already sent in HRR) ===
        if !did_hrr {
            let ccs = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
            self.delegate
                .write_all(&ccs)
                .map_err(|e| TlsError::Io(e.kind()))?;
        }

        // === Step 7: Negotiate ALPN ===
        let selected_alpn: Option<usize> = if let Some(server_protos) = server_config.alpn_protocols
        {
            let mut found = None;
            'outer: for sp in server_protos {
                for i in 0..owned_alpn.count {
                    let client_proto = &owned_alpn.data[i][..owned_alpn.lens[i]];
                    if *sp == client_proto {
                        found = Some(i);
                        break 'outer;
                    }
                }
            }
            found
        } else {
            None
        };

        // === Step 8: Send EncryptedExtensions with ALPN ===
        {
            let alpn_slice: Option<&[u8]> =
                selected_alpn.map(|i| &owned_alpn.data[i][..owned_alpn.lens[i]] as &[u8]);
            let (wks, rks) = self.key_schedule.as_split();
            let slice = self.record_write_buf.write_handshake_record(
                true,
                wks,
                rks.transcript_hash(),
                |buf| encode_encrypted_extensions(buf, alpn_slice),
            )?;
            self.delegate
                .write_all(slice)
                .map_err(|e| TlsError::Io(e.kind()))?;
            self.key_schedule.write_state().increment_counter();
        }

        // === Step 9: If client_auth, send CertificateRequest ===
        if server_config.client_auth {
            let (wks, rks) = self.key_schedule.as_split();
            let slice = self.record_write_buf.write_handshake_record(
                true,
                wks,
                rks.transcript_hash(),
                encode_certificate_request,
            )?;
            self.delegate
                .write_all(slice)
                .map_err(|e| TlsError::Io(e.kind()))?;
            self.key_schedule.write_state().increment_counter();
        }

        // === Step 10: Send Certificate (encrypted) ===
        {
            let (wks, rks) = self.key_schedule.as_split();
            let slice = self.record_write_buf.write_handshake_record(
                true,
                wks,
                rks.transcript_hash(),
                |buf| encode_certificate(buf, server_config.cert_chain),
            )?;
            self.delegate
                .write_all(slice)
                .map_err(|e| TlsError::Io(e.kind()))?;
            self.key_schedule.write_state().increment_counter();
        }

        // === Step 11: Send CertificateVerify (encrypted) ===
        {
            use crate::crypto_ops::TlsHash;
            let transcript_hash = self.key_schedule.transcript_hash().clone().finalize();
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
            let sig_bytes = signature.as_ref();

            let (wks, rks) = self.key_schedule.as_split();
            let slice = self.record_write_buf.write_handshake_record(
                true,
                wks,
                rks.transcript_hash(),
                |buf| encode_certificate_verify(buf, signature_scheme.as_u16(), sig_bytes),
            )?;
            self.delegate
                .write_all(slice)
                .map_err(|e| TlsError::Io(e.kind()))?;
            self.key_schedule.write_state().increment_counter();
        }

        // === Step 12: Send Finished (encrypted) ===
        {
            let finished = self.key_schedule.create_client_finished()?;
            let verify_data: heapless::Vec<u8, 64> =
                heapless::Vec::from_slice(&finished.verify).map_err(|_| TlsError::EncodeError)?;

            let (wks, rks) = self.key_schedule.as_split();
            let slice = self.record_write_buf.write_handshake_record(
                true,
                wks,
                rks.transcript_hash(),
                |buf| encode_finished(buf, &verify_data),
            )?;
            self.delegate
                .write_all(slice)
                .map_err(|e| TlsError::Io(e.kind()))?;
            self.key_schedule.write_state().increment_counter();
        }

        // === Step 13: Capture transcript for application secrets ===
        let traffic_hash = self.key_schedule.transcript_hash().clone();

        // === Step 14: Read client messages (CCS, Certificate, CertificateVerify, Finished) ===
        loop {
            let record = self
                .record_reader
                .read_blocking(&mut self.delegate, self.key_schedule.read_state())?;

            if let ServerRecord::ChangeCipherSpec(_) = &record {
                continue;
            }

            let mut finished_ok = false;
            decrypt_record(
                self.key_schedule.read_state(),
                record,
                |key_schedule, record| match record {
                    ServerRecord::Handshake(ServerHandshake::Finished(finished)) => {
                        if !key_schedule.verify_server_finished(&finished)? {
                            warn!("Client Finished verification failed");
                            return Err(TlsError::InvalidSignature);
                        }
                        finished_ok = true;
                        Ok(())
                    }
                    ServerRecord::Handshake(ServerHandshake::Certificate(_)) => Ok(()),
                    ServerRecord::Handshake(ServerHandshake::CertificateVerify(_)) => Ok(()),
                    ServerRecord::ChangeCipherSpec(_) => Ok(()),
                    _ => Err(TlsError::InvalidHandshake),
                },
            )?;

            if finished_ok {
                break;
            }
        }

        // === Step 15: Initialize master secret ===
        self.key_schedule.replace_transcript_hash(traffic_hash);
        self.key_schedule.initialize_master_secret_server()?;

        *self.opened.get_mut() = true;
        self.delegate.flush().map_err(|e| TlsError::Io(e.kind()))?;

        Ok(())
    }

    /// Encrypt and send the provided slice over the connection. The connection
    /// must be opened before writing.
    ///
    /// The slice may be buffered internally and not written to the connection immediately.
    /// In this case [`Self::flush()`] should be called to force the currently buffered writes
    /// to be written to the connection.
    ///
    /// Returns the number of bytes buffered/written.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        if self.is_opened() {
            if !self
                .record_write_buf
                .contains(ClientRecordHeader::ApplicationData)
            {
                self.flush()?;
                self.record_write_buf
                    .start_record(ClientRecordHeader::ApplicationData)?;
            }

            let buffered = self.record_write_buf.append(buf);

            if self.record_write_buf.is_full() {
                self.flush()?;
            }

            Ok(buffered)
        } else {
            Err(TlsError::MissingHandshake)
        }
    }

    /// Force all previously written, buffered bytes to be encoded into a tls record and written
    /// to the connection.
    pub fn flush(&mut self) -> Result<(), TlsError> {
        if !self.record_write_buf.is_empty() {
            let key_schedule = self.key_schedule.write_state();
            let slice = self.record_write_buf.close_record(key_schedule)?;

            self.delegate
                .write_all(slice)
                .map_err(|e| TlsError::Io(e.kind()))?;

            key_schedule.increment_counter();

            if self.flush_policy.flush_transport() {
                self.flush_transport()?;
            }
        }

        Ok(())
    }

    #[inline]
    fn flush_transport(&mut self) -> Result<(), TlsError> {
        self.delegate.flush().map_err(|e| TlsError::Io(e.kind()))
    }

    fn create_read_buffer(&mut self) -> ReadBuffer<'_> {
        self.decrypted.create_read_buffer(self.record_reader.buf)
    }

    /// Read and decrypt data filling the provided slice.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut buffer = self.read_buffered()?;

        let len = buffer.pop_into(buf);
        trace!("Copied {} bytes", len);

        Ok(len)
    }

    /// Reads buffered data. If nothing is in memory, it'll wait for a TLS record and process it.
    pub fn read_buffered(&mut self) -> Result<ReadBuffer<'_>, TlsError> {
        if self.is_opened() {
            while self.decrypted.is_empty() {
                self.read_application_data()?;
            }

            Ok(self.create_read_buffer())
        } else {
            Err(TlsError::MissingHandshake)
        }
    }

    fn read_application_data(&mut self) -> Result<(), TlsError> {
        let buf_ptr_range = self.record_reader.buf.as_ptr_range();
        let key_schedule = self.key_schedule.read_state();
        let record = self
            .record_reader
            .read_blocking(&mut self.delegate, key_schedule)?;

        let mut handler = DecryptedReadHandler {
            source_buffer: buf_ptr_range,
            buffer_info: &mut self.decrypted,
            is_open: self.opened.get_mut(),
        };
        decrypt_record(key_schedule, record, |_key_schedule, record| {
            handler.handle(record)
        })?;

        Ok(())
    }

    fn close_internal(&mut self) -> Result<(), TlsError> {
        self.flush()?;

        let is_opened = self.is_opened();
        let (write_key_schedule, read_key_schedule) = self.key_schedule.as_split();
        let slice = self.record_write_buf.write_record(
            &ClientRecord::close_notify(is_opened),
            write_key_schedule,
            Some(read_key_schedule),
        )?;

        self.delegate
            .write_all(slice)
            .map_err(|e| TlsError::Io(e.kind()))?;

        self.key_schedule.write_state().increment_counter();

        self.flush_transport()?;

        Ok(())
    }

    /// Close a connection instance, returning the ownership of the I/O provider.
    pub fn close(mut self) -> Result<Socket, (Socket, TlsError)> {
        match self.close_internal() {
            Ok(()) => Ok(self.delegate),
            Err(e) => Err((self.delegate, e)),
        }
    }

    pub fn split(
        &mut self,
    ) -> (
        TlsReader<'_, Socket, CipherSuite>,
        TlsWriter<'_, Socket, CipherSuite>,
    )
    where
        Socket: Clone,
    {
        let (wks, rks) = self.key_schedule.as_split();

        let reader = TlsReader {
            opened: &self.opened,
            delegate: self.delegate.clone(),
            key_schedule: rks,
            record_reader: self.record_reader.reborrow_mut(),
            decrypted: &mut self.decrypted,
        };
        let writer = TlsWriter {
            opened: &self.opened,
            delegate: self.delegate.clone(),
            key_schedule: wks,
            record_write_buf: self.record_write_buf.reborrow_mut(),
            flush_policy: self.flush_policy,
        };

        (reader, writer)
    }
}

impl<'a, Socket, CipherSuite> ErrorType for TlsConnection<'a, Socket, CipherSuite>
where
    Socket: Read + Write + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    type Error = TlsError;
}

impl<'a, Socket, CipherSuite> Read for TlsConnection<'a, Socket, CipherSuite>
where
    Socket: Read + Write + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        TlsConnection::read(self, buf)
    }
}

impl<'a, Socket, CipherSuite> BufRead for TlsConnection<'a, Socket, CipherSuite>
where
    Socket: Read + Write + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    fn fill_buf(&mut self) -> Result<&[u8], Self::Error> {
        self.read_buffered().map(|mut buf| buf.peek_all())
    }

    fn consume(&mut self, amt: usize) {
        self.create_read_buffer().pop(amt);
    }
}

impl<'a, Socket, CipherSuite> Write for TlsConnection<'a, Socket, CipherSuite>
where
    Socket: Read + Write + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        TlsConnection::write(self, buf)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        TlsConnection::flush(self)
    }
}

pub struct TlsReader<'a, Socket, CipherSuite>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    opened: &'a AtomicBool,
    delegate: Socket,
    key_schedule: &'a mut ReadKeySchedule<CipherSuite>,
    record_reader: RecordReaderBorrowMut<'a>,
    decrypted: &'a mut DecryptedBufferInfo,
}

impl<Socket, CipherSuite> AsRef<Socket> for TlsReader<'_, Socket, CipherSuite>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    fn as_ref(&self) -> &Socket {
        &self.delegate
    }
}

impl<'a, Socket, CipherSuite> TlsReader<'a, Socket, CipherSuite>
where
    Socket: Read + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    fn create_read_buffer(&mut self) -> ReadBuffer<'_> {
        self.decrypted.create_read_buffer(self.record_reader.buf)
    }

    /// Reads buffered data. If nothing is in memory, it'll wait for a TLS record and process it.
    pub fn read_buffered(&mut self) -> Result<ReadBuffer<'_>, TlsError> {
        if self.opened.load(Ordering::Acquire) {
            while self.decrypted.is_empty() {
                self.read_application_data()?;
            }

            Ok(self.create_read_buffer())
        } else {
            Err(TlsError::MissingHandshake)
        }
    }

    fn read_application_data(&mut self) -> Result<(), TlsError> {
        let buf_ptr_range = self.record_reader.buf.as_ptr_range();
        let record = self
            .record_reader
            .read_blocking(&mut self.delegate, self.key_schedule)?;

        let mut opened = self.opened.load(Ordering::Acquire);
        let mut handler = DecryptedReadHandler {
            source_buffer: buf_ptr_range,
            buffer_info: self.decrypted,
            is_open: &mut opened,
        };
        let result = decrypt_record(self.key_schedule, record, |_key_schedule, record| {
            handler.handle(record)
        });

        if !opened {
            self.opened.store(false, Ordering::Release);
        }
        result
    }
}

pub struct TlsWriter<'a, Socket, CipherSuite>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    opened: &'a AtomicBool,
    delegate: Socket,
    key_schedule: &'a mut WriteKeySchedule<CipherSuite>,
    record_write_buf: WriteBufferBorrowMut<'a>,
    flush_policy: FlushPolicy,
}

impl<'a, Socket, CipherSuite> TlsWriter<'a, Socket, CipherSuite>
where
    Socket: Write + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    fn flush_transport(&mut self) -> Result<(), TlsError> {
        self.delegate.flush().map_err(|e| TlsError::Io(e.kind()))
    }
}

impl<Socket, CipherSuite> AsRef<Socket> for TlsWriter<'_, Socket, CipherSuite>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    fn as_ref(&self) -> &Socket {
        &self.delegate
    }
}

impl<Socket, CipherSuite> ErrorType for TlsWriter<'_, Socket, CipherSuite>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    type Error = TlsError;
}

impl<Socket, CipherSuite> ErrorType for TlsReader<'_, Socket, CipherSuite>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    type Error = TlsError;
}

impl<'a, Socket, CipherSuite> Read for TlsReader<'a, Socket, CipherSuite>
where
    Socket: Read + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut buffer = self.read_buffered()?;

        let len = buffer.pop_into(buf);
        trace!("Copied {} bytes", len);

        Ok(len)
    }
}

impl<'a, Socket, CipherSuite> BufRead for TlsReader<'a, Socket, CipherSuite>
where
    Socket: Read + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    fn fill_buf(&mut self) -> Result<&[u8], Self::Error> {
        self.read_buffered().map(|mut buf| buf.peek_all())
    }

    fn consume(&mut self, amt: usize) {
        self.create_read_buffer().pop(amt);
    }
}

impl<'a, Socket, CipherSuite> Write for TlsWriter<'a, Socket, CipherSuite>
where
    Socket: Write + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        if self.opened.load(Ordering::Acquire) {
            if !self
                .record_write_buf
                .contains(ClientRecordHeader::ApplicationData)
            {
                self.flush()?;
                self.record_write_buf
                    .start_record(ClientRecordHeader::ApplicationData)?;
            }

            let buffered = self.record_write_buf.append(buf);

            if self.record_write_buf.is_full() {
                self.flush()?;
            }

            Ok(buffered)
        } else {
            Err(TlsError::MissingHandshake)
        }
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        if !self.record_write_buf.is_empty() {
            let slice = self.record_write_buf.close_record(self.key_schedule)?;

            self.delegate
                .write_all(slice)
                .map_err(|e| TlsError::Io(e.kind()))?;

            self.key_schedule.increment_counter();

            if self.flush_policy.flush_transport() {
                self.flush_transport()?;
            }
        }

        Ok(())
    }
}
