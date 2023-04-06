use core::ops::ControlFlow;

use crate::alert::*;
use crate::connection::*;
use crate::handshake::ServerHandshake;
use crate::key_schedule::KeySchedule;
use crate::read_buffer::ReadBuffer;
use crate::record::{ClientRecord, ServerRecord};
use crate::record_reader::RecordReader;
use crate::TlsError;
use embedded_io::Error as _;
use embedded_io::{
    asynch::{Read as AsyncRead, Write as AsyncWrite},
    Io,
};
use rand_core::{CryptoRng, RngCore};

pub use crate::config::*;

// Some space needed by TLS record
const TLS_RECORD_OVERHEAD: usize = 128;

/// Type representing an async TLS connection. An instance of this type can
/// be used to establish a TLS connection, write and read encrypted data over this connection,
/// and closing to free up the underlying resources.
pub struct TlsConnection<'a, Socket, CipherSuite>
where
    Socket: AsyncRead + AsyncWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    delegate: Socket,
    opened: bool,
    key_schedule: KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
    record_reader: RecordReader<'a, CipherSuite>,
    record_write_buf: &'a mut [u8],
    write_pos: usize,
    decrypted_offset: usize,
    decrypted_len: usize,
    decrypted_consumed: usize,
}

impl<'a, Socket, CipherSuite> TlsConnection<'a, Socket, CipherSuite>
where
    Socket: AsyncRead + AsyncWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    /// Create a new TLS connection with the provided context and a async I/O implementation
    ///
    /// NOTE: The record read buffer should be sized to fit an encrypted TLS record. The size of this record
    /// depends on the server configuration, but the maximum allowed value for a TLS record is 16 kB, which
    /// should be a safe value to use.
    ///
    /// The write record buffer can be smaller than the read buffer. During write [`TLS_RECORD_OVERHEAD`] over overhead
    /// is added per record, so the buffer must at least be this large. Large writes are split into multiple records if
    /// depending on the size of the write buffer.
    /// The largest of the two buffers will be used to encode the TLS handshake record, hence either of the
    /// buffers must at least be large enough to encode a handshake.
    pub fn new(
        delegate: Socket,
        record_read_buf: &'a mut [u8],
        record_write_buf: &'a mut [u8],
    ) -> Self {
        assert!(
            record_write_buf.len() > TLS_RECORD_OVERHEAD,
            "The write buffer must be sufficiently large to include the tls record overhead"
        );
        Self {
            delegate,
            opened: false,
            key_schedule: KeySchedule::new(),
            record_reader: RecordReader::new(record_read_buf),
            record_write_buf,
            write_pos: 0,
            decrypted_offset: 0,
            decrypted_len: 0,
            decrypted_consumed: 0,
        }
    }

    /// Open a TLS connection, performing the handshake with the configuration provided when creating
    /// the connection instance.
    ///
    /// The handshake may support certificates up to CERT_SIZE.
    ///
    /// Returns an error if the handshake does not proceed. If an error occurs, the connection instance
    /// must be recreated.
    pub async fn open<'m, RNG: CryptoRng + RngCore + 'm, Verifier: TlsVerifier<CipherSuite> + 'm>(
        &mut self,
        context: TlsContext<'m, CipherSuite, RNG>,
    ) -> Result<(), TlsError>
    where
        'a: 'm,
    {
        let mut handshake: Handshake<CipherSuite, Verifier> =
            Handshake::new(Verifier::new(context.config.server_name));
        let mut state = State::ClientHello;

        loop {
            let next_state = state
                .process(
                    &mut self.delegate,
                    &mut handshake,
                    &mut self.record_reader,
                    self.record_write_buf,
                    &mut self.key_schedule,
                    context.config,
                    context.rng,
                )
                .await?;
            trace!("State {:?} -> {:?}", state, next_state);
            state = next_state;
            if let State::ApplicationData = state {
                self.opened = true;
                break;
            }
        }

        Ok(())
    }

    /// Encrypt and send the provided slice over the connection. The connection
    /// must be opened before writing.
    ///
    /// The slice may be buffered internally and not written to the connection immediately.
    /// In this case [`flush()`] should be called to force the currently buffered writes
    /// to be written to the connection.
    ///
    /// Returns the number of bytes buffered/written.
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        if self.opened {
            let max_block_size = self.record_write_buf.len() - TLS_RECORD_OVERHEAD;
            let buffered = usize::min(buf.len(), max_block_size - self.write_pos);
            if buffered > 0 {
                self.record_write_buf[self.write_pos..self.write_pos + buffered]
                    .copy_from_slice(&buf[..buffered]);
                self.write_pos += buffered;
            }

            if self.write_pos == max_block_size {
                let len = encode_application_data_record_in_place::<CipherSuite>(
                    self.record_write_buf,
                    self.write_pos,
                    &mut self.key_schedule,
                )?;

                self.delegate
                    .write_all(&self.record_write_buf[..len])
                    .await
                    .map_err(|e| TlsError::Io(e.kind()))?;

                self.key_schedule.increment_write_counter();
                self.write_pos = 0;
            }

            Ok(buffered)
        } else {
            Err(TlsError::MissingHandshake)
        }
    }

    /// Force all previously written, buffered bytes to be encoded into a tls record and written to the connection.
    pub async fn flush(&mut self) -> Result<(), TlsError> {
        if self.write_pos > 0 {
            let len = encode_application_data_record_in_place::<CipherSuite>(
                self.record_write_buf,
                self.write_pos,
                &mut self.key_schedule,
            )?;

            self.delegate
                .write_all(&self.record_write_buf[..len])
                .await
                .map_err(|e| TlsError::Io(e.kind()))?;

            self.key_schedule.increment_write_counter();
            self.write_pos = 0;
        }

        Ok(())
    }

    fn create_read_buffer(&mut self) -> ReadBuffer {
        let offset = self.decrypted_offset + self.decrypted_consumed;
        let end = self.decrypted_offset + self.decrypted_len;
        ReadBuffer::new(
            &mut self.record_reader.buf[offset..end],
            &mut self.decrypted_consumed,
        )
    }

    /// Read and decrypt data filling the provided slice.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        let mut buffer = self.read_buffered().await?;

        let to_copy = buffer.pop(buf.len());

        trace!("Got {} bytes to copy", to_copy.len());
        buf[..to_copy.len()].copy_from_slice(to_copy);

        Ok(to_copy.len())
    }

    /// Reads buffered data. If nothing is in memory, it'll wait for a TLS record and process it.
    pub async fn read_buffered(&mut self) -> Result<ReadBuffer, TlsError> {
        if self.opened {
            while self.need_to_read() {
                self.read_application_data().await?;
            }

            Ok(self.create_read_buffer())
        } else {
            Err(TlsError::MissingHandshake)
        }
    }

    async fn read_application_data(&mut self) -> Result<(), TlsError> {
        let buf_ptr = self.record_reader.buf.as_ptr();
        let buf_len = self.record_reader.buf.len();
        let record = self
            .record_reader
            .read(&mut self.delegate, &mut self.key_schedule)
            .await?;

        decrypt_record_in_place::<CipherSuite, _>(
            &mut self.key_schedule,
            record,
            (),
            |_key_schedule, record| {
                match record {
                    ServerRecord::ApplicationData(data) => {
                        trace!("Got application data record");

                        // SAFETY: Assume `decrypt_record()` to decrypt in-place
                        // We have assertions to ensure this is valid.
                        let slice = data.data.as_slice();
                        let slice_ptr = slice.as_ptr();
                        let offset = unsafe { slice_ptr.offset_from(buf_ptr) };
                        assert!(offset >= 0);
                        let offset = offset as usize;
                        assert!(offset + slice.len() <= buf_len);

                        self.decrypted_offset = offset;
                        self.decrypted_len = slice.len();
                        self.decrypted_consumed = 0;
                        Ok(ControlFlow::Break(()))
                    }
                    ServerRecord::Alert(alert) => {
                        if let AlertDescription::CloseNotify = alert.description {
                            self.opened = false;
                            Err(TlsError::ConnectionClosed)
                        } else {
                            Err(TlsError::InternalError)
                        }
                    }
                    ServerRecord::ChangeCipherSpec(_) => Err(TlsError::InternalError),
                    ServerRecord::Handshake(ServerHandshake::NewSessionTicket(_)) => {
                        // Ignore
                        Ok(ControlFlow::Continue(()))
                    }
                    _ => {
                        unimplemented!()
                    }
                }
            },
        )
    }

    /// Close a connection instance, returning the ownership of the config, random generator and the async I/O provider.
    async fn close_internal(&mut self) -> Result<(), TlsError> {
        let record = ClientRecord::Alert(
            Alert::new(AlertLevel::Warning, AlertDescription::CloseNotify),
            self.opened,
        );

        let (_, len) =
            encode_record::<CipherSuite>(self.record_write_buf, &mut self.key_schedule, &record)?;

        self.delegate
            .write_all(&self.record_write_buf[..len])
            .await
            .map_err(|e| TlsError::Io(e.kind()))?;

        self.key_schedule.increment_write_counter();

        Ok(())
    }

    /// Close a connection instance, returning the ownership of the async I/O provider.
    pub async fn close(mut self) -> Result<Socket, (Socket, TlsError)> {
        match self.close_internal().await {
            Ok(()) => Ok(self.delegate),
            Err(e) => Err((self.delegate, e)),
        }
    }

    fn need_to_read(&self) -> bool {
        self.decrypted_consumed >= self.decrypted_len
    }
}

impl<'a, Socket, CipherSuite> Io for TlsConnection<'a, Socket, CipherSuite>
where
    Socket: AsyncRead + AsyncWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    type Error = TlsError;
}

impl<'a, Socket, CipherSuite> AsyncRead for TlsConnection<'a, Socket, CipherSuite>
where
    Socket: AsyncRead + AsyncWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        TlsConnection::read(self, buf).await
    }
}

impl<'a, Socket, CipherSuite> AsyncWrite for TlsConnection<'a, Socket, CipherSuite>
where
    Socket: AsyncRead + AsyncWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        TlsConnection::write(self, buf).await
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        TlsConnection::flush(self).await
    }
}
