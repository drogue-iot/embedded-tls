use crate::common::decrypted_buffer_info::DecryptedBufferInfo;
use crate::common::decrypted_read_handler::DecryptedReadHandler;
use crate::connection::*;
use crate::key_schedule::KeySchedule;
use crate::read_buffer::ReadBuffer;
use crate::record::{ClientRecord, ClientRecordHeader};
use crate::record_reader::RecordReader;
use crate::write_buffer::WriteBuffer;
use crate::TlsError;
use embedded_io::asynch::BufRead;
use embedded_io::Error as _;
use embedded_io::{
    asynch::{Read as AsyncRead, Write as AsyncWrite},
    Io,
};
use rand_core::{CryptoRng, RngCore};

pub use crate::config::*;

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
    key_schedule: KeySchedule<CipherSuite>,
    record_reader: RecordReader<'a, CipherSuite>,
    record_write_buf: WriteBuffer<'a>,
    decrypted: DecryptedBufferInfo,
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
        Self {
            delegate,
            opened: false,
            key_schedule: KeySchedule::new(),
            record_reader: RecordReader::new(record_read_buf),
            record_write_buf: WriteBuffer::new(record_write_buf),
            decrypted: DecryptedBufferInfo::default(),
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
                    &mut self.record_write_buf,
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
            if !self
                .record_write_buf
                .contains(ClientRecordHeader::ApplicationData)
            {
                self.flush().await?;
                self.record_write_buf
                    .start_record(ClientRecordHeader::ApplicationData)?;
            }

            let buffered = self.record_write_buf.append(buf);

            if self.record_write_buf.is_full() {
                self.flush().await?;
            }

            Ok(buffered)
        } else {
            Err(TlsError::MissingHandshake)
        }
    }

    /// Force all previously written, buffered bytes to be encoded into a tls record and written to the connection.
    pub async fn flush(&mut self) -> Result<(), TlsError> {
        if !self.record_write_buf.is_empty() {
            let key_schedule = self.key_schedule.write_state();
            let slice = self.record_write_buf.close_record(key_schedule)?;

            self.delegate
                .write_all(slice)
                .await
                .map_err(|e| TlsError::Io(e.kind()))?;

            key_schedule.increment_counter();
        }

        Ok(())
    }

    fn create_read_buffer(&mut self) -> ReadBuffer {
        self.decrypted.create_read_buffer(self.record_reader.buf)
    }

    /// Read and decrypt data filling the provided slice.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        let mut buffer = self.read_buffered().await?;

        let len = buffer.pop_into(buf);
        trace!("Copied {} bytes", len);

        Ok(len)
    }

    /// Reads buffered data. If nothing is in memory, it'll wait for a TLS record and process it.
    pub async fn read_buffered(&mut self) -> Result<ReadBuffer, TlsError> {
        if self.opened {
            while self.decrypted.is_empty() {
                self.read_application_data().await?;
            }

            Ok(self.create_read_buffer())
        } else {
            Err(TlsError::MissingHandshake)
        }
    }

    async fn read_application_data(&mut self) -> Result<(), TlsError> {
        let buf_ptr_range = self.record_reader.buf.as_ptr_range();
        let record = self
            .record_reader
            .read(&mut self.delegate, self.key_schedule.read_state())
            .await?;

        let mut handler = DecryptedReadHandler {
            source_buffer: buf_ptr_range,
            buffer_info: &mut self.decrypted,
            is_open: &mut self.opened,
        };
        decrypt_record(
            self.key_schedule.read_state(),
            record,
            |_key_schedule, record| handler.handle(record),
        )?;

        Ok(())
    }

    /// Close a connection instance, returning the ownership of the config, random generator and the async I/O provider.
    async fn close_internal(&mut self) -> Result<(), TlsError> {
        self.flush().await?;

        let (write_key_schedule, read_key_schedule) = self.key_schedule.as_split();
        let slice = self.record_write_buf.write_record(
            &ClientRecord::close_notify(self.opened),
            write_key_schedule,
            Some(read_key_schedule),
        )?;

        self.delegate
            .write_all(slice)
            .await
            .map_err(|e| TlsError::Io(e.kind()))?;

        self.key_schedule.write_state().increment_counter();

        Ok(())
    }

    /// Close a connection instance, returning the ownership of the async I/O provider.
    pub async fn close(mut self) -> Result<Socket, (Socket, TlsError)> {
        match self.close_internal().await {
            Ok(()) => Ok(self.delegate),
            Err(e) => Err((self.delegate, e)),
        }
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

impl<'a, Socket, CipherSuite> BufRead for TlsConnection<'a, Socket, CipherSuite>
where
    Socket: AsyncRead + AsyncWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    async fn fill_buf(&mut self) -> Result<&[u8], Self::Error> {
        self.read_buffered().await.map(|mut buf| buf.peek_all())
    }

    fn consume(&mut self, amt: usize) {
        self.create_read_buffer().pop(amt);
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
