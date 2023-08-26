use crate::common::decrypted_buffer_info::DecryptedBufferInfo;
use crate::common::decrypted_read_handler::DecryptedReadHandler;
use crate::connection::*;
use crate::key_schedule::KeySchedule;
use crate::key_schedule::{ReadKeySchedule, SharedState, WriteKeySchedule};
use crate::read_buffer::ReadBuffer;
use crate::record::{ClientRecord, ClientRecordHeader};
use crate::record_reader::RecordReader;
use crate::split::{SplitState, SplitStateContainer};
use crate::write_buffer::WriteBuffer;
use crate::TlsError;
use embedded_io::Error as _;
use embedded_io::ErrorType;
use embedded_io_async::{BufRead, Read as AsyncRead, Write as AsyncWrite};
use rand_core::{CryptoRng, RngCore};

pub use crate::config::*;
#[cfg(feature = "std")]
pub use crate::split::ManagedSplitState;
pub use crate::split::SplitConnectionState;

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

    /// Open a TLS connection, performing the handshake with the configuration provided when
    /// creating the connection instance.
    ///
    /// Returns an error if the handshake does not proceed. If an error occurs, the connection
    /// instance must be recreated.
    pub async fn open<'v, RNG, Verifier>(
        &mut self,
        context: TlsContext<'v, CipherSuite, RNG>,
    ) -> Result<(), TlsError>
    where
        RNG: CryptoRng + RngCore,
        Verifier: TlsVerifier<'v, CipherSuite>,
    {
        let mut handshake: Handshake<CipherSuite, Verifier> =
            Handshake::new(Verifier::new(context.config.server_name));
        let mut state = State::ClientHello;

        while state != State::ApplicationData {
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
        }
        self.opened = true;

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

    /// Force all previously written, buffered bytes to be encoded into a tls record and written
    /// to the connection.
    pub async fn flush(&mut self) -> Result<(), TlsError> {
        if !self.record_write_buf.is_empty() {
            let key_schedule = self.key_schedule.write_state();
            let slice = self.record_write_buf.close_record(key_schedule)?;

            self.delegate.write_all(slice).await?;

            key_schedule.increment_counter();

            self.delegate
                .flush()
                .await
                .map_err(|e| TlsError::Io(e.kind()))?;
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

        self.delegate.write_all(slice).await?;

        self.key_schedule.write_state().increment_counter();

        self.flush().await
    }

    /// Close a connection instance, returning the ownership of the async I/O provider.
    pub async fn close(mut self) -> Result<Socket, (Socket, TlsError)> {
        match self.close_internal().await {
            Ok(()) => Ok(self.delegate),
            Err(e) => Err((self.delegate, e)),
        }
    }

    #[cfg(feature = "std")]
    pub fn split(
        self,
    ) -> (
        TlsReader<'a, Socket, CipherSuite, ManagedSplitState>,
        TlsWriter<'a, Socket, CipherSuite, ManagedSplitState>,
    )
    where
        Socket: Clone,
    {
        self.split_with(ManagedSplitState::new())
    }

    pub fn split_with<StateContainer>(
        self,
        state: StateContainer,
    ) -> (
        TlsReader<'a, Socket, CipherSuite, StateContainer::State>,
        TlsWriter<'a, Socket, CipherSuite, StateContainer::State>,
    )
    where
        Socket: Clone,
        StateContainer: SplitStateContainer,
    {
        let state = state.state();
        state.set_open(self.opened);

        let (shared, wks, rks) = self.key_schedule.split();

        let reader = TlsReader {
            state: state.clone(),
            delegate: self.delegate.clone(),
            key_schedule: rks,
            record_reader: self.record_reader,
            decrypted: self.decrypted,
        };
        let writer = TlsWriter {
            state,
            delegate: self.delegate,
            key_schedule_shared: shared,
            key_schedule: wks,
            record_write_buf: self.record_write_buf,
        };

        (reader, writer)
    }

    pub fn unsplit<State>(
        reader: TlsReader<'a, Socket, CipherSuite, State>,
        writer: TlsWriter<'a, Socket, CipherSuite, State>,
    ) -> Self
    where
        Socket: Clone,
        State: SplitState,
    {
        debug_assert!(reader.state.same(&writer.state));

        TlsConnection {
            delegate: writer.delegate,
            opened: writer.state.is_open(),
            key_schedule: KeySchedule::unsplit(
                writer.key_schedule_shared,
                writer.key_schedule,
                reader.key_schedule,
            ),
            record_reader: reader.record_reader,
            record_write_buf: writer.record_write_buf,
            decrypted: reader.decrypted,
        }
    }
}

impl<'a, Socket, CipherSuite> ErrorType for TlsConnection<'a, Socket, CipherSuite>
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

pub struct TlsReader<'a, Socket, CipherSuite, State>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    state: State,
    delegate: Socket,
    key_schedule: ReadKeySchedule<CipherSuite>,
    record_reader: RecordReader<'a, CipherSuite>,
    decrypted: DecryptedBufferInfo,
}

impl<'a, Socket, CipherSuite, State> AsRef<Socket> for TlsReader<'a, Socket, CipherSuite, State>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    fn as_ref(&self) -> &Socket {
        &self.delegate
    }
}

impl<'a, Socket, CipherSuite, State> TlsReader<'a, Socket, CipherSuite, State>
where
    Socket: AsyncRead + 'a,
    CipherSuite: TlsCipherSuite + 'static,
    State: SplitState,
{
    fn create_read_buffer(&mut self) -> ReadBuffer {
        self.decrypted.create_read_buffer(self.record_reader.buf)
    }

    /// Reads buffered data. If nothing is in memory, it'll wait for a TLS record and process it.
    pub async fn read_buffered(&mut self) -> Result<ReadBuffer, TlsError> {
        if self.state.is_open() {
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
            .read(&mut self.delegate, &mut self.key_schedule)
            .await?;

        let mut opened = self.state.is_open();
        let mut handler = DecryptedReadHandler {
            source_buffer: buf_ptr_range,
            buffer_info: &mut self.decrypted,
            is_open: &mut opened,
        };
        let result = decrypt_record(&mut self.key_schedule, record, |_key_schedule, record| {
            handler.handle(record)
        });

        if !opened {
            self.state.set_open(false);
        }
        result
    }
}

pub struct TlsWriter<'a, Socket, CipherSuite, State>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    state: State,
    delegate: Socket,
    key_schedule_shared: SharedState<CipherSuite>,
    key_schedule: WriteKeySchedule<CipherSuite>,
    record_write_buf: WriteBuffer<'a>,
}

impl<'a, Socket, CipherSuite, State> AsRef<Socket> for TlsWriter<'a, Socket, CipherSuite, State>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    fn as_ref(&self) -> &Socket {
        &self.delegate
    }
}

impl<'a, Socket, CipherSuite, State> ErrorType for TlsWriter<'a, Socket, CipherSuite, State>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    type Error = TlsError;
}

impl<'a, Socket, CipherSuite, State> ErrorType for TlsReader<'a, Socket, CipherSuite, State>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    type Error = TlsError;
}

impl<'a, Socket, CipherSuite, State> AsyncRead for TlsReader<'a, Socket, CipherSuite, State>
where
    Socket: AsyncRead + 'a,
    CipherSuite: TlsCipherSuite + 'static,
    State: SplitState,
{
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let mut buffer = self.read_buffered().await?;

        let len = buffer.pop_into(buf);
        trace!("Copied {} bytes", len);

        Ok(len)
    }
}

impl<'a, Socket, CipherSuite, State> BufRead for TlsReader<'a, Socket, CipherSuite, State>
where
    Socket: AsyncRead + 'a,
    CipherSuite: TlsCipherSuite + 'static,
    State: SplitState,
{
    async fn fill_buf(&mut self) -> Result<&[u8], Self::Error> {
        self.read_buffered().await.map(|mut buf| buf.peek_all())
    }

    fn consume(&mut self, amt: usize) {
        self.create_read_buffer().pop(amt);
    }
}

impl<'a, Socket, CipherSuite, State> AsyncWrite for TlsWriter<'a, Socket, CipherSuite, State>
where
    Socket: AsyncWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
    State: SplitState,
{
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        if self.state.is_open() {
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

    async fn flush(&mut self) -> Result<(), Self::Error> {
        if !self.record_write_buf.is_empty() {
            let slice = self.record_write_buf.close_record(&mut self.key_schedule)?;

            self.delegate.write_all(slice).await?;

            self.key_schedule.increment_counter();

            self.delegate
                .flush()
                .await
                .map_err(|e| TlsError::Io(e.kind()))?;
        }

        Ok(())
    }
}
