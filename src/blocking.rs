use crate::common::decrypted_buffer_info::DecryptedBufferInfo;
use crate::common::decrypted_read_handler::DecryptedReadHandler;
use crate::connection::*;
use crate::key_schedule::KeySchedule;
use crate::read_buffer::ReadBuffer;
use crate::record::{ClientRecord, ClientRecordHeader};
use crate::record_reader::RecordReader;
use crate::write_buffer::WriteBuffer;
use embedded_io::blocking::BufRead;
use embedded_io::Error as _;
use embedded_io::{
    blocking::{Read, Write},
    Io,
};
use rand_core::{CryptoRng, RngCore};

pub use crate::config::*;
pub use crate::TlsError;

/// Type representing an async TLS connection. An instance of this type can
/// be used to establish a TLS connection, write and read encrypted data over this connection,
/// and closing to free up the underlying resources.
pub struct TlsConnection<'a, Socket, CipherSuite>
where
    Socket: Read + Write + 'a,
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
    Socket: Read + Write + 'a,
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
    pub fn open<'m, RNG: CryptoRng + RngCore + 'm, Verifier: TlsVerifier<CipherSuite> + 'static>(
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
            let next_state = state.process_blocking(
                &mut self.delegate,
                &mut handshake,
                &mut self.record_reader,
                &mut self.record_write_buf,
                &mut self.key_schedule,
                context.config,
                context.rng,
            )?;
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
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        if self.opened {
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

    /// Force all previously written, buffered bytes to be encoded into a tls record and written to the connection.
    pub fn flush(&mut self) -> Result<(), TlsError> {
        if !self.record_write_buf.is_empty() {
            let key_schedule = self.key_schedule.write_state();
            let slice = self.record_write_buf.close_record(key_schedule)?;

            self.delegate
                .write_all(slice)
                .map_err(|e| TlsError::Io(e.kind()))?;

            key_schedule.increment_counter();
        }

        Ok(())
    }

    fn create_read_buffer(&mut self) -> ReadBuffer {
        self.decrypted.create_read_buffer(self.record_reader.buf)
    }

    /// Read and decrypt data filling the provided slice.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        let mut buffer = self.read_buffered()?;

        let len = buffer.pop_into(buf);
        trace!("Copied {} bytes", len);

        Ok(len)
    }

    /// Reads buffered data. If nothing is in memory, it'll wait for a TLS record and process it.
    pub fn read_buffered(&mut self) -> Result<ReadBuffer, TlsError> {
        if self.opened {
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
            is_open: &mut self.opened,
        };
        decrypt_record(key_schedule, record, |_key_schedule, record| {
            handler.handle(record)
        })?;

        Ok(())
    }

    fn close_internal(&mut self) -> Result<(), TlsError> {
        self.flush()?;

        let (write_key_schedule, read_key_schedule) = self.key_schedule.as_split();
        let slice = self.record_write_buf.write_record(
            &ClientRecord::close_notify(self.opened),
            write_key_schedule,
            Some(read_key_schedule),
        )?;

        self.delegate
            .write_all(slice)
            .map_err(|e| TlsError::Io(e.kind()))?;

        self.key_schedule.write_state().increment_counter();

        Ok(())
    }

    /// Close a connection instance, returning the ownership of the I/O provider.
    pub fn close(mut self) -> Result<Socket, (Socket, TlsError)> {
        match self.close_internal() {
            Ok(()) => Ok(self.delegate),
            Err(e) => Err((self.delegate, e)),
        }
    }

    #[cfg(feature = "split")]
    pub fn split(
        self,
    ) -> (
        TlsReader<'a, Socket, CipherSuite>,
        TlsWriter<'a, Socket, CipherSuite>,
    )
    where
        Socket: Clone,
    {
        split::split(self)
    }

    #[cfg(feature = "split")]
    pub fn unsplit(
        reader: TlsReader<'a, Socket, CipherSuite>,
        writer: TlsWriter<'a, Socket, CipherSuite>,
    ) -> Self
    where
        Socket: Clone,
    {
        split::unsplit(reader, writer)
    }
}

impl<'a, Socket, CipherSuite> Io for TlsConnection<'a, Socket, CipherSuite>
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

#[cfg(feature = "split")]
mod split {
    use super::*;

    use crate::key_schedule::{ReadKeySchedule, SharedState, WriteKeySchedule};
    use core::sync::atomic::Ordering;
    use std::{sync::atomic::AtomicBool, sync::Arc};

    pub struct TlsReader<'a, Socket, CipherSuite>
    where
        Socket: Read + 'a,
        CipherSuite: TlsCipherSuite + 'static,
    {
        opened: Arc<AtomicBool>,
        delegate: Socket,
        key_schedule: ReadKeySchedule<CipherSuite>,
        record_reader: RecordReader<'a, CipherSuite>,
        decrypted: DecryptedBufferInfo,
    }

    impl<'a, Socket, CipherSuite> AsRef<Socket> for TlsReader<'a, Socket, CipherSuite>
    where
        Socket: Read + 'a,
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
        fn create_read_buffer(&mut self) -> ReadBuffer {
            self.decrypted.create_read_buffer(self.record_reader.buf)
        }

        /// Reads buffered data. If nothing is in memory, it'll wait for a TLS record and process it.
        pub fn read_buffered(&mut self) -> Result<ReadBuffer, TlsError> {
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
                .read_blocking(&mut self.delegate, &mut self.key_schedule)?;

            let mut opened = self.opened.load(Ordering::Acquire);
            let mut handler = DecryptedReadHandler {
                source_buffer: buf_ptr_range,
                buffer_info: &mut self.decrypted,
                is_open: &mut opened,
            };
            let result = decrypt_record(&mut self.key_schedule, record, |_key_schedule, record| {
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
        Socket: Write + 'a,
        CipherSuite: TlsCipherSuite + 'static,
    {
        opened: Arc<AtomicBool>,
        delegate: Socket,
        key_schedule_shared: SharedState<CipherSuite>,
        key_schedule: WriteKeySchedule<CipherSuite>,
        record_write_buf: &'a mut [u8],
        write_pos: usize,
    }

    impl<'a, Socket, CipherSuite> AsRef<Socket> for TlsWriter<'a, Socket, CipherSuite>
    where
        Socket: Write + 'a,
        CipherSuite: TlsCipherSuite + 'static,
    {
        fn as_ref(&self) -> &Socket {
            &self.delegate
        }
    }

    impl<'a, Socket, CipherSuite> Io for TlsWriter<'a, Socket, CipherSuite>
    where
        Socket: Write + 'a,
        CipherSuite: TlsCipherSuite + 'static,
    {
        type Error = TlsError;
    }

    impl<'a, Socket, CipherSuite> Io for TlsReader<'a, Socket, CipherSuite>
    where
        Socket: Read + 'a,
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
            let mut buffer = self.read_buffered()?;

            let len = buffer.pop_into(buf);
            trace!("Copied {} bytes", len);

            Ok(len)
        }
    }

    impl<'a, Socket, CipherSuite> Write for TlsWriter<'a, Socket, CipherSuite>
    where
        Socket: Write + 'a,
        CipherSuite: TlsCipherSuite + 'static,
    {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            if self.opened.load(Ordering::Acquire) {
                let max_block_size = self.record_write_buf.len() - TLS_RECORD_OVERHEAD;
                let buffered = usize::min(buf.len(), max_block_size - self.write_pos);
                if buffered > 0 {
                    self.record_write_buf[self.write_pos..self.write_pos + buffered]
                        .copy_from_slice(&buf[..buffered]);
                    self.write_pos += buffered;
                }

                if self.write_pos == max_block_size {
                    self.flush()?;
                }

                Ok(buffered)
            } else {
                Err(TlsError::MissingHandshake)
            }
        }

        fn flush(&mut self) -> Result<(), Self::Error> {
            if self.write_pos > 0 {
                let len = encode_application_data_record_in_place(
                    self.record_write_buf,
                    self.write_pos,
                    &mut self.key_schedule,
                )?;

                self.delegate
                    .write_all(&self.record_write_buf[..len])
                    .map_err(|e| TlsError::Io(e.kind()))?;

                self.key_schedule.increment_counter();
                self.write_pos = 0;
            }

            Ok(())
        }
    }

    pub fn split<'a, Socket, CipherSuite>(
        connection: TlsConnection<'a, Socket, CipherSuite>,
    ) -> (
        TlsReader<'a, Socket, CipherSuite>,
        TlsWriter<'a, Socket, CipherSuite>,
    )
    where
        Socket: Read + Write + 'a,
        Socket: Clone,
        CipherSuite: TlsCipherSuite + 'static,
    {
        let opened = Arc::new(AtomicBool::new(connection.opened));
        let (shared, wks, rks) = connection.key_schedule.split();

        let reader = TlsReader {
            opened: opened.clone(),
            delegate: connection.delegate.clone(),
            key_schedule: rks,
            record_reader: connection.record_reader,
            decrypted: connection.decrypted,
        };
        let writer = TlsWriter {
            opened,
            delegate: connection.delegate,
            key_schedule_shared: shared,
            key_schedule: wks,
            record_write_buf: connection.record_write_buf,
            write_pos: connection.write_pos,
        };

        (reader, writer)
    }

    pub(super) fn unsplit<'a, Socket, CipherSuite>(
        reader: TlsReader<'a, Socket, CipherSuite>,
        writer: TlsWriter<'a, Socket, CipherSuite>,
    ) -> TlsConnection<'a, Socket, CipherSuite>
    where
        Socket: Read + Write + 'a,
        CipherSuite: TlsCipherSuite + 'static,
    {
        debug_assert!(Arc::ptr_eq(&reader.opened, &writer.opened));

        TlsConnection {
            delegate: writer.delegate,
            opened: writer.opened.load(Ordering::Relaxed),
            key_schedule: KeySchedule::unsplit(
                writer.key_schedule_shared,
                writer.key_schedule,
                reader.key_schedule,
            ),
            record_reader: reader.record_reader,
            record_write_buf: writer.record_write_buf,
            write_pos: writer.write_pos,
            decrypted: reader.decrypted,
        }
    }
}

#[cfg(feature = "split")]
pub use split::{TlsReader, TlsWriter};
