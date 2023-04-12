use core::sync::atomic::{AtomicBool, Ordering};

use crate::alert::*;
use crate::common::decrypted_buffer_info::DecryptedBufferInfo;
use crate::common::decrypted_read_handler::DecryptedReadHandler;
use crate::connection::*;
use crate::key_schedule::{KeySchedule, ReadKeySchedule, WriteKeySchedule};
use crate::read_buffer::ReadBuffer;
use crate::record::ClientRecord;
use crate::record_reader::RecordReader;
use embedded_io::blocking::{Read, Write};
use embedded_io::{Error as _, Io};
use rand_core::{CryptoRng, RngCore};

pub use crate::config::*;
pub use crate::TlsError;

// Some space needed by TLS record
const TLS_RECORD_OVERHEAD: usize = 128;

struct IsOpenToken {
    flag: AtomicBool,
}

impl IsOpenToken {
    fn new() -> Self {
        Self {
            flag: AtomicBool::new(true),
        }
    }

    fn check_open(&self) -> Result<(), TlsError> {
        if self.is_open() {
            Ok(())
        } else {
            Err(TlsError::MissingHandshake)
        }
    }

    fn is_open(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }

    fn close(&self) {
        self.flag.store(false, Ordering::Relaxed);
    }
}

/// Type representing an async TLS connection. An instance of this type can
/// be used to establish a TLS connection, write and read encrypted data over this connection,
/// and closing to free up the underlying resources.
pub struct TlsConnector<'a> {
    record_read_buf: &'a mut [u8],
    record_write_buf: &'a mut [u8],
}

impl<'a> TlsConnector<'a> {
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
    pub fn new(record_read_buf: &'a mut [u8], record_write_buf: &'a mut [u8]) -> Self {
        assert!(
            record_write_buf.len() > TLS_RECORD_OVERHEAD,
            "The write buffer must be sufficiently large to include the tls record overhead"
        );
        Self {
            record_read_buf,
            record_write_buf,
        }
    }

    /// Open a TLS connection, performing the handshake with the configuration provided when creating
    /// the connection instance.
    ///
    /// The handshake may support certificates up to CERT_SIZE.
    ///
    /// Returns an error if the handshake does not proceed. If an error occurs, the connection instance
    /// must be recreated.
    pub fn open<
        'b,
        CipherSuite,
        Socket,
        RNG: CryptoRng + RngCore,
        Verifier: TlsVerifier<CipherSuite>,
    >(
        &'b mut self,
        context: TlsContext<'_, CipherSuite, RNG>,
        mut delegate: Socket,
    ) -> Result<TlsConnection<'b, Socket, CipherSuite>, TlsError>
    where
        Socket: Read + Write + 'b,
        CipherSuite: TlsCipherSuite + 'b,
    {
        let mut handshake: Handshake<CipherSuite, Verifier> =
            Handshake::new(Verifier::new(context.config.server_name));
        let mut state = State::ClientHello;

        let mut key_schedule = KeySchedule::new();
        let mut record_reader = RecordReader::new(self.record_read_buf);

        loop {
            let next_state = state.process_blocking(
                &mut delegate,
                &mut handshake,
                &mut record_reader,
                self.record_write_buf,
                &mut key_schedule,
                context.config,
                context.rng,
            )?;
            trace!("State {:?} -> {:?}", state, next_state);
            state = next_state;
            if let State::ApplicationData = state {
                return Ok(TlsConnection {
                    delegate,
                    is_open: IsOpenToken::new(),
                    key_schedule,
                    record_reader,
                    record_write_buf: self.record_write_buf,
                    write_pos: 0,
                    decrypted: DecryptedBufferInfo::default(),
                });
            }
        }
    }
}

/// Type representing an async TLS connection. An instance of this type can
/// be used to establish a TLS connection, write and read encrypted data over this connection,
/// and closing to free up the underlying resources.
pub struct TlsConnection<'a, Socket, CipherSuite>
where
    Socket: Read + Write + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    delegate: Socket,
    is_open: IsOpenToken,
    key_schedule: KeySchedule<CipherSuite>,
    record_reader: RecordReader<'a, CipherSuite>,
    record_write_buf: &'a mut [u8],
    write_pos: usize,
    decrypted: DecryptedBufferInfo,
}

impl<'a, Socket, CipherSuite> TlsConnection<'a, Socket, CipherSuite>
where
    Socket: Read + Write + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    /// Encrypt and send the provided slice over the connection. The connection
    /// must be opened before writing.
    ///
    /// The slice may be buffered internally and not written to the connection immediately.
    /// In this case [`flush()`] should be called to force the currently buffered writes
    /// to be written to the connection.
    ///
    /// Returns the number of bytes buffered/written.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        self.is_open.check_open()?;

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
    }

    /// Force all previously written, buffered bytes to be encoded into a tls record and written to the connection.
    pub fn flush(&mut self) -> Result<(), TlsError> {
        if self.write_pos > 0 {
            let key_schedule = self.key_schedule.write_state();
            let len = encode_application_data_record_in_place(
                self.record_write_buf,
                self.write_pos,
                key_schedule,
            )?;

            self.delegate
                .write_all(&self.record_write_buf[..len])
                .map_err(|e| TlsError::Io(e.kind()))?;

            key_schedule.increment_counter();
            self.write_pos = 0;
        }

        Ok(())
    }

    fn create_read_buffer(&mut self) -> ReadBuffer {
        self.decrypted.create_read_buffer(self.record_reader.buf)
    }

    /// Read and decrypt data filling the provided slice.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        let mut buffer = self.read_buffered()?;

        let to_copy = buffer.pop(buf.len());

        trace!("Got {} bytes to copy", to_copy.len());
        buf[..to_copy.len()].copy_from_slice(to_copy);

        Ok(to_copy.len())
    }

    /// Reads buffered data. If nothing is in memory, it'll wait for a TLS record and process it.
    pub fn read_buffered(&mut self) -> Result<ReadBuffer, TlsError> {
        self.is_open.check_open()?;

        while self.decrypted.is_empty() {
            self.read_application_data()?;
        }

        Ok(self.create_read_buffer())
    }

    fn read_application_data(&mut self) -> Result<(), TlsError> {
        let buf_ptr_range = self.record_reader.buf.as_ptr_range();
        let key_schedule = self.key_schedule.read_state();
        let record = self
            .record_reader
            .read_blocking(&mut self.delegate, key_schedule)?;

        let mut is_open = self.is_open.is_open();
        let mut handler = DecryptedReadHandler {
            source_buffer: buf_ptr_range,
            buffer_info: &mut self.decrypted,
            is_open: &mut is_open,
        };
        let result = decrypt_record(key_schedule, record, |_key_schedule, record| {
            handler.handle(record)
        });

        if !is_open {
            self.is_open.close();
        }

        result
    }

    fn close_internal(&mut self) -> Result<(), TlsError> {
        let record = ClientRecord::Alert(
            Alert::new(AlertLevel::Warning, AlertDescription::CloseNotify),
            self.is_open.is_open(),
        );

        let (write_key_schedule, read_key_schedule) = self.key_schedule.as_split();
        let (_, len) = encode_record(
            self.record_write_buf,
            read_key_schedule,
            write_key_schedule,
            &record,
        )?;

        self.delegate
            .write_all(&self.record_write_buf[..len])
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

    pub fn split(
        &mut self,
    ) -> Result<
        (
            TlsReader<'_, 'a, Socket, CipherSuite>,
            TlsWriter<'_, Socket, CipherSuite>,
        ),
        TlsError,
    >
    where
        Socket: Clone,
    {
        self.is_open.check_open()?;

        let (wks, rks) = self.key_schedule.as_split();

        Ok((
            TlsReader {
                socket: self.delegate.clone(),
                is_open: &self.is_open,
                record_reader: &mut self.record_reader,
                key_schedule: rks,
                decrypted: &mut self.decrypted,
            },
            TlsWriter {
                socket: self.delegate.clone(),
                is_open: &self.is_open,
                key_schedule: wks,
                write_pos: &mut self.write_pos,
                record_write_buf: &mut self.record_write_buf,
            },
        ))
    }

    pub fn socket(&self) -> &Socket {
        &self.delegate
    }
}

pub struct TlsReader<'a, 'r, Socket, CipherSuite>
where
    Socket: Read + Write + 'a,
    CipherSuite: TlsCipherSuite + 'static,
    'r: 'a,
{
    socket: Socket,
    is_open: &'a IsOpenToken,
    key_schedule: &'a mut ReadKeySchedule<CipherSuite>,
    record_reader: &'a mut RecordReader<'r, CipherSuite>,
    decrypted: &'a mut DecryptedBufferInfo,
}

impl<'a, 'r, Socket, CipherSuite> TlsReader<'a, 'r, Socket, CipherSuite>
where
    Socket: Read + Write + 'a,
    CipherSuite: TlsCipherSuite + 'static,
    'r: 'a,
{
    fn create_read_buffer(&mut self) -> ReadBuffer {
        self.decrypted.create_read_buffer(self.record_reader.buf)
    }

    /// Read and decrypt data filling the provided slice.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        let mut buffer = self.read_buffered()?;

        let to_copy = buffer.pop(buf.len());

        trace!("Got {} bytes to copy", to_copy.len());
        buf[..to_copy.len()].copy_from_slice(to_copy);

        Ok(to_copy.len())
    }

    /// Reads buffered data. If nothing is in memory, it'll wait for a TLS record and process it.
    pub fn read_buffered(&mut self) -> Result<ReadBuffer, TlsError> {
        self.is_open.check_open()?;

        while self.decrypted.is_empty() {
            self.read_application_data()?;
        }

        Ok(self.create_read_buffer())
    }

    fn read_application_data(&mut self) -> Result<(), TlsError> {
        let buf_ptr_range = self.record_reader.buf.as_ptr_range();
        let record = self
            .record_reader
            .read_blocking(&mut self.socket, self.key_schedule)?;

        let mut is_open = true;
        let mut handler = DecryptedReadHandler {
            source_buffer: buf_ptr_range,
            buffer_info: &mut self.decrypted,
            is_open: &mut is_open,
        };
        let result = decrypt_record(self.key_schedule, record, |_key_schedule, record| {
            handler.handle(record)
        });

        if !is_open {
            self.is_open.close();
        }

        result
    }

    pub fn socket(&self) -> &Socket {
        &self.socket
    }
}

pub struct TlsWriter<'a, Socket, CipherSuite>
where
    Socket: Read + Write + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    socket: Socket,
    is_open: &'a IsOpenToken,
    key_schedule: &'a mut WriteKeySchedule<CipherSuite>,
    write_pos: &'a mut usize,
    record_write_buf: &'a mut [u8],
}

impl<'a, Socket, CipherSuite> TlsWriter<'a, Socket, CipherSuite>
where
    Socket: Read + Write + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    /// Encrypt and send the provided slice over the connection. The connection
    /// must be opened before writing.
    ///
    /// The slice may be buffered internally and not written to the connection immediately.
    /// In this case [`flush()`] should be called to force the currently buffered writes
    /// to be written to the connection.
    ///
    /// Returns the number of bytes buffered/written.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        self.is_open.check_open()?;

        let max_block_size = self.record_write_buf.len() - TLS_RECORD_OVERHEAD;
        let buffered = usize::min(buf.len(), max_block_size - *self.write_pos);
        if buffered > 0 {
            self.record_write_buf[*self.write_pos..*self.write_pos + buffered]
                .copy_from_slice(&buf[..buffered]);
            *self.write_pos += buffered;
        }

        if *self.write_pos == max_block_size {
            self.flush()?;
        }

        Ok(buffered)
    }

    /// Force all previously written, buffered bytes to be encoded into a tls record and written to the connection.
    pub fn flush(&mut self) -> Result<(), TlsError> {
        if *self.write_pos > 0 {
            let len = encode_application_data_record_in_place(
                self.record_write_buf,
                *self.write_pos,
                self.key_schedule,
            )?;

            self.socket
                .write_all(&self.record_write_buf[..len])
                .map_err(|e| TlsError::Io(e.kind()))?;

            self.key_schedule.increment_counter();
            *self.write_pos = 0;
        }

        Ok(())
    }

    pub fn socket(&self) -> &Socket {
        &self.socket
    }
}

impl<'a, 'r, Socket, CipherSuite> Io for TlsReader<'a, 'r, Socket, CipherSuite>
where
    Socket: Read + Write + 'a,
    CipherSuite: TlsCipherSuite + 'static,
    'r: 'a,
{
    type Error = TlsError;
}

impl<'a, Socket, CipherSuite> Io for TlsWriter<'a, Socket, CipherSuite>
where
    Socket: Read + Write + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    type Error = TlsError;
}

impl<'a, 'r, Socket, CipherSuite> Read for TlsReader<'a, 'r, Socket, CipherSuite>
where
    Socket: Read + Write + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        TlsReader::read(self, buf)
    }
}

impl<'a, Socket, CipherSuite> Write for TlsWriter<'a, Socket, CipherSuite>
where
    Socket: Read + Write + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        TlsWriter::write(self, buf)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        TlsWriter::flush(self)
    }
}
