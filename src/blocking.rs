use crate::alert::*;
use crate::buffer::CryptoBuffer;
use crate::connection::*;
use crate::handshake::ServerHandshake;
use crate::key_schedule::KeySchedule;
use crate::record::{ClientRecord, ServerRecord};
use embedded_io::Error as _;
use embedded_io::{
    blocking::{Read, Write},
    Io,
};
use rand_core::{CryptoRng, RngCore};

use heapless::spsc::Queue;

pub use crate::config::*;
pub use crate::TlsError;

// Some space needed by TLS record
const TLS_RECORD_OVERHEAD: usize = 128;

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
    key_schedule: KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
    record_read_buf: &'a mut [u8],
    record_write_buf: &'a mut [u8],
    decrypted_offset: usize,
    decrypted_len: usize,
    decrypted_consumed: usize,
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
        assert!(
            record_write_buf.len() > TLS_RECORD_OVERHEAD,
            "The write buffer must be sufficiently large to include the tls record overhead"
        );
        Self {
            delegate,
            opened: false,
            key_schedule: KeySchedule::new(),
            record_read_buf,
            record_write_buf,
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
        let record_buf = if self.record_read_buf.len() > self.record_write_buf.len() {
            &mut self.record_read_buf
        } else {
            &mut self.record_write_buf
        };

        loop {
            let next_state = state.process_blocking::<_, _, _, Verifier>(
                &mut self.delegate,
                &mut handshake,
                record_buf,
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
    /// Returns the number of bytes written.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        if self.opened {
            let mut wp = 0;
            let mut remaining = buf.len();

            let max_block_size = self.record_write_buf.len() - TLS_RECORD_OVERHEAD;
            while remaining > 0 {
                let delegate = &mut self.delegate;
                let key_schedule = &mut self.key_schedule;
                let to_write = core::cmp::min(remaining, max_block_size);
                let record: ClientRecord<'a, '_, CipherSuite> =
                    ClientRecord::ApplicationData(&buf[wp..to_write]);

                let (_, len) = encode_record(self.record_write_buf, key_schedule, &record)?;

                delegate
                    .write(&self.record_write_buf[..len])
                    .map_err(|e| TlsError::Io(e.kind()))?;
                key_schedule.increment_write_counter();
                wp += to_write;
                remaining -= to_write;
            }

            Ok(buf.len())
        } else {
            Err(TlsError::MissingHandshake)
        }
    }

    /// Read and decrypt data filling the provided slice. The slice must be able to
    /// keep the expected amount of data that can be received in one record to avoid
    /// loosing data.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        if self.opened {
            let mut remaining = buf.len();
            let mut consumed = self.decrypted_consumed;
            while remaining == buf.len() {
                let record_data = if consumed < self.decrypted_len {
                    // The current record is not completely consumed
                    CryptoBuffer::wrap(
                        &mut self.record_read_buf
                            [self.decrypted_offset..self.decrypted_offset + self.decrypted_len],
                    )
                } else {
                    // The current record is completely consumed, read the next...
                    consumed = 0;
                    self.read_application_data()?
                };

                let unread = &record_data.as_slice()[consumed..];
                let to_copy = core::cmp::min(unread.len(), buf.len());
                trace!("Got {} bytes to copy", to_copy);
                buf[..to_copy].copy_from_slice(&unread[..to_copy]);
                consumed += to_copy;
                remaining -= to_copy;
            }
            self.decrypted_consumed = consumed;
            Ok(buf.len() - remaining)
        } else {
            Err(TlsError::MissingHandshake)
        }
    }

    fn read_application_data<'m>(&'m mut self) -> Result<CryptoBuffer<'m>, TlsError> {
        let buf_ptr = self.record_read_buf.as_ptr();
        let buf_len = self.record_read_buf.len();
        let record = decode_record_blocking::<Socket, CipherSuite>(
            &mut self.delegate,
            self.record_read_buf,
            &mut self.key_schedule,
        )?;
        let mut records = Queue::new();
        decrypt_record::<CipherSuite>(&mut self.key_schedule, &mut records, record)?;

        while let Some(record) = records.dequeue() {
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
                    return Ok(data.data);
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
                    Ok(())
                }
                _ => {
                    unimplemented!()
                }
            }?;
        }

        Ok(CryptoBuffer::empty())
    }

    fn close_internal(&mut self) -> Result<(), TlsError> {
        let record = ClientRecord::Alert(
            Alert::new(AlertLevel::Warning, AlertDescription::CloseNotify),
            self.opened,
        );

        let record_buf = if self.record_read_buf.len() > self.record_write_buf.len() {
            &mut self.record_read_buf
        } else {
            &mut self.record_write_buf
        };
        let (_, len) = encode_record::<CipherSuite>(record_buf, &mut self.key_schedule, &record)?;

        self.delegate
            .write(&record_buf[..len])
            .map_err(|e| TlsError::Io(e.kind()))?;

        self.key_schedule.increment_write_counter();

        Ok(())
    }

    /// Close a connection instance, returning the ownership of the I/O provider.
    pub fn close(mut self) -> Result<Socket, (Socket, TlsError)> {
        match self.close_internal() {
            Ok(()) => Ok(self.delegate),
            Err(e) => Err((self.delegate, e)),
        }
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

impl<'a, Socket, CipherSuite> Write for TlsConnection<'a, Socket, CipherSuite>
where
    Socket: Read + Write + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        TlsConnection::write(self, buf)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}
