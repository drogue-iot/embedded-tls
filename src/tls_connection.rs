use crate::alert::*;
use crate::connection::*;
use crate::handshake::ServerHandshake;
use crate::key_schedule::KeySchedule;
use crate::record::{ClientRecord, ServerRecord};
use crate::TlsError;
use embedded_io::asynch::{Read as AsyncRead, Write as AsyncWrite};
use embedded_io::Error as _;
use rand_core::{CryptoRng, RngCore};

use crate::application_data::ApplicationData;
use heapless::spsc::Queue;

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
    key_schedule: KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
    record_buf: &'a mut [u8],
    opened: bool,
}

impl<'a, Socket, CipherSuite> TlsConnection<'a, Socket, CipherSuite>
where
    Socket: AsyncRead + AsyncWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    /// Create a new TLS connection with the provided context and a async I/O implementation
    ///
    /// NOTE: The record buffer should be sized to fit an encrypted TLS record and the TLS handshake
    /// record. The maximum value of a TLS record is 16 kB, which should be a safe value to use.
    pub fn new(delegate: Socket, record_buf: &'a mut [u8]) -> Self {
        Self {
            delegate,
            opened: false,
            key_schedule: KeySchedule::new(),
            record_buf,
        }
    }

    /// Open a TLS connection, performing the handshake with the configuration provided when creating
    /// the connection instance.
    ///
    /// The handshake may support certificates up to CERT_SIZE.
    ///
    /// Returns an error if the handshake does not proceed. If an error occurs, the connection instance
    /// must be recreated.
    pub async fn open<
        'm,
        RNG: CryptoRng + RngCore + 'static,
        Clock: TlsClock + 'static,
        const CERT_SIZE: usize,
    >(
        &mut self,
        context: TlsContext<'m, CipherSuite, RNG>,
    ) -> Result<(), TlsError>
    where
        'a: 'm,
    {
        let mut handshake: Handshake<CipherSuite, CERT_SIZE> = Handshake::new();
        let mut state = State::ClientHello;

        loop {
            let next_state = state
                .process::<_, _, _, Clock, CERT_SIZE>(
                    &mut self.delegate,
                    &mut handshake,
                    self.record_buf,
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
    /// Returns the number of bytes written.
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        if self.opened {
            let mut wp = 0;
            let mut remaining = buf.len();

            let max_block_size = self.record_buf.len() - TLS_RECORD_OVERHEAD;
            while remaining > 0 {
                let delegate = &mut self.delegate;
                let key_schedule = &mut self.key_schedule;
                let to_write = core::cmp::min(remaining, max_block_size);
                let record: ClientRecord<'a, '_, CipherSuite> =
                    ClientRecord::ApplicationData(&buf[wp..to_write]);

                let (_, len) = encode_record(self.record_buf, key_schedule, &record)?;

                delegate
                    .write(&self.record_buf[..len])
                    .await
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
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        if self.opened {
            let mut remaining = buf.len();
            // Note: Read only a single ApplicationData record for now, as we don't do any buffering.
            while remaining == buf.len() {
                let socket = &mut self.delegate;
                let key_schedule = &mut self.key_schedule;
                let record =
                    decode_record::<Socket, CipherSuite>(socket, self.record_buf, key_schedule)
                        .await?;
                let mut records = Queue::new();
                decrypt_record::<CipherSuite>(key_schedule, &mut records, record)?;
                while let Some(record) = records.dequeue() {
                    match record {
                        ServerRecord::ApplicationData(ApplicationData { header: _, data }) => {
                            trace!("Got application data record");
                            if buf.len() < data.len() {
                                warn!("Passed buffer is too small");
                                Err(TlsError::EncodeError)
                            } else {
                                let to_copy = core::cmp::min(data.len(), buf.len());
                                // TODO Need to buffer data not consumed
                                trace!("Got {} bytes to copy", to_copy);
                                buf[..to_copy].copy_from_slice(&data.as_slice()[..to_copy]);
                                remaining -= to_copy;
                                Ok(())
                            }
                        }
                        ServerRecord::Alert(alert) => {
                            if let AlertDescription::CloseNotify = alert.description {
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
            }
            Ok(buf.len() - remaining)
        } else {
            Err(TlsError::MissingHandshake)
        }
    }

    /// Close a connection instance, returning the ownership of the config, random generator and the async I/O provider.
    pub async fn close(self) -> Result<Socket, TlsError> {
        let record = ClientRecord::Alert(
            Alert::new(AlertLevel::Warning, AlertDescription::CloseNotify),
            self.opened,
        );

        let mut key_schedule = self.key_schedule;
        let mut delegate = self.delegate;
        let record_buf = self.record_buf;

        let (_, len) = encode_record::<CipherSuite>(record_buf, &mut key_schedule, &record)?;

        delegate
            .write(&record_buf[..len])
            .await
            .map_err(|e| TlsError::Io(e.kind()))?;

        key_schedule.increment_write_counter();

        Ok(delegate)
    }
}
