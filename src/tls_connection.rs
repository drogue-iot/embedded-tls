use crate::alert::*;
use crate::connection::*;
use crate::handshake::ServerHandshake;
use crate::key_schedule::KeySchedule;
use crate::record::{ClientRecord, ServerRecord};
use crate::{
    traits::{AsyncRead, AsyncWrite},
    TlsError,
};
use rand_core::{CryptoRng, RngCore};

use crate::application_data::ApplicationData;
use heapless::spsc::Queue;

pub use crate::config::*;

// Some space needed by TLS record
const TLS_RECORD_OVERHEAD: usize = 128;

/// Type representing an async TLS connection. An instance of this type can
/// be used to establish a TLS connection, write and read encrypted data over this connection,
/// and closing to free up the underlying resources.
pub struct TlsConnection<'a, RNG, Clock, Socket, CipherSuite>
where
    RNG: CryptoRng + RngCore + 'static,
    Clock: TlsClock + 'static,
    Socket: AsyncRead + AsyncWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    delegate: Socket,
    rng: RNG,
    config: TlsConfig<'a, CipherSuite>,
    key_schedule: KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
    record_buf: &'a mut [u8],
    opened: bool,
    clock: core::marker::PhantomData<&'a Clock>,
}

impl<'a, RNG, Clock, Socket, CipherSuite> TlsConnection<'a, RNG, Clock, Socket, CipherSuite>
where
    RNG: CryptoRng + RngCore + 'static,
    Clock: TlsClock,
    Socket: AsyncRead + AsyncWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    /// Create a new TLS connection with the provided context and a async I/O implementation
    pub fn new(context: TlsContext<'a, CipherSuite, RNG, Clock>, delegate: Socket) -> Self {
        Self {
            delegate,
            config: context.config,
            rng: context.rng,
            opened: false,
            key_schedule: KeySchedule::new(),
            record_buf: context.record_buf,
            clock: core::marker::PhantomData,
        }
    }

    /// Open a TLS connection, performing the handshake with the configuration provided when creating
    /// the connection instance.
    ///
    /// The handshake may support certificates up to CERT_SIZE.
    ///
    /// Returns an error if the handshake does not proceed. If an error occurs, the connection instance
    /// must be recreated.
    pub async fn open<'m, const CERT_SIZE: usize>(&mut self) -> Result<(), TlsError>
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
                    &mut self.record_buf,
                    &mut self.key_schedule,
                    &self.config,
                    &mut self.rng,
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
            trace!("TLS WRITE");
            let mut wp = 0;
            let mut remaining = buf.len();

            let max_block_size = self.record_buf.len() - TLS_RECORD_OVERHEAD;
            while remaining > 0 {
                let delegate = &mut self.delegate;
                let key_schedule = &mut self.key_schedule;
                let to_write = core::cmp::min(remaining, max_block_size);
                let record: ClientRecord<'a, '_, CipherSuite> =
                    ClientRecord::ApplicationData(&buf[wp..to_write]);

                let (_, len) = encode_record(&mut self.record_buf, key_schedule, &record)?;

                delegate.write(&self.record_buf[..len]).await?;
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
            trace!("TLS READ");
            let mut remaining = buf.len();
            // Note: Read only a single ApplicationData record for now, as we don't do any buffering.
            while remaining == buf.len() {
                let socket = &mut self.delegate;
                let key_schedule = &mut self.key_schedule;
                let record = decode_record::<Socket, CipherSuite>(
                    socket,
                    &mut self.record_buf,
                    key_schedule,
                )
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
    pub async fn close(
        self,
    ) -> Result<(TlsContext<'a, CipherSuite, RNG, Clock>, Socket), TlsError> {
        let record = ClientRecord::Alert(
            Alert::new(AlertLevel::Warning, AlertDescription::CloseNotify),
            self.opened,
        );

        let mut key_schedule = self.key_schedule;
        let mut delegate = self.delegate;
        let mut record_buf = self.record_buf;
        let rng = self.rng;
        let config = self.config;

        let (_, len) = encode_record::<CipherSuite>(&mut record_buf, &mut key_schedule, &record)?;

        delegate.write(&record_buf[..len]).await?;

        key_schedule.increment_write_counter();

        Ok((
            TlsContext::new_with_config(rng, record_buf, config),
            delegate,
        ))
    }
}
