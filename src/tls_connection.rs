use crate::alert::*;
use crate::config::{TlsCipherSuite, TlsConfig, TlsContext};
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
// use crate::handshake::certificate_request::CertificateRequest;
// use crate::handshake::certificate_verify::CertificateVerify;
// use crate::handshake::encrypted_extensions::EncryptedExtensions;
// use crate::handshake::finished::Finished;
// use crate::handshake::new_session_ticket::NewSessionTicket;
// use crate::handshake::server_hello::ServerHello;
use heapless::spsc::Queue;

// Some space needed by TLS record
const TLS_RECORD_OVERHEAD: usize = 128;

pub struct TlsConnection<'a, RNG, Socket, CipherSuite>
where
    RNG: CryptoRng + RngCore + 'static,
    Socket: AsyncRead + AsyncWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    delegate: Socket,
    rng: RNG,
    config: TlsConfig<'a, CipherSuite>,
    key_schedule: KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
    record_buf: &'a mut [u8],
    opened: bool,
}

impl<'a, RNG, Socket, CipherSuite> TlsConnection<'a, RNG, Socket, CipherSuite>
where
    RNG: CryptoRng + RngCore + 'static,
    Socket: AsyncRead + AsyncWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    /// Create a new TLS connection with the provided config, a random generator and a async I/O implementation
    pub fn new(context: TlsContext<'a, CipherSuite, RNG>, delegate: Socket) -> Self {
        Self {
            delegate,
            config: context.config,
            rng: context.rng,
            opened: false,
            key_schedule: KeySchedule::new(),
            record_buf: context.record_buf,
        }
    }

    /// Open a TLS connection, performing the handshake with the configuration provided when creating
    /// the connection instance.
    ///
    /// Returns an error if the handshake does not proceed. If an error occurs, the connection instance
    /// must be recreated.
    pub async fn open<'m>(&mut self) -> Result<(), TlsError>
    where
        'a: 'm,
    {
        let mut handshake: Handshake<CipherSuite> = Handshake::new();
        let mut state = State::ClientHello;

        loop {
            let next_state = state
                .process(
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
            let mut wp = 0;
            let mut remaining = buf.len();

            let max_block_size = self.record_buf.len() - TLS_RECORD_OVERHEAD;
            while remaining > 0 {
                let delegate = &mut self.delegate;
                let frame_buf = &mut self.record_buf;
                let key_schedule = &mut self.key_schedule;
                let to_write = core::cmp::min(remaining, max_block_size);
                let record: ClientRecord<'a, '_, CipherSuite> =
                    ClientRecord::ApplicationData(&buf[wp..to_write]);
                let trans = transmit(delegate, frame_buf, key_schedule, &record, false);
                trans.await?;
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
                    fetch_record::<Socket, CipherSuite>(socket, &mut self.record_buf, key_schedule)
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
    pub async fn close(self) -> Result<(TlsContext<'a, CipherSuite, RNG>, Socket), TlsError> {
        let record = if self.opened {
            ClientRecord::Alert(
                Alert::new(AlertLevel::Warning, AlertDescription::CloseNotify),
                true,
            )
        } else {
            ClientRecord::Alert(
                Alert::new(AlertLevel::Warning, AlertDescription::CloseNotify),
                false,
            )
        };

        let mut key_schedule = self.key_schedule;
        let mut delegate = self.delegate;
        let mut record_buf = self.record_buf;
        let rng = self.rng;
        let config = self.config;

        transmit::<Socket, CipherSuite>(
            &mut delegate,
            &mut record_buf,
            &mut key_schedule,
            &record,
            false,
        )
        .await?;

        Ok((
            TlsContext::new_with_config(rng, record_buf, config),
            delegate,
        ))
    }
}
