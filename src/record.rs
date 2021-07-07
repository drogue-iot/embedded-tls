use crate::application_data::ApplicationData;
use crate::buffer::*;
use crate::change_cipher_spec::ChangeCipherSpec;
use crate::config::{TlsCipherSuite, TlsConfig};
use crate::content_types::ContentType;
use crate::handshake::client_hello::ClientHello;
use crate::handshake::{ClientHandshake, ServerHandshake};
use crate::TlsError;
use crate::{alert::*, parse_buffer::ParseBuffer};
use core::fmt::Debug;
use core::ops::Range;
use digest::{BlockInput, FixedOutput, Reset, Update};
use generic_array::ArrayLength;
use rand_core::{CryptoRng, RngCore};
use sha2::Digest;

pub type Encrypted = bool;

pub enum ClientRecord<'config, 'a, CipherSuite>
where
    // N: ArrayLength<u8>,
    CipherSuite: TlsCipherSuite,
{
    Handshake(ClientHandshake<'config, 'a, CipherSuite>, Encrypted),
    ChangeCipherSpec(ChangeCipherSpec, Encrypted),
    Alert(Alert, Encrypted),
    ApplicationData(&'a [u8]),
}

impl<'config, 'a, CipherSuite> ClientRecord<'config, 'a, CipherSuite>
where
    //N: ArrayLength<u8>,
    CipherSuite: TlsCipherSuite,
{
    pub fn content_type(&self) -> ContentType {
        match self {
            ClientRecord::Handshake(_, false) => ContentType::Handshake,
            ClientRecord::Alert(_, false) => ContentType::ChangeCipherSpec,
            ClientRecord::ChangeCipherSpec(_, false) => ContentType::ChangeCipherSpec,
            ClientRecord::Handshake(_, true) => ContentType::ApplicationData,
            ClientRecord::Alert(_, true) => ContentType::ApplicationData,
            ClientRecord::ChangeCipherSpec(_, true) => ContentType::ApplicationData,
            ClientRecord::ApplicationData(_) => ContentType::ApplicationData,
        }
    }

    pub fn client_hello<RNG>(
        config: &'config TlsConfig<'config, CipherSuite>,
        rng: &mut RNG,
    ) -> Self
    where
        RNG: CryptoRng + RngCore,
    {
        ClientRecord::Handshake(
            ClientHandshake::ClientHello(ClientHello::new(config, rng)),
            false,
        )
    }

    pub(crate) fn encode<
        N: Update + BlockInput + FixedOutput + Reset + Default + Clone,
        F: FnMut(&mut CryptoBuffer<'_>) -> Result<usize, TlsError>,
    >(
        &self,
        enc_buf: &mut [u8],
        transcript: &mut N,
        mut encrypt_fn: F,
    ) -> Result<(usize, Option<Range<usize>>), TlsError> {
        let mut buf = CryptoBuffer::wrap(enc_buf);
        buf.push(self.content_type() as u8)
            .map_err(|_| TlsError::EncodeError)?;
        let version = match self {
            ClientRecord::Handshake(_, true) => &[0x03, 0x03],
            ClientRecord::Handshake(_, false) => &[0x03, 0x01],
            ClientRecord::ChangeCipherSpec(_, true) => &[0x03, 0x03],
            ClientRecord::ChangeCipherSpec(_, false) => &[0x03, 0x01],
            ClientRecord::Alert(_, true) => &[0x03, 0x03],
            ClientRecord::Alert(_, false) => &[0x03, 0x01],
            ClientRecord::ApplicationData(_) => &[0x03, 0x03],
        };

        buf.extend_from_slice(version)
            .map_err(|_| TlsError::EncodeError)?;

        let record_length_marker = buf.len();
        buf.push(0).map_err(|_| TlsError::EncodeError)?;
        buf.push(0).map_err(|_| TlsError::EncodeError)?;

        let (range, mut buf) = match self {
            ClientRecord::Handshake(handshake, false) => {
                let range = handshake.encode(&mut buf)?;
                (Some(range), buf)
            }
            ClientRecord::Handshake(handshake, true) => {
                let mut wrapped = buf.forward();

                let range = handshake.encode(&mut wrapped)?;
                N::update(transcript, &wrapped.as_slice()[range]);
                wrapped
                    .push(ContentType::Handshake as u8)
                    .map_err(|_| TlsError::EncodeError)?;

                let _ = encrypt_fn(&mut wrapped)?;
                (None, wrapped.rewind())
            }
            ClientRecord::ChangeCipherSpec(spec, false) => {
                spec.encode(&mut buf)?;
                (None, buf)
            }
            ClientRecord::ChangeCipherSpec(spec, true) => {
                let mut wrapped = buf.forward();

                let _ = spec.encode(&mut wrapped)?;
                wrapped
                    .push(ContentType::ChangeCipherSpec as u8)
                    .map_err(|_| TlsError::EncodeError)?;

                let _ = encrypt_fn(&mut wrapped)?;
                (None, wrapped.rewind())
            }
            ClientRecord::Alert(alert, false) => {
                alert.encode(&mut buf)?;
                (None, buf)
            }
            ClientRecord::Alert(alert, true) => {
                let mut wrapped = buf.forward();

                let _ = alert.encode(&mut wrapped)?;
                wrapped
                    .push(ContentType::Alert as u8)
                    .map_err(|_| TlsError::EncodeError)?;

                let _ = encrypt_fn(&mut wrapped)?;
                (None, wrapped.rewind())
            }

            ClientRecord::ApplicationData(data) => {
                let mut wrapped = buf.forward();
                wrapped
                    .extend_from_slice(data)
                    .map_err(|_| TlsError::EncodeError)?;
                wrapped
                    .push(ContentType::ApplicationData as u8)
                    .map_err(|_| TlsError::EncodeError)?;

                let _ = encrypt_fn(&mut wrapped)?;
                (None, wrapped.rewind())
            }
        };

        let record_length = (buf.len() as u16 - record_length_marker as u16) - 2;

        // trace!("record len {}", record_length);

        buf.set(record_length_marker, record_length.to_be_bytes()[0])
            .map_err(|_| TlsError::EncodeError)?;
        buf.set(record_length_marker + 1, record_length.to_be_bytes()[1])
            .map_err(|_| TlsError::EncodeError)?;

        Ok((buf.len(), range))
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ServerRecord<'a, N: ArrayLength<u8>> {
    Handshake(ServerHandshake<'a, N>),
    ChangeCipherSpec(ChangeCipherSpec),
    Alert(Alert),
    ApplicationData(ApplicationData<'a>),
}

pub struct RecordHeader {
    header: [u8; 5],
}

impl RecordHeader {
    pub fn content_type(&self) -> ContentType {
        // Content type already validated in read
        ContentType::of(self.header[0]).unwrap()
    }

    pub fn content_length(&self) -> usize {
        // Content lenth already validated in read
        u16::from_be_bytes([self.header[3], self.header[4]]) as usize
    }

    pub fn data(&self) -> &[u8; 5] {
        &self.header
    }

    pub fn decode(header: [u8; 5]) -> Result<RecordHeader, TlsError> {
        match ContentType::of(header[0]) {
            None => Err(TlsError::InvalidRecord),
            Some(_) => Ok(RecordHeader { header }),
        }
    }
}

impl<'a, N: ArrayLength<u8>> ServerRecord<'a, N> {
    pub fn decode<D>(
        header: RecordHeader,
        rx_buf: &'a mut [u8],
        digest: &mut D,
    ) -> Result<ServerRecord<'a, N>, TlsError>
    where
        D: Digest,
    {
        let content_length = header.content_length();
        match header.content_type() {
            ContentType::Invalid => Err(TlsError::Unimplemented),
            ContentType::ChangeCipherSpec => Ok(ServerRecord::ChangeCipherSpec(
                ChangeCipherSpec::read(&mut rx_buf[..content_length])?,
            )),
            ContentType::Alert => {
                let mut parse = ParseBuffer::from(&rx_buf[..content_length]);
                let alert = Alert::parse(&mut parse)?;
                Ok(ServerRecord::Alert(alert))
            }
            ContentType::Handshake => Ok(ServerRecord::Handshake(ServerHandshake::read(
                &mut rx_buf[..content_length],
                digest,
            )?)),
            ContentType::ApplicationData => {
                let mut buf = CryptoBuffer::wrap(rx_buf);
                buf.truncate(content_length);

                Ok(ServerRecord::ApplicationData(ApplicationData::new(
                    buf, header,
                )))
            }
        }
    }

    //pub fn parse<D: Digest>(buf: &[u8]) -> Result<Self, TlsError> {}
}
