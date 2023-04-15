use crate::application_data::ApplicationData;
use crate::buffer::*;
use crate::change_cipher_spec::ChangeCipherSpec;
use crate::config::{TlsCipherSuite, TlsConfig};
use crate::connection::encrypt;
use crate::content_types::ContentType;
use crate::handshake::client_hello::ClientHello;
use crate::handshake::{ClientHandshake, ServerHandshake};
use crate::key_schedule::{HashOutputSize, ReadKeySchedule, WriteKeySchedule};
use crate::write_buffer::WriteBuffer;
use crate::TlsError;
use crate::{alert::*, parse_buffer::ParseBuffer};
use core::fmt::Debug;
use generic_array::ArrayLength;
use rand_core::{CryptoRng, RngCore};
use sha2::Digest;
use typenum::Unsigned;

pub type Encrypted = bool;

#[allow(clippy::large_enum_variant)]
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

pub enum ClientRecordHeader {
    Handshake(Encrypted),
    ChangeCipherSpec(Encrypted),
    Alert(Encrypted),
    ApplicationData,
}

impl ClientRecordHeader {
    pub fn content_type(&self) -> ContentType {
        match self {
            Self::Handshake(false) => ContentType::Handshake,
            Self::Alert(false) => ContentType::ChangeCipherSpec,
            Self::ChangeCipherSpec(false) => ContentType::ChangeCipherSpec,
            Self::Handshake(true) => ContentType::ApplicationData,
            Self::Alert(true) => ContentType::ApplicationData,
            Self::ChangeCipherSpec(true) => ContentType::ApplicationData,
            Self::ApplicationData => ContentType::ApplicationData,
        }
    }

    pub fn version(&self) -> [u8; 2] {
        match self {
            Self::Handshake(true) => [0x03, 0x03],
            Self::Handshake(false) => [0x03, 0x01],
            Self::ChangeCipherSpec(true) => [0x03, 0x03],
            Self::ChangeCipherSpec(false) => [0x03, 0x01],
            Self::Alert(true) => [0x03, 0x03],
            Self::Alert(false) => [0x03, 0x01],
            Self::ApplicationData => [0x03, 0x03],
        }
    }

    fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.push(self.content_type() as u8)
            .map_err(|_| TlsError::EncodeError)?;
        buf.extend_from_slice(&self.version())
            .map_err(|_| TlsError::EncodeError)?;

        Ok(())
    }
}

impl<'config, 'a, CipherSuite> ClientRecord<'config, 'a, CipherSuite>
where
    //N: ArrayLength<u8>,
    CipherSuite: TlsCipherSuite,
{
    pub fn header(&self) -> ClientRecordHeader {
        match self {
            ClientRecord::Handshake(_, encrypted) => ClientRecordHeader::Handshake(*encrypted),
            ClientRecord::ChangeCipherSpec(_, encrypted) => {
                ClientRecordHeader::ChangeCipherSpec(*encrypted)
            }
            ClientRecord::Alert(_, encrypted) => ClientRecordHeader::Alert(*encrypted),
            ClientRecord::ApplicationData(_) => ClientRecordHeader::ApplicationData,
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

    pub fn close_notify(opened: bool) -> Self {
        ClientRecord::Alert(
            Alert::new(AlertLevel::Warning, AlertDescription::CloseNotify),
            opened,
        )
    }

    pub(crate) fn encode(
        &self,
        enc_buf: &mut [u8],
        read_key_schedule: Option<&mut ReadKeySchedule<CipherSuite>>,
        write_key_schedule: &mut WriteKeySchedule<CipherSuite>,
    ) -> Result<usize, TlsError> {
        let mut buf = CryptoBuffer::wrap(enc_buf);

        self.header().encode(&mut buf)?;

        let record_length_marker = buf.len();
        buf.push_u16(0).map_err(|_| TlsError::EncodeError)?;

        let mut wrapped = buf.forward();
        match self {
            ClientRecord::Handshake(handshake, false) => {
                let start = wrapped.len();
                handshake.encode(&mut wrapped)?;
                let end = wrapped.len();

                let enc_buf = &mut wrapped.as_mut_slice()[start..end];
                let transcript = read_key_schedule
                    .ok_or(TlsError::InternalError)?
                    .transcript_hash();

                if let ClientHandshake::ClientHello(hello) = handshake {
                    // Special case for PSK which needs to:
                    //
                    // 1. Add the client hello without the binders to the transcript
                    // 2. Create the binders for each identity using the transcript
                    // 3. Add the rest of the client hello.
                    //
                    // This causes a few issues since lengths must be correctly inside the payload,
                    // but won't actually be added to the record buffer until the end.
                    if let Some((_, identities)) = &hello.config.psk {
                        let binders_len =
                            identities.len() * (1 + HashOutputSize::<CipherSuite>::to_usize());

                        let binders_pos = enc_buf.len() - binders_len;

                        // NOTE: Exclude the binders_len itself from the digest
                        transcript.update(&enc_buf[0..binders_pos - 2]);

                        // Append after the client hello data. Sizes have already been set.
                        let mut buf = CryptoBuffer::wrap(&mut enc_buf[binders_pos..]);
                        // Create a binder and encode for each identity
                        for _id in identities {
                            let binder = write_key_schedule.create_psk_binder(transcript)?;
                            binder.encode(&mut buf)?;
                        }

                        transcript.update(&enc_buf[binders_pos - 2..]);
                    } else {
                        transcript.update(enc_buf);
                    }
                } else {
                    transcript.update(enc_buf);
                }
            }
            ClientRecord::Handshake(handshake, true) => {
                let transcript = read_key_schedule
                    .ok_or(TlsError::InternalError)?
                    .transcript_hash();

                let start = wrapped.len();
                handshake.encode(&mut wrapped)?;
                let end = wrapped.len();
                transcript.update(&wrapped.as_slice()[start..end]);
                wrapped
                    .push(ContentType::Handshake as u8)
                    .map_err(|_| TlsError::EncodeError)?;

                // TODO: write buffer should track written range and encrypt if the record type
                // requires it. The API should contain start_record, append and end_record fns.
                let _ = encrypt(write_key_schedule, &mut wrapped)?;
            }
            ClientRecord::ChangeCipherSpec(spec, false) => {
                spec.encode(&mut wrapped)?;
            }
            ClientRecord::ChangeCipherSpec(spec, true) => {
                spec.encode(&mut wrapped)?;
                wrapped
                    .push(ContentType::ChangeCipherSpec as u8)
                    .map_err(|_| TlsError::EncodeError)?;

                let _ = encrypt(write_key_schedule, &mut wrapped)?;
            }
            ClientRecord::Alert(alert, false) => {
                alert.encode(&mut wrapped)?;
            }
            ClientRecord::Alert(alert, true) => {
                alert.encode(&mut wrapped)?;
                wrapped
                    .push(ContentType::Alert as u8)
                    .map_err(|_| TlsError::EncodeError)?;

                let _ = encrypt(write_key_schedule, &mut wrapped)?;
            }

            ClientRecord::ApplicationData(data) => {
                wrapped
                    .extend_from_slice(data)
                    .map_err(|_| TlsError::EncodeError)?;
                wrapped
                    .push(ContentType::ApplicationData as u8)
                    .map_err(|_| TlsError::EncodeError)?;

                let _ = encrypt(write_key_schedule, &mut wrapped)?;
            }
        };
        let mut buf = wrapped.rewind();

        let record_length = (buf.len() - record_length_marker) as u16 - 2;

        // trace!("record len {}", record_length);

        buf.set_u16(record_length_marker, record_length)
            .map_err(|_| TlsError::EncodeError)?;

        Ok(buf.len())
    }
}

pub(crate) fn encode_application_data_in_place<CipherSuite>(
    write_buffer: &mut WriteBuffer,
    key_schedule: &mut WriteKeySchedule<CipherSuite>,
) -> Result<usize, TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    if write_buffer.space() < 5 {
        return Err(TlsError::EncodeError);
    }

    let enc_buf = &mut write_buffer.buffer;
    let data_len = write_buffer.pos;

    // Make room for the header
    enc_buf.copy_within(..data_len, 5);

    let mut buf = CryptoBuffer::wrap(enc_buf);

    let header = ClientRecordHeader::ApplicationData;
    header.encode(&mut buf)?;

    let record_length_marker = buf.len();
    buf.push_u16(0).map_err(|_| TlsError::EncodeError)?;

    assert_eq!(5, buf.len());

    let buf = CryptoBuffer::wrap_with_pos(enc_buf, 5 + data_len);
    let mut wrapped = buf.offset(5);
    wrapped
        .push(ContentType::ApplicationData as u8)
        .map_err(|_| TlsError::EncodeError)?;
    let _ = encrypt(key_schedule, &mut wrapped)?;

    let mut buf = wrapped.rewind();
    let record_length = (buf.len() - record_length_marker) as u16 - 2;

    buf.set_u16(record_length_marker, record_length)
        .map_err(|_| TlsError::EncodeError)?;

    Ok(buf.len())
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(clippy::large_enum_variant)]
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
    pub fn content_type(&self) -> ContentType {
        match self {
            ServerRecord::Handshake(_) => ContentType::Handshake,
            ServerRecord::ChangeCipherSpec(_) => ContentType::ChangeCipherSpec,
            ServerRecord::Alert(_) => ContentType::Alert,
            ServerRecord::ApplicationData(_) => ContentType::ApplicationData,
        }
    }

    pub fn decode<D>(
        header: RecordHeader,
        data: &'a mut [u8],
        digest: &mut D,
    ) -> Result<ServerRecord<'a, N>, TlsError>
    where
        D: Digest,
    {
        assert_eq!(header.content_length(), data.len());
        match header.content_type() {
            ContentType::Invalid => Err(TlsError::Unimplemented),
            ContentType::ChangeCipherSpec => Ok(ServerRecord::ChangeCipherSpec(
                ChangeCipherSpec::read(data)?,
            )),
            ContentType::Alert => {
                let mut parse = ParseBuffer::new(data);
                let alert = Alert::parse(&mut parse)?;
                Ok(ServerRecord::Alert(alert))
            }
            ContentType::Handshake => Ok(ServerRecord::Handshake(ServerHandshake::read(
                data, digest,
            )?)),
            ContentType::ApplicationData => {
                let buf = CryptoBuffer::wrap_with_pos(data, data.len());
                Ok(ServerRecord::ApplicationData(ApplicationData::new(
                    buf, header,
                )))
            }
        }
    }

    //pub fn parse<D: Digest>(buf: &[u8]) -> Result<Self, TlsError> {}
}
