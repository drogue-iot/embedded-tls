use crate::application_data::ApplicationData;
use crate::buffer::*;
use crate::change_cipher_spec::ChangeCipherSpec;
use crate::config::{TlsCipherSuite, TlsConfig};
use crate::content_types::ContentType;
use crate::handshake::client_hello::ClientHello;
use crate::handshake::{ClientHandshake, ServerHandshake};
use crate::key_schedule::{HashOutputSize, WriteKeySchedule};
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

#[derive(Clone, Copy, PartialEq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ClientRecordHeader {
    Handshake(Encrypted),
    ChangeCipherSpec(Encrypted),
    Alert(Encrypted),
    ApplicationData,
}

impl ClientRecordHeader {
    pub fn is_encrypted(&self) -> bool {
        match self {
            ClientRecordHeader::Handshake(encrypted)
            | ClientRecordHeader::ChangeCipherSpec(encrypted)
            | ClientRecordHeader::Alert(encrypted) => *encrypted,
            ClientRecordHeader::ApplicationData => true,
        }
    }

    pub fn header_content_type(&self) -> ContentType {
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

    pub fn trailer_content_type(&self) -> ContentType {
        match self {
            Self::Handshake(_) => ContentType::Handshake,
            Self::Alert(_) => ContentType::ChangeCipherSpec,
            Self::ChangeCipherSpec(_) => ContentType::ChangeCipherSpec,
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

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.push(self.header_content_type() as u8)
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

    pub(crate) fn encode_payload(&self, buf: &mut CryptoBuffer) -> Result<usize, TlsError> {
        let record_length_marker = buf.len();

        match self {
            ClientRecord::Handshake(handshake, _) => handshake.encode(buf)?,
            ClientRecord::ChangeCipherSpec(spec, _) => spec.encode(buf)?,
            ClientRecord::Alert(alert, _) => alert.encode(buf)?,

            ClientRecord::ApplicationData(data) => buf
                .extend_from_slice(data)
                .map_err(|_| TlsError::EncodeError)?,
        };

        Ok(buf.len() - record_length_marker)
    }

    pub fn finish_record(
        &self,
        buf: &mut CryptoBuffer,
        transcript: &mut CipherSuite::Hash,
        write_key_schedule: &mut WriteKeySchedule<CipherSuite>,
    ) -> Result<(), TlsError> {
        match self {
            ClientRecord::Handshake(handshake, false) => {
                let enc_buf = buf.as_mut_slice();
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
            ClientRecord::Handshake(_, true) => {
                let enc_buf = buf.as_slice();
                let end = enc_buf.len();
                // Don't include the content type in the slice
                transcript.update(&enc_buf[0..end - 1]);
            }
            _ => {}
        };

        Ok(())
    }
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
