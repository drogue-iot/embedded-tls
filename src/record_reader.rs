use crate::key_schedule::ReadKeySchedule;
use embedded_io::{Error, Read as BlockingRead};
use embedded_io_async::Read as AsyncRead;

use crate::{
    config::TlsCipherSuite,
    record::{RecordHeader, ServerRecord},
    TlsError,
};

pub struct RecordReader<'a> {
    pub(crate) buf: &'a mut [u8],
    /// The number of decoded bytes in the buffer
    decoded: usize,
    /// The number of read but not yet decoded bytes in the buffer
    pending: usize,
}

impl<'a> RecordReader<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        if buf.len() < 16640 {
            warn!("Read buffer is smaller than 16640 bytes, which may cause problems!");
        }
        Self {
            buf,
            decoded: 0,
            pending: 0,
        }
    }

    pub async fn read<'m, CipherSuite: TlsCipherSuite>(
        &'m mut self,
        transport: &mut impl AsyncRead,
        key_schedule: &mut ReadKeySchedule<CipherSuite>,
    ) -> Result<ServerRecord<'m, CipherSuite>, TlsError> {
        self.advance(transport, RecordHeader::LEN).await?;
        let header = self.record_header()?;
        self.advance(transport, RecordHeader::LEN + header.content_length())
            .await?;
        self.consume(header, key_schedule.transcript_hash())
    }

    async fn advance<'m>(
        &'m mut self,
        transport: &mut impl AsyncRead,
        amount: usize,
    ) -> Result<(), TlsError> {
        self.ensure_contiguous(amount)?;

        while self.pending < amount {
            let read = transport
                .read(&mut self.buf[self.decoded + self.pending..])
                .await
                .map_err(|e| TlsError::Io(e.kind()))?;
            if read == 0 {
                return Err(TlsError::IoError);
            }
            self.pending += read;
        }

        Ok(())
    }

    pub fn read_blocking<'m, CipherSuite: TlsCipherSuite>(
        &'m mut self,
        transport: &mut impl BlockingRead,
        key_schedule: &mut ReadKeySchedule<CipherSuite>,
    ) -> Result<ServerRecord<'m, CipherSuite>, TlsError> {
        self.advance_blocking(transport, RecordHeader::LEN)?;
        let header = self.record_header()?;
        self.advance_blocking(transport, RecordHeader::LEN + header.content_length())?;
        self.consume(header, key_schedule.transcript_hash())
    }

    fn advance_blocking<'m>(
        &'m mut self,
        transport: &mut impl BlockingRead,
        amount: usize,
    ) -> Result<(), TlsError> {
        self.ensure_contiguous(amount)?;

        while self.pending < amount {
            let read = transport
                .read(&mut self.buf[self.decoded + self.pending..])
                .map_err(|e| TlsError::Io(e.kind()))?;
            if read == 0 {
                return Err(TlsError::IoError);
            }
            self.pending += read;
        }

        Ok(())
    }

    fn record_header(&self) -> Result<RecordHeader, TlsError> {
        RecordHeader::decode(unwrap!(self.buf
            [self.decoded..self.decoded + RecordHeader::LEN]
            .try_into()
            .ok()))
    }

    fn consume<'m, CipherSuite: TlsCipherSuite>(
        &'m mut self,
        header: RecordHeader,
        digest: &mut CipherSuite::Hash,
    ) -> Result<ServerRecord<'m, CipherSuite>, TlsError> {
        let content_len = header.content_length();

        let slice = &mut self.buf
            [self.decoded + RecordHeader::LEN..self.decoded + RecordHeader::LEN + content_len];

        self.decoded += RecordHeader::LEN + content_len;
        self.pending -= RecordHeader::LEN + content_len;

        ServerRecord::decode(header, slice, digest)
    }

    fn ensure_contiguous(&mut self, len: usize) -> Result<(), TlsError> {
        if self.decoded + len > self.buf.len() {
            if len > self.buf.len() {
                error!(
                    "Record too large for buffer. Size: {} Buffer size: {}",
                    len,
                    self.buf.len()
                );
                return Err(TlsError::InsufficientSpace);
            }
            self.buf
                .copy_within(self.decoded..self.decoded + self.pending, 0);
            self.decoded = 0;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use super::*;
    use crate::{content_types::ContentType, key_schedule::KeySchedule, Aes128GcmSha256};

    struct ChunkRead<'a>(&'a [u8], usize);

    impl embedded_io::ErrorType for ChunkRead<'_> {
        type Error = Infallible;
    }

    impl BlockingRead for ChunkRead<'_> {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            let len = usize::min(self.1, buf.len());
            let len = usize::min(len, self.0.len());
            buf[..len].copy_from_slice(&self.0[..len]);
            self.0 = &self.0[len..];
            Ok(len)
        }
    }

    #[test]
    fn can_read_blocking() {
        can_read_blocking_case(1, 0);
        can_read_blocking_case(2, 1);
        can_read_blocking_case(3, 0);
        can_read_blocking_case(4, 3);
        can_read_blocking_case(5, 1);
        can_read_blocking_case(6, 3);
        can_read_blocking_case(7, 5);
        can_read_blocking_case(8, 7);
        can_read_blocking_case(9, 0);
        can_read_blocking_case(10, 1);
        can_read_blocking_case(11, 2);
        can_read_blocking_case(12, 3);
        can_read_blocking_case(13, 4);
        can_read_blocking_case(14, 5);
        can_read_blocking_case(15, 6);
        can_read_blocking_case(16, 7);
    }

    fn can_read_blocking_case(chunk_size: usize, expected_pending: usize) {
        let mut transport = ChunkRead(
            &[
                // Header
                ContentType::ApplicationData as u8,
                0x03,
                0x03,
                0x00,
                0x04,
                // Data
                0xde,
                0xad,
                0xbe,
                0xef,
                // Header
                ContentType::ApplicationData as u8,
                0x03,
                0x03,
                0x00,
                0x02,
                // Data
                0xaa,
                0xbb,
            ],
            chunk_size,
        );

        let mut buf = [0; 32];
        let mut reader = RecordReader::new(&mut buf);
        let mut key_schedule = KeySchedule::<Aes128GcmSha256>::new();

        {
            if let ServerRecord::ApplicationData(data) = reader
                .read_blocking(&mut transport, key_schedule.read_state())
                .unwrap()
            {
                assert_eq!([0xde, 0xad, 0xbe, 0xef], data.data.as_slice());
            } else {
                panic!("Wrong server record");
            }

            assert_eq!(9, reader.decoded);
            assert_eq!(expected_pending, reader.pending);
        }

        {
            if let ServerRecord::ApplicationData(data) = reader
                .read_blocking(&mut transport, key_schedule.read_state())
                .unwrap()
            {
                assert_eq!([0xaa, 0xbb], data.data.as_slice());
            } else {
                panic!("Wrong server record");
            }

            assert_eq!(16, reader.decoded);
            assert_eq!(0, reader.pending);
        }
    }

    #[test]
    fn can_read_blocking_must_rotate_buffer() {
        let mut transport = [
            // Header
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            0x00,
            0x04,
            // Data
            0xde,
            0xad,
            0xbe,
            0xef,
            // Header
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            0x00,
            0x02,
            // Data
            0xaa,
            0xbb,
        ]
        .as_slice();

        let mut buf = [0; 9]; // This buffer is so small that it cannot contain both the header and data
        let mut reader = RecordReader::new(&mut buf);
        let mut key_schedule = KeySchedule::<Aes128GcmSha256>::new();

        {
            if let ServerRecord::ApplicationData(data) = reader
                .read_blocking(&mut transport, key_schedule.read_state())
                .unwrap()
            {
                assert_eq!([0xde, 0xad, 0xbe, 0xef], data.data.as_slice());
            } else {
                panic!("Wrong server record");
            }

            assert_eq!(9, reader.decoded); // The buffer is rotated after decoding the header
            assert_eq!(0, reader.pending);
        }

        {
            if let ServerRecord::ApplicationData(data) = reader
                .read_blocking(&mut transport, key_schedule.read_state())
                .unwrap()
            {
                assert_eq!([0xaa, 0xbb], data.data.as_slice());
            } else {
                panic!("Wrong server record");
            }

            assert_eq!(7, reader.decoded);
            assert_eq!(0, reader.pending);
        }
    }

    #[test]
    fn can_read_empty_record() {
        let mut transport = [
            // Header
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            0x00,
            0x00,
            // Data
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            0x00,
            0x00,
            // Data
        ]
        .as_slice();

        let mut buf = [0; 32];
        let mut reader = RecordReader::new(&mut buf);
        let mut key_schedule = KeySchedule::<Aes128GcmSha256>::new();

        {
            if let ServerRecord::ApplicationData(data) = reader
                .read_blocking(&mut transport, key_schedule.read_state())
                .unwrap()
            {
                assert!(data.data.is_empty());
            } else {
                panic!("Wrong server record");
            }

            assert_eq!(5, reader.decoded);
            assert_eq!(5, reader.pending);
        }

        {
            if let ServerRecord::ApplicationData(data) = reader
                .read_blocking(&mut transport, key_schedule.read_state())
                .unwrap()
            {
                assert!(data.data.is_empty());
            } else {
                panic!("Wrong server record");
            }

            assert_eq!(10, reader.decoded);
            assert_eq!(0, reader.pending);
        }
    }
}
