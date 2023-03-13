use core::marker::PhantomData;

use digest::OutputSizeUser;
use embedded_io::{blocking::Read as BlockingRead, Error};

#[cfg(feature = "async")]
use embedded_io::asynch::Read as AsyncRead;

use crate::{
    config::TlsCipherSuite,
    key_schedule::KeySchedule,
    record::{RecordHeader, ServerRecord},
    TlsError,
};

pub struct RecordReader<'a, CipherSuite>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    pub(crate) buf: &'a mut [u8],
    /// The number of decoded bytes in the buffer
    decoded: usize,
    /// The number of read but not yet decoded bytes in the buffer
    pending: usize,
    cipher_suite: PhantomData<CipherSuite>,
}

impl<'a, CipherSuite> RecordReader<'a, CipherSuite>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            decoded: 0,
            pending: 0,
            cipher_suite: PhantomData,
        }
    }

    #[cfg(feature = "async")]
    pub async fn read<'m>(
        &'m mut self,
        transport: &mut impl AsyncRead,
        key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
    ) -> Result<ServerRecord<'m, <CipherSuite::Hash as OutputSizeUser>::OutputSize>, TlsError>
    where
        CipherSuite: TlsCipherSuite + 'static,
    {
        let header = self.advance(transport, 5).await?;
        let header = RecordHeader::decode(header.try_into().unwrap())?;
        let content_length = header.content_length();

        let data = self.advance(transport, content_length).await?;
        ServerRecord::decode::<CipherSuite::Hash>(header, data, key_schedule.transcript_hash())
    }

    #[cfg(feature = "async")]
    async fn advance<'m>(
        &'m mut self,
        transport: &mut impl AsyncRead,
        amount: usize,
    ) -> Result<&'m mut [u8], TlsError> {
        if self.decoded + amount > self.buf.len() {
            if amount > self.buf.len() {
                return Err(TlsError::InsufficientSpace);
            }
            self.buf
                .copy_within(self.decoded..self.decoded + self.pending, 0);
            self.decoded = 0;
        }

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

        let slice = &mut self.buf[self.decoded..self.decoded + amount];
        self.decoded += amount;
        self.pending -= amount;
        Ok(slice)
    }

    pub fn read_blocking<'m>(
        &'m mut self,
        transport: &mut impl BlockingRead,
        key_schedule: &mut KeySchedule<CipherSuite::Hash, CipherSuite::KeyLen, CipherSuite::IvLen>,
    ) -> Result<ServerRecord<'m, <CipherSuite::Hash as OutputSizeUser>::OutputSize>, TlsError>
    where
        CipherSuite: TlsCipherSuite + 'static,
    {
        let header = self.advance_blocking(transport, 5)?;
        let header = RecordHeader::decode(header.try_into().unwrap())?;
        let content_length = header.content_length();

        let data = self.advance_blocking(transport, content_length)?;
        ServerRecord::decode::<CipherSuite::Hash>(header, data, key_schedule.transcript_hash())
    }

    fn advance_blocking<'m>(
        &'m mut self,
        transport: &mut impl BlockingRead,
        amount: usize,
    ) -> Result<&'m mut [u8], TlsError> {
        if self.decoded + amount > self.buf.len() {
            if amount > self.buf.len() {
                return Err(TlsError::InsufficientSpace);
            }
            self.buf
                .copy_within(self.decoded..self.decoded + self.pending, 0);
            self.decoded = 0;
        }

        while self.pending < amount {
            let read = transport
                .read(&mut self.buf[self.decoded + self.pending..])
                .map_err(|e| TlsError::Io(e.kind()))?;
            if read == 0 {
                return Err(TlsError::IoError);
            }
            self.pending += read;
        }

        let slice = &mut self.buf[self.decoded..self.decoded + amount];
        self.decoded += amount;
        self.pending -= amount;
        Ok(slice)
    }
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use super::*;
    use crate::{content_types::ContentType, Aes128GcmSha256, TlsCipherSuite};

    struct ChunkRead<'a>(&'a [u8], usize);

    impl embedded_io::Io for ChunkRead<'_> {
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
        let mut reader = RecordReader::<Aes128GcmSha256>::new(&mut buf);
        let mut key_schedule = KeySchedule::<
            <Aes128GcmSha256 as TlsCipherSuite>::Hash,
            <Aes128GcmSha256 as TlsCipherSuite>::KeyLen,
            <Aes128GcmSha256 as TlsCipherSuite>::IvLen,
        >::new();

        {
            if let ServerRecord::ApplicationData(data) = reader
                .read_blocking(&mut transport, &mut key_schedule)
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
                .read_blocking(&mut transport, &mut key_schedule)
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

        let mut buf = [0; 5]; // This buffer is so small that it cannot contain both the header and data
        let mut reader = RecordReader::<Aes128GcmSha256>::new(&mut buf);
        let mut key_schedule = KeySchedule::<
            <Aes128GcmSha256 as TlsCipherSuite>::Hash,
            <Aes128GcmSha256 as TlsCipherSuite>::KeyLen,
            <Aes128GcmSha256 as TlsCipherSuite>::IvLen,
        >::new();

        {
            if let ServerRecord::ApplicationData(data) = reader
                .read_blocking(&mut transport, &mut key_schedule)
                .unwrap()
            {
                assert_eq!([0xde, 0xad, 0xbe, 0xef], data.data.as_slice());
            } else {
                panic!("Wrong server record");
            }

            assert_eq!(4, reader.decoded); // The buffer is rotated after decoding the header
            assert_eq!(1, reader.pending);
        }

        {
            if let ServerRecord::ApplicationData(data) = reader
                .read_blocking(&mut transport, &mut key_schedule)
                .unwrap()
            {
                assert_eq!([0xaa, 0xbb], data.data.as_slice());
            } else {
                panic!("Wrong server record");
            }

            assert_eq!(2, reader.decoded);
            assert_eq!(0, reader.pending);
        }
    }
}