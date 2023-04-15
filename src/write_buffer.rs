use crate::{
    buffer::CryptoBuffer,
    config::TlsCipherSuite,
    connection::encrypt,
    key_schedule::{ReadKeySchedule, WriteKeySchedule},
    record::{ClientRecord, ClientRecordHeader},
    TlsError,
};

// Some space needed by TLS record
pub const TLS_RECORD_OVERHEAD: usize = 128;

pub struct WriteBuffer<'a> {
    buffer: &'a mut [u8],
    pos: usize,
    current_header: Option<ClientRecordHeader>,
}

impl<'a> WriteBuffer<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        debug_assert!(
            buffer.len() > TLS_RECORD_OVERHEAD,
            "The write buffer must be sufficiently large to include the tls record overhead"
        );
        Self {
            buffer,
            pos: 0,
            current_header: None,
        }
    }

    fn max_block_size(&self) -> usize {
        self.buffer.len() - TLS_RECORD_OVERHEAD
    }

    pub fn is_full(&self) -> bool {
        self.pos == self.max_block_size()
    }

    pub fn append(&mut self, buf: &[u8]) -> usize {
        let buffered = usize::min(buf.len(), self.max_block_size() - self.pos);
        if buffered > 0 {
            self.buffer[self.pos..self.pos + buffered].copy_from_slice(&buf[..buffered]);
            self.pos += buffered;
        }
        buffered
    }

    pub fn len(&self) -> usize {
        self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn space(&self) -> usize {
        self.max_block_size() - self.pos
    }

    pub fn contains(&self, header: ClientRecordHeader) -> bool {
        self.current_header == Some(header)
    }

    fn with_buffer(
        &mut self,
        op: impl FnOnce(CryptoBuffer) -> Result<CryptoBuffer, TlsError>,
    ) -> Result<(), TlsError> {
        let buf = CryptoBuffer::wrap_with_pos(self.buffer, self.pos);

        match op(buf) {
            Ok(buf) => {
                self.pos = buf.len();
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    pub(crate) fn start_record(&mut self, header: ClientRecordHeader) -> Result<(), TlsError> {
        debug_assert!(self.current_header.is_none());

        debug!("start_record({:?})", header);
        self.current_header = Some(header);

        self.with_buffer(|mut buf| {
            header.encode(&mut buf)?;
            buf.push_u16(0)?;
            Ok(buf.rewind())
        })
    }

    pub(crate) fn close_record<CipherSuite>(
        &mut self,
        write_key_schedule: &mut WriteKeySchedule<CipherSuite>,
    ) -> Result<&[u8], TlsError>
    where
        CipherSuite: TlsCipherSuite,
    {
        let header = self.current_header.take().unwrap();
        self.with_buffer(|mut buf| {
            if header.is_encrypted() {
                buf.push(header.trailer_content_type() as u8)
                    .map_err(|_| TlsError::EncodeError)?;

                let mut buf = buf.offset(5);
                encrypt(write_key_schedule, &mut buf)?;
                return Ok(buf.rewind());
            }
            Ok(buf)
        })?;
        const HEADER_SIZE: u16 = 5;
        let [upper, lower] = (self.pos as u16 - HEADER_SIZE).to_be_bytes();

        self.buffer[3] = upper;
        self.buffer[4] = lower;

        let slice = &self.buffer[..self.pos];

        self.pos = 0;
        self.current_header = None;

        Ok(slice)
    }

    pub fn write_record<CipherSuite>(
        &mut self,
        record: &ClientRecord<CipherSuite>,
        write_key_schedule: &mut WriteKeySchedule<CipherSuite>,
        read_key_schedule: Option<&mut ReadKeySchedule<CipherSuite>>,
    ) -> Result<&[u8], TlsError>
    where
        CipherSuite: TlsCipherSuite,
    {
        if self.current_header.is_some() {
            return Err(TlsError::InternalError);
        }

        self.start_record(record.header())?;
        self.with_buffer(|buf| {
            let mut buf = buf.forward();
            record.encode_payload(&mut buf)?;
            record.finish_record(&mut buf, read_key_schedule, write_key_schedule)?;
            Ok(buf.rewind())
        })?;
        self.close_record(write_key_schedule)
    }
}
