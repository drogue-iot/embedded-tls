pub struct RecordBuffer<'d> {
    buf: &'d mut [u8],
}
impl<'d> RecordBuffer<'d> {
    pub fn new(buf: &'d mut [u8]) -> Self {
        Self { buf }
    }

    pub fn fill_blocking<R: BlockingRead>(&mut self, io: &mut R) -> Result<(), TlsError> {
        let mut pos: usize = 0;
        let mut header: [u8; 5] = [0; 5];
        loop {
            pos += transport
                .read(&mut header[pos..5])
                .map_err(|e| TlsError::Io(e.kind()))?;
            if pos == 5 {
                break;
            }
        }
        let header = RecordHeader::decode(header)?;

        let content_length = header.content_length();
        if content_length > rx_buf.len() {
            return Err(TlsError::InsufficientSpace);
        }

        let mut pos = 0;
        while pos < content_length {
            let read = transport
                .read(&mut rx_buf[pos..content_length])
                .map_err(|_| TlsError::InvalidRecord)?;
            pos += read;
        }
        Ok(())
    }

    #[cfg(feature = "async")]
    pub async fn fill<R: AsyncRead>(&mut self, io: &mut R) -> Result<(), TlsError> {
        let mut pos: usize = 0;
        let mut header: [u8; 5] = [0; 5];
        loop {
            pos += io
                .read(&mut header[pos..5])
                .await
                .map_err(|e| TlsError::Io(e.kind()))?;
            if pos == 5 {
                break;
            }
        }
        let header = RecordHeader::decode(header)?;

        let content_length = header.content_length();
        if content_length > rx_buf.len() {
            return Err(TlsError::InsufficientSpace);
        }

        let mut pos = 0;
        while pos < content_length {
            let read = io
                .read(&mut rx_buf[pos..content_length])
                .await
                .map_err(|_| TlsError::InvalidRecord)?;
            pos += read;
        }
        Ok(())
    }
}
