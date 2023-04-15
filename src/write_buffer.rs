// Some space needed by TLS record
pub const TLS_RECORD_OVERHEAD: usize = 128;

pub struct WriteBuffer<'a> {
    pub buffer: &'a mut [u8],
    pub pos: usize,
}

impl<'a> WriteBuffer<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        debug_assert!(
            buffer.len() > TLS_RECORD_OVERHEAD,
            "The write buffer must be sufficiently large to include the tls record overhead"
        );
        Self { buffer, pos: 0 }
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
}
