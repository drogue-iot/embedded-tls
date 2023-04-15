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

    pub fn is_full(&self) -> bool {
        let max_block_size = self.buffer.len() - TLS_RECORD_OVERHEAD;
        self.pos == max_block_size
    }
}
