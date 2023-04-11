/// A reference to consume bytes from the internal buffer.
#[must_use]
pub struct ReadBuffer<'a> {
    data: &'a [u8],
    consumed: usize,
    used: bool,

    decrypted_consumed: &'a mut usize,
}

impl<'a> ReadBuffer<'a> {
    #[inline]
    pub(crate) fn new(buffer: &'a [u8], decrypted_consumed: &'a mut usize) -> Self {
        Self {
            data: buffer,
            consumed: 0,
            used: false,
            decrypted_consumed,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.data.len() - self.consumed
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Consumes and returns a slice of at most `count` bytes.
    #[inline]
    pub fn take(&mut self, count: usize) -> &[u8] {
        let count = self.len().min(count);
        let start = self.consumed;
        self.consumed += count;
        self.used = true;

        &self.data[start..start + count]
    }

    /// Consumes and returns the internal buffer.
    #[inline]
    pub fn take_all(&mut self) -> &[u8] {
        self.take(self.len())
    }

    /// Drops the reference and restores internal buffer.
    #[inline]
    pub fn revert(self) {
        core::mem::forget(self);
    }
}

impl Drop for ReadBuffer<'_> {
    #[inline]
    fn drop(&mut self) {
        *self.decrypted_consumed = if self.used {
            self.consumed
        } else {
            // Consume all if dropped unused
            self.data.len()
        };
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn dropping_unused_buffer_consumes_all() {
        let mut consumed = 0;
        let buffer = [0, 1, 2, 3];

        _ = ReadBuffer::new(&buffer, &mut consumed);

        assert_eq!(consumed, 4);
    }

    #[test]
    fn take_moves_internal_cursor() {
        let mut consumed = 0;

        let mut buffer = ReadBuffer::new(&[0, 1, 2, 3], &mut consumed);

        assert_eq!(buffer.take(1), &[0]);
        assert_eq!(buffer.take(1), &[1]);
        assert_eq!(buffer.take(1), &[2]);
    }

    #[test]
    fn dropping_consumes_as_many_bytes_as_used() {
        let mut consumed = 0;

        let mut buffer = ReadBuffer::new(&[0, 1, 2, 3], &mut consumed);

        assert_eq!(buffer.take(1), &[0]);
        assert_eq!(buffer.take(1), &[1]);
        assert_eq!(buffer.take(1), &[2]);

        core::mem::drop(buffer);

        assert_eq!(consumed, 3);
    }

    #[test]
    fn take_returns_fewer_bytes_if_requested_more_than_what_it_has() {
        let mut consumed = 0;

        let mut buffer = ReadBuffer::new(&[0, 1, 2, 3], &mut consumed);

        assert_eq!(buffer.take(1), &[0]);
        assert_eq!(buffer.take(1), &[1]);
        assert_eq!(buffer.take(4), &[2, 3]);
        assert_eq!(buffer.take(1), &[]);

        core::mem::drop(buffer);

        assert_eq!(consumed, 4);
    }
}
