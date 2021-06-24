use aes_gcm::aead::Buffer;
use aes_gcm::Error;

pub struct CryptoBuffer<'b> {
    buf: &'b mut [u8],
    capacity: usize,
    offset: usize,
    len: usize,
}

impl<'b> CryptoBuffer<'b> {
    pub(crate) fn wrap(buf: &'b mut [u8]) -> Self {
        Self {
            capacity: buf.len(),
            buf,
            offset: 0,
            len: 0,
        }
    }

    pub(crate) fn wrap_with_pos(buf: &'b mut [u8], pos: usize) -> Self {
        Self {
            capacity: buf.len(),
            buf,
            offset: 0,
            len: pos,
        }
    }

    pub fn push(&mut self, b: u8) -> Result<(), ()> {
        if self.capacity - (self.len + self.offset) > 0 {
            self.buf[self.offset + self.len] = b;
            self.len += 1;
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn set(&mut self, idx: usize, val: u8) -> Result<(), ()> {
        if idx < self.len {
            self.buf[self.offset + idx] = val;
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn as_mut_slice<'m>(&'m mut self) -> &'m mut [u8] {
        &mut self.buf[self.offset..self.offset + self.len]
    }

    pub fn as_slice<'m>(&'m self) -> &'m [u8] {
        &self.buf[self.offset..self.offset + self.len]
    }

    fn extend_internal(&mut self, other: &[u8]) -> Result<(), ()> {
        let start = self.offset + self.len;
        if self.capacity - start < other.len() {
            Err(())
        } else {
            self.buf[start..start + other.len()].clone_from_slice(&other[..other.len()]);
            self.len += other.len();
            Ok(())
        }
    }

    pub fn extend_from_slice(&mut self, other: &[u8]) -> Result<(), ()> {
        self.extend_internal(other)
    }

    fn truncate_internal(&mut self, len: usize) {
        if len <= self.capacity - self.offset {
            self.len = len;
        }
    }

    pub fn truncate(&mut self, len: usize) {
        self.truncate_internal(len)
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn release(self) -> &'b mut [u8] {
        self.buf
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn forward(self) -> CryptoBuffer<'b> {
        let len = self.len;
        self.offset(len)
    }

    pub fn rewind(self) -> CryptoBuffer<'b> {
        self.offset(0)
    }

    pub(crate) fn offset(self, offset: usize) -> CryptoBuffer<'b> {
        let new_len = if offset > self.offset {
            self.len - (offset - self.offset)
        } else {
            self.len + (self.offset - offset)
        };
        info!(
            "offset({}) len({}) -> offset({}), len({})",
            self.offset, self.len, offset, new_len
        );
        CryptoBuffer {
            buf: self.buf,
            len: new_len,
            capacity: self.capacity,
            offset,
        }
    }
}

impl<'b> AsRef<[u8]> for CryptoBuffer<'b> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<'b> AsMut<[u8]> for CryptoBuffer<'b> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl<'b> Buffer for CryptoBuffer<'b> {
    fn extend_from_slice(&mut self, other: &[u8]) -> Result<(), Error> {
        self.extend_internal(other).map_err(|_| Error)
    }

    fn truncate(&mut self, len: usize) {
        self.truncate_internal(len)
    }
}

#[cfg(test)]
mod test {
    use super::CryptoBuffer;

    #[test]
    fn offset_calc() {
        let mut buf = [0; 8];
        let mut c = CryptoBuffer::wrap(&mut buf);
        c.push(1).unwrap();
        c.push(2).unwrap();
        c.push(3).unwrap();

        assert_eq!(&[1, 2, 3], c.as_slice());

        let l = c.len();
        let mut c = c.offset(l);

        c.push(4).unwrap();
        c.push(5).unwrap();
        c.push(6).unwrap();

        assert_eq!(&[4, 5, 6], c.as_slice());

        let mut c = c.offset(0);

        c.push(7).unwrap();
        c.push(8).unwrap();

        assert_eq!(&[1, 2, 3, 4, 5, 6, 7, 8], c.as_slice());

        let mut c = c.offset(6);
        c.set(0, 14).unwrap();
        c.set(1, 15).unwrap();

        let c = c.offset(0);
        assert_eq!(&[1, 2, 3, 4, 5, 6, 14, 15], c.as_slice());

        let mut c = c.offset(4);
        c.truncate(0);
        c.extend_from_slice(&[10, 11, 12, 13]).unwrap();
        assert_eq!(&[10, 11, 12, 13], c.as_slice());

        let c = c.offset(0);
        assert_eq!(&[1, 2, 3, 4, 10, 11, 12, 13], c.as_slice());
    }
}
