use aes_gcm::aead::Buffer;
use aes_gcm::Error;

pub(crate) struct CryptoBuffer<'b> {
    buf: &'b mut [u8],
    capacity: usize,
    len: usize,
}

impl<'b> CryptoBuffer<'b> {
    pub(crate) fn wrap(buf: &'b mut [u8]) -> Self {
        Self {
            capacity: buf.len(),
            buf,
            len: 0,
        }
    }

    pub fn push(&mut self, b: u8) -> Result<(), ()> {
        if self.capacity - self.len > 0 {
            self.buf[self.len] = b;
            self.len += 1;
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn set(&mut self, idx: usize, val: u8) -> Result<(), ()> {
        if idx < self.len {
            self.buf[idx] = val;
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn extend_from_slice(&mut self, other: &[u8]) -> Result<(), ()> {
        if self.capacity - self.len < other.len() {
            Err(())
        } else {
            self.buf[self.len..self.len + other.len()].clone_from_slice(&other[..other.len()]);
            self.len += other.len();
            Ok(())
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn release(mut self) -> &'b mut [u8] {
        self.buf
    }
}

impl<'b> AsRef<[u8]> for CryptoBuffer<'b> {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl<'b> AsMut<[u8]> for CryptoBuffer<'b> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.len]
    }
}

impl<'b> Buffer for CryptoBuffer<'b> {
    fn extend_from_slice(&mut self, other: &[u8]) -> Result<(), Error> {
        if self.capacity - self.len < other.len() {
            Err(Error)
        } else {
            self.buf[self.len..self.len + other.len()].clone_from_slice(&other[..other.len()]);
            self.len += other.len();
            Ok(())
        }
    }

    fn truncate(&mut self, len: usize) {
        if len <= self.buf.len() {
            self.len = len;
        }
    }
}
