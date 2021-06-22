use aes_gcm::aead::Buffer;
use aes_gcm::Error;
use generic_array::ArrayLength;
use heapless::Vec;

pub(crate) struct CryptoBuffer<'b, N: ArrayLength<u8>>(&'b mut Vec<u8, N>);

impl<'b, N: ArrayLength<u8>> CryptoBuffer<'b, N> {
    pub(crate) fn wrap(buf: &'b mut Vec<u8, N>) -> Self {
        Self(buf)
    }
}

impl<'b, N: ArrayLength<u8>> AsRef<[u8]> for CryptoBuffer<'b, N> {
    fn as_ref(&self) -> &[u8] {
        &*self.0
    }
}

impl<'b, N: ArrayLength<u8>> AsMut<[u8]> for CryptoBuffer<'b, N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<'b, N: ArrayLength<u8>> Buffer for CryptoBuffer<'b, N> {
    fn extend_from_slice(&mut self, other: &[u8]) -> Result<(), Error> {
        (&mut *self.0).extend_from_slice(other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len);
    }
}
