use crate::TlsError;
use aead::inout::InOutBuf;
use aead::{AeadInOut, KeyInit, Nonce, Tag};

/// Hardware-abstracted AEAD for record encryption.
///
/// This trait uses raw slices to avoid coupling to a specific `aead` crate version.
pub trait TlsAead {
    fn encrypt_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), TlsError>;
    fn decrypt_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), TlsError>;
}

/// Wrapper that bridges `aead` 0.6's `AeadInOut` to the `TlsAead` raw-slice interface.
pub struct AesGcmAead<C>(C);

impl<C: AeadInOut + KeyInit> AesGcmAead<C> {
    pub fn new(key: &[u8]) -> Result<Self, crate::TlsError> {
        C::new_from_slice(key)
            .map(Self)
            .map_err(|_| crate::TlsError::CryptoError)
    }
}

impl<C: AeadInOut + KeyInit> TlsAead for AesGcmAead<C> {
    fn encrypt_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), TlsError> {
        let nonce_arr = &Nonce::<C>::try_from(nonce).map_err(|_| TlsError::CryptoError)?;
        let buf = InOutBuf::from(buffer);
        let computed = self
            .0
            .encrypt_inout_detached(nonce_arr, aad, buf)
            .map_err(|_| TlsError::CryptoError)?;
        tag.copy_from_slice(computed.as_slice());
        Ok(())
    }

    fn decrypt_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), TlsError> {
        let nonce_arr = &Nonce::<C>::try_from(nonce).map_err(|_| TlsError::CryptoError)?;
        let tag_arr = &Tag::<C>::try_from(tag).map_err(|_| TlsError::CryptoError)?;
        let buf = InOutBuf::from(buffer);
        self.0
            .decrypt_inout_detached(nonce_arr, aad, buf, tag_arr)
            .map_err(|_| TlsError::CryptoError)
    }
}
