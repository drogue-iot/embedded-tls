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
        error!("[DIAG] AesGcmAead::new called with key len={}", key.len());
        C::new_from_slice(key).map(Self).map_err(|e| {
            error!(
                "[DIAG] AesGcmAead::new failed: key len={}, error={:?}",
                key.len(),
                e
            );
            crate::TlsError::CryptoError
        })
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
        error!(
            "[DIAG] encrypt_in_place: nonce_len={}, buf_len={}, tag_len={}",
            nonce.len(),
            buffer.len(),
            tag.len()
        );
        let nonce_arr = &Nonce::<C>::try_from(nonce).map_err(|e| {
            error!(
                "[DIAG] encrypt nonce conversion failed: nonce_len={}, err={:?}",
                nonce.len(),
                e
            );
            TlsError::CryptoError
        })?;
        let buf = InOutBuf::from(buffer);
        let computed = self
            .0
            .encrypt_inout_detached(nonce_arr, aad, buf)
            .map_err(|e| {
                error!("[DIAG] encrypt_inout_detached failed: err={:?}", e);
                TlsError::CryptoError
            })?;
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
        error!(
            "[DIAG] decrypt_in_place: nonce_len={}, buf_len={}, tag_len={}",
            nonce.len(),
            buffer.len(),
            tag.len()
        );
        let nonce_arr = &Nonce::<C>::try_from(nonce).map_err(|e| {
            error!(
                "[DIAG] decrypt nonce conversion failed: nonce_len={}, err={:?}",
                nonce.len(),
                e
            );
            TlsError::CryptoError
        })?;
        let tag_arr = &Tag::<C>::try_from(tag).map_err(|e| {
            error!(
                "[DIAG] decrypt tag conversion failed: tag_len={}, err={:?}",
                tag.len(),
                e
            );
            TlsError::CryptoError
        })?;
        let buf = InOutBuf::from(buffer);
        self.0
            .decrypt_inout_detached(nonce_arr, aad, buf, tag_arr)
            .map_err(|e| {
                error!("[DIAG] decrypt_inout_detached failed: err={:?}", e);
                TlsError::CryptoError
            })
    }
}
