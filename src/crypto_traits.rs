#![cfg_attr(not(any(test, feature = "std")), no_std)]

use crate::TlsError;
use crate::config::TlsCipherSuite;
use generic_array::{ArrayLength, GenericArray};
use typenum::Unsigned;

pub trait TlsHash: Clone {
    type OutputSize: ArrayLength<u8>;
    fn new() -> Self
    where
        Self: Sized;
    fn reset(&mut self);
    fn update(&mut self, data: &[u8]);
    fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>);
    fn output_size(&self) -> usize {
        Self::OutputSize::USIZE
    }
}

pub trait TlsHmac: Clone {
    type OutputSize: ArrayLength<u8>;
    fn new(key: &[u8]) -> Result<Self, TlsError>
    where
        Self: Sized;
    fn update(&mut self, data: &[u8]);
    fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>);
    fn output_size(&self) -> usize {
        Self::OutputSize::USIZE
    }
}

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

use digest::{Digest, FixedOutput, KeyInit, Mac, OutputSizeUser, Reset};

impl<T> TlsHash for T
where
    T: Digest + Reset + Clone + OutputSizeUser + FixedOutput,
{
    type OutputSize = <T as OutputSizeUser>::OutputSize;
    fn new() -> Self {
        Digest::new()
    }
    fn reset(&mut self) {
        Digest::reset(self);
    }
    fn update(&mut self, data: &[u8]) {
        Digest::update(self, data);
    }
    fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
        out.copy_from_slice(Digest::finalize(self).as_slice());
    }
}

impl<T> TlsHmac for T
where
    T: Mac + Clone + KeyInit,
    <T as OutputSizeUser>::OutputSize: ArrayLength<u8>,
{
    type OutputSize = <T as OutputSizeUser>::OutputSize;
    fn new(key: &[u8]) -> Result<Self, TlsError> {
        Mac::new_from_slice(key).map_err(|_| TlsError::CryptoError)
    }
    fn update(&mut self, data: &[u8]) {
        Mac::update(self, data);
    }
    fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
        out.copy_from_slice(Mac::finalize(self).into_bytes().as_slice());
    }
}

use aes_gcm::{AeadInPlace, KeyInit as AeadKeyInit};

impl<T> TlsAead for T
where
    T: AeadKeyInit + AeadInPlace,
{
    fn encrypt_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), TlsError> {
        let nonce_ga = GenericArray::from_slice(nonce);
        let computed = AeadInPlace::encrypt_in_place_detached(self, nonce_ga, aad, buffer)
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
        let nonce_ga = GenericArray::from_slice(nonce);
        let tag_ga = GenericArray::from_slice(tag);
        AeadInPlace::decrypt_in_place_detached(self, nonce_ga, aad, buffer, tag_ga)
            .map_err(|_| TlsError::CryptoError)
    }
}

pub struct RustCryptoHash<C: TlsCipherSuite>(C::Hash);
impl<C: TlsCipherSuite> Clone for RustCryptoHash<C> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<C: TlsCipherSuite> TlsHash for RustCryptoHash<C> {
    type OutputSize = <C::Hash as OutputSizeUser>::OutputSize;
    fn new() -> Self {
        Self(Digest::new())
    }
    fn reset(&mut self) {
        Digest::reset(&mut self.0);
    }
    fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.0, data);
    }
    fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
        out.copy_from_slice(Digest::finalize(self.0).as_slice());
    }
}

pub struct RustCryptoAead<C: TlsCipherSuite>(C::Cipher);
impl<C: TlsCipherSuite> TlsAead for RustCryptoAead<C> {
    fn encrypt_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), crate::TlsError> {
        let nonce_ga = GenericArray::from_slice(nonce);
        let computed = AeadInPlace::encrypt_in_place_detached(&self.0, nonce_ga, aad, buffer)
            .map_err(|_| crate::TlsError::CryptoError)?;
        tag.copy_from_slice(computed.as_slice());
        Ok(())
    }
    fn decrypt_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), crate::TlsError> {
        let nonce_ga = GenericArray::from_slice(nonce);
        let tag_ga = GenericArray::from_slice(tag);
        AeadInPlace::decrypt_in_place_detached(&self.0, nonce_ga, aad, buffer, tag_ga)
            .map_err(|_| crate::TlsError::CryptoError)
    }
}
impl<C: TlsCipherSuite> RustCryptoAead<C> {
    pub fn new(key: &[u8]) -> Result<Self, crate::TlsError> {
        C::Cipher::new_from_slice(key)
            .map(Self)
            .map_err(|_| crate::TlsError::CryptoError)
    }
}
