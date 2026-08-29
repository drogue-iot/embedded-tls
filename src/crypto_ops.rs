//! Abstraction traits for HMAC, HKDF, Cipher, and Hash operations.
//!
//! These traits allow the TLS cipher suite to use either software (`RustCrypto`)
//! or hardware-accelerated implementations.

use crate::TlsError;
use digest::generic_array::{ArrayLength, GenericArray};
use typenum::Unsigned;

/// Buffer abstraction for cipher encrypt/decrypt operations.
pub trait TlsBuffer {
    fn as_slice(&self) -> &[u8];
    fn as_mut_slice(&mut self) -> &mut [u8];
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn extend_from_slice(&mut self, other: &[u8]) -> Result<(), TlsError>;
    fn truncate(&mut self, len: usize);
    fn capacity(&self) -> usize;
}

/// AEAD cipher abstraction for TLS record encryption/decryption.
pub trait TlsCipher: Sized {
    type KeySize: ArrayLength<u8>;
    type NonceSize: ArrayLength<u8>;
    type TagSize: ArrayLength<u8> + Unsigned;

    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self;
    fn encrypt_in_place<B: TlsBuffer>(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        aad: &[u8],
        buffer: &mut B,
    ) -> Result<(), TlsError>;
    fn decrypt_in_place<B: TlsBuffer>(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        aad: &[u8],
        buffer: &mut B,
    ) -> Result<(), TlsError>;
    #[must_use]
    fn tag_size() -> usize {
        Self::TagSize::to_usize()
    }
}

/// Hash abstraction for TLS transcript hashing.
pub trait TlsHash: Clone + Sized {
    type OutputSize: ArrayLength<u8>;
    fn new() -> Self;
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> GenericArray<u8, Self::OutputSize>;
    #[must_use]
    fn chain_update(mut self, data: &[u8]) -> Self {
        self.update(data);
        self
    }
}

/// HMAC abstraction for TLS key schedule operations.
pub trait TlsHmac: Sized {
    /// Output size of the HMAC (matches the underlying hash output size).
    type OutputSize: ArrayLength<u8>;

    /// Create a new HMAC instance from a key slice.
    fn new_from_slice(key: &[u8]) -> Result<Self, TlsError>;

    /// Feed data into the HMAC.
    fn update(&mut self, data: &[u8]);

    /// Finalize the HMAC and return the tag.
    fn finalize(self) -> GenericArray<u8, Self::OutputSize>;

    /// Finalize and verify the HMAC against an expected tag.
    fn verify(self, tag: &GenericArray<u8, Self::OutputSize>) -> Result<(), TlsError>;
}

/// HKDF abstraction for TLS key derivation.
pub trait TlsHkdf: Sized {
    /// Output size of the underlying hash / PRK.
    type OutputSize: ArrayLength<u8>;

    /// HKDF-Extract: derive a PRK from salt and input keying material.
    fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> (GenericArray<u8, Self::OutputSize>, Self);

    /// Create an HKDF instance from an existing PRK.
    fn from_prk(prk: &[u8]) -> Result<Self, TlsError>;

    /// HKDF-Expand: expand the PRK with `info` into `output`.
    fn expand(&self, info: &[u8], output: &mut [u8]) -> Result<(), TlsError>;
}

// --- Software implementations wrapping RustCrypto ---

use aes_gcm::aead::{AeadCore, AeadInPlace, KeyInit};
use digest::core_api::BlockSizeUser;
use digest::{Digest, FixedOutput, OutputSizeUser, Reset};
use hmac::{Mac, SimpleHmac};

/// Software HMAC implementation using `hmac::SimpleHmac`.
pub struct SoftwareHmac<H: Digest + BlockSizeUser>(SimpleHmac<H>);

impl<H> TlsHmac for SoftwareHmac<H>
where
    H: Digest + BlockSizeUser + Clone + Reset + FixedOutput + OutputSizeUser,
{
    type OutputSize = H::OutputSize;

    fn new_from_slice(key: &[u8]) -> Result<Self, TlsError> {
        <SimpleHmac<H> as Mac>::new_from_slice(key)
            .map(SoftwareHmac)
            .map_err(|_| TlsError::CryptoError)
    }

    fn update(&mut self, data: &[u8]) {
        Mac::update(&mut self.0, data);
    }

    fn finalize(self) -> GenericArray<u8, Self::OutputSize> {
        self.0.finalize().into_bytes()
    }

    fn verify(self, tag: &GenericArray<u8, Self::OutputSize>) -> Result<(), TlsError> {
        self.0.verify(tag).map_err(|_| TlsError::CryptoError)
    }
}

/// Software HKDF implementation using `hkdf::Hkdf`.
pub struct SoftwareHkdf<H: Digest + BlockSizeUser + Clone>(hkdf::Hkdf<H, SimpleHmac<H>>);

impl<H> TlsHkdf for SoftwareHkdf<H>
where
    H: Digest + BlockSizeUser + Clone + Reset + FixedOutput + OutputSizeUser,
{
    type OutputSize = H::OutputSize;

    fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> (GenericArray<u8, Self::OutputSize>, Self) {
        let (prk, hkdf) = hkdf::Hkdf::<H, SimpleHmac<H>>::extract(salt, ikm);
        (prk, SoftwareHkdf(hkdf))
    }

    fn from_prk(prk: &[u8]) -> Result<Self, TlsError> {
        hkdf::Hkdf::<H, SimpleHmac<H>>::from_prk(prk)
            .map(SoftwareHkdf)
            .map_err(|_| TlsError::InternalError)
    }

    fn expand(&self, info: &[u8], output: &mut [u8]) -> Result<(), TlsError> {
        self.0
            .expand(info, output)
            .map_err(|_| TlsError::CryptoError)
    }
}

// --- Software Cipher wrapper ---

/// Adapter that bridges `TlsBuffer` to `aead::Buffer` for software AEAD implementations.
struct BufferAdapter<'a, B: TlsBuffer>(&'a mut B);

impl<B: TlsBuffer> AsRef<[u8]> for BufferAdapter<'_, B> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<B: TlsBuffer> AsMut<[u8]> for BufferAdapter<'_, B> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

impl<B: TlsBuffer> aes_gcm::aead::Buffer for BufferAdapter<'_, B> {
    fn extend_from_slice(&mut self, other: &[u8]) -> Result<(), aes_gcm::Error> {
        self.0.extend_from_slice(other).map_err(|_| aes_gcm::Error)
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len);
    }
}

/// Software AEAD cipher implementation wrapping any `RustCrypto` AEAD type.
pub struct SoftwareCipher<C>(C);

impl<C> TlsCipher for SoftwareCipher<C>
where
    C: KeyInit + AeadInPlace + AeadCore,
{
    type KeySize = C::KeySize;
    type NonceSize = C::NonceSize;
    type TagSize = C::TagSize;

    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        SoftwareCipher(C::new(key))
    }

    fn encrypt_in_place<B: TlsBuffer>(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        aad: &[u8],
        buffer: &mut B,
    ) -> Result<(), TlsError> {
        self.0
            .encrypt_in_place(nonce, aad, &mut BufferAdapter(buffer))
            .map_err(|_| TlsError::InvalidApplicationData)
    }

    fn decrypt_in_place<B: TlsBuffer>(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        aad: &[u8],
        buffer: &mut B,
    ) -> Result<(), TlsError> {
        self.0
            .decrypt_in_place(nonce, aad, &mut BufferAdapter(buffer))
            .map_err(|_| TlsError::CryptoError)
    }
}

// --- Software Hash wrapper ---

/// Software hash implementation wrapping any `RustCrypto` `Digest` type.
#[derive(Clone)]
pub struct SoftwareHash<H: Digest + Clone>(H);

impl<H> TlsHash for SoftwareHash<H>
where
    H: Digest + Clone,
{
    type OutputSize = H::OutputSize;

    fn new() -> Self {
        SoftwareHash(H::new())
    }

    fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.0, data);
    }

    fn finalize(self) -> GenericArray<u8, Self::OutputSize> {
        Digest::finalize(self.0)
    }
}
