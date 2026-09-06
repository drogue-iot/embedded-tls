//! `embassy-crypto` backend for the `CryptoProvider` hardware-abstraction layer.
//!
//! Enabled via the `embassy-crypto` cargo feature. All P-256 operations go
//! through the high-level [`embassy_crypto::asymmetric`] API — no `p256`
//! software EC stack is required at runtime; a HAL registering `P256EcImpl`
//! can serve it. Transcript hash / HKDF HMAC stay on the cipher-suite types.

use core::marker::PhantomData;

use crate::config::{Aes128GcmSha256, Aes256GcmSha384, CryptoProvider, TlsCipherSuite};
use crate::crypto_traits::AesGcmAead;
use crate::{CryptoRngCore, NamedGroup, TlsError};

use embassy_crypto::asymmetric::Signature;
use embassy_crypto::{HmacSha256, HmacSha384, Sha256, Sha384, asymmetric};

/// `CryptoProvider` backed by `embassy-crypto` drivers.
pub struct EmbassyCryptoProvider<CipherSuite, RNG> {
    rng: RNG,
    _cipher: PhantomData<CipherSuite>,
}

impl<RNG: CryptoRngCore> EmbassyCryptoProvider<(), RNG> {
    /// Create a provider for the cipher suite given by the turbofish,
    /// mirroring [`UnsecureProvider::new`](crate::UnsecureProvider::new).
    pub fn new<CipherSuite: TlsCipherSuite>(rng: RNG) -> EmbassyCryptoProvider<CipherSuite, RNG> {
        EmbassyCryptoProvider {
            rng,
            _cipher: PhantomData,
        }
    }
}

fn ecdh_p256(
    group: NamedGroup,
    secret_key: &[u8],
    peer_public: &[u8],
    shared_secret: &mut [u8],
) -> Result<(), TlsError> {
    match group {
        NamedGroup::Secp256r1 => {
            let d: &[u8; 32] = secret_key
                .try_into()
                .map_err(|_| TlsError::InvalidKeyShare)?;
            let ours =
                asymmetric::SecretKey::from_bytes(d).map_err(|_| TlsError::InvalidKeyShare)?;
            let peer_xy: &[u8; 64] = peer_public
                .try_into()
                .map_err(|_| TlsError::InvalidKeyShare)?;
            let peer = asymmetric::PublicKey::from_xy(
                peer_xy[..32].try_into().unwrap(),
                peer_xy[32..].try_into().unwrap(),
            );
            if !peer.is_valid() {
                return Err(TlsError::InvalidKeyShare);
            }
            let shared = ours.ecdh(&peer).map_err(|_| TlsError::InvalidKeyShare)?;
            shared_secret[..32].copy_from_slice(shared.as_bytes());
            Ok(())
        }
        _ => Err(TlsError::InvalidKeyShare),
    }
}

fn keygen_p256<RNG: CryptoRngCore>(
    rng: &mut RNG,
    group: NamedGroup,
    secret_key: &mut [u8],
    public_key: &mut [u8],
) -> Result<(), TlsError> {
    match group {
        NamedGroup::Secp256r1 => {
            let secret = asymmetric::SecretKey::generate(rng).map_err(|_| TlsError::CryptoError)?;
            secret_key[..32].copy_from_slice(&secret.to_bytes());
            let public = secret.public_key().map_err(|_| TlsError::CryptoError)?;
            let (x, y) = public.to_xy();
            public_key[..32].copy_from_slice(&x);
            public_key[32..].copy_from_slice(&y);
            Ok(())
        }
        _ => Err(TlsError::InvalidKeyShare),
    }
}

impl<RNG: CryptoRngCore> CryptoProvider for EmbassyCryptoProvider<Aes128GcmSha256, RNG> {
    type CipherSuite = Aes128GcmSha256;
    type Signature = Signature;
    type Hash = Sha256;
    type Hmac = HmacSha256;
    type Aead = AesGcmAead<embassy_crypto::Aes128Gcm>;

    fn rng(&mut self) -> impl CryptoRngCore {
        &mut self.rng
    }
    fn aead(&mut self, key: &[u8]) -> Result<Self::Aead, TlsError> {
        AesGcmAead::new(key)
    }
    fn ecdh(&mut self, g: NamedGroup, sk: &[u8], p: &[u8], o: &mut [u8]) -> Result<(), TlsError> {
        ecdh_p256(g, sk, p, o)
    }
    fn keygen(&mut self, g: NamedGroup, sk: &mut [u8], pk: &mut [u8]) -> Result<(), TlsError> {
        keygen_p256(&mut self.rng, g, sk, pk)
    }
}

impl<RNG: CryptoRngCore> CryptoProvider for EmbassyCryptoProvider<Aes256GcmSha384, RNG> {
    type CipherSuite = Aes256GcmSha384;
    type Signature = Signature;
    type Hash = Sha384;
    type Hmac = HmacSha384;
    type Aead = AesGcmAead<embassy_crypto::Aes256Gcm>;

    fn rng(&mut self) -> impl CryptoRngCore {
        &mut self.rng
    }
    fn aead(&mut self, key: &[u8]) -> Result<Self::Aead, TlsError> {
        AesGcmAead::new(key)
    }
    fn ecdh(&mut self, g: NamedGroup, sk: &[u8], p: &[u8], o: &mut [u8]) -> Result<(), TlsError> {
        ecdh_p256(g, sk, p, o)
    }
    fn keygen(&mut self, g: NamedGroup, sk: &mut [u8], pk: &mut [u8]) -> Result<(), TlsError> {
        keygen_p256(&mut self.rng, g, sk, pk)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use rand::rng;

    #[test]
    fn p256_keygen_ecdh_roundtrip() {
        let (mut a, mut b, mut pk_a, mut pk_b, mut s1, mut s2) = (
            [0u8; 32], [0u8; 32], [0u8; 64], [0u8; 64], [0u8; 32], [0u8; 32],
        );
        keygen_p256(&mut rng(), NamedGroup::Secp256r1, &mut a, &mut pk_a).unwrap();
        keygen_p256(&mut rng(), NamedGroup::Secp256r1, &mut b, &mut pk_b).unwrap();
        ecdh_p256(NamedGroup::Secp256r1, &a, &pk_b, &mut s1).unwrap();
        ecdh_p256(NamedGroup::Secp256r1, &b, &pk_a, &mut s2).unwrap();
        assert_eq!(s1, s2);
    }
}
