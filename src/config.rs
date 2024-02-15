use core::marker::PhantomData;
use core::ops::Deref;

use crate::cipher_suites::CipherSuite;
use crate::extensions::extension_data::signature_algorithms::SignatureScheme;
use crate::extensions::extension_data::supported_groups::NamedGroup;
use crate::handshake::certificate::CertificateRef;
use crate::handshake::certificate_verify::CertificateVerifyRef;
use crate::TlsError;
use aes_gcm::{AeadInPlace, Aes128Gcm, Aes256Gcm, KeyInit};
use digest::core_api::BlockSizeUser;
use digest::{Digest, FixedOutput, OutputSizeUser, Reset};
use ecdsa::signature::RandomizedSigner;
use generic_array::ArrayLength;
use heapless::Vec;
use p256::NistP256;
use rand_core::CryptoRngCore;
pub use sha2::Sha256;
pub use sha2::Sha384;
use typenum::{Sum, U10, U12, U16, U32};

use ecdsa::{
    elliptic_curve::{CurveArithmetic, SecretKey},
    hazmat::{DigestPrimitive, SignPrimitive},
    PrimeCurve, SignatureSize, SigningKey,
};

pub use crate::extensions::extension_data::max_fragment_length::MaxFragmentLength;

pub(crate) const TLS_RECORD_MAX: usize = 16384;
pub const TLS_RECORD_OVERHEAD: usize = 128;

// longest label is 12b -> buf <= 2 + 1 + 6 + longest + 1 + hash_out = hash_out + 22
type LongestLabel = U12;
type LabelOverhead = U10;
type LabelBuffer<CipherSuite> = Sum<
    <<CipherSuite as TlsCipherSuite>::Hash as OutputSizeUser>::OutputSize,
    Sum<LongestLabel, LabelOverhead>,
>;

/// Represents a TLS 1.3 cipher suite
pub trait TlsCipherSuite {
    const CODE_POINT: u16;
    type Cipher: KeyInit<KeySize = Self::KeyLen> + AeadInPlace<NonceSize = Self::IvLen>;
    type KeyLen: ArrayLength<u8>;
    type IvLen: ArrayLength<u8>;

    type Hash: Digest + Reset + Clone + OutputSizeUser + BlockSizeUser + FixedOutput;
    type LabelBufferSize: ArrayLength<u8>;
}

pub struct Aes128GcmSha256;
impl TlsCipherSuite for Aes128GcmSha256 {
    const CODE_POINT: u16 = CipherSuite::TlsAes128GcmSha256 as u16;
    type Cipher = Aes128Gcm;
    type KeyLen = U16;
    type IvLen = U12;

    type Hash = Sha256;
    type LabelBufferSize = LabelBuffer<Self>;
}

pub struct Aes256GcmSha384;
impl TlsCipherSuite for Aes256GcmSha384 {
    const CODE_POINT: u16 = CipherSuite::TlsAes256GcmSha384 as u16;
    type Cipher = Aes256Gcm;
    type KeyLen = U32;
    type IvLen = U12;

    type Hash = Sha384;
    type LabelBufferSize = LabelBuffer<Self>;
}

/// A TLS 1.3 verifier.
///
/// The verifier is responsible for verifying certificates and signatures. Since certificate verification is
/// an expensive process, this trait allows clients to choose how much verification should take place,
/// and also to skip the verification if the server is verified through other means (I.e. a pre-shared key).
pub trait TlsVerifier<'a, CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    /// Host verification is enabled by passing a server hostname.
    fn set_hostname_verification(
        &mut self,
        hostname: Option<&'a str>,
    ) -> Result<(), crate::TlsError>;

    /// Verify a certificate.
    ///
    /// The handshake transcript up to this point and the server certificate is provided
    /// for the implementation
    /// to use.
    fn verify_certificate(
        &mut self,
        transcript: &CipherSuite::Hash,
        ca: &Option<Certificate>,
        cert: CertificateRef,
    ) -> Result<(), TlsError>;

    /// Verify the certificate signature.
    ///
    /// The signature verification uses the transcript and certificate provided earlier to decode the provided signature.
    fn verify_signature(&mut self, verify: CertificateVerifyRef) -> Result<(), crate::TlsError>;
}

pub struct NoVerify;

impl<'a, CipherSuite> TlsVerifier<'a, CipherSuite> for NoVerify
where
    CipherSuite: TlsCipherSuite,
{
    fn set_hostname_verification(
        &mut self,
        _hostname: Option<&'a str>,
    ) -> Result<(), crate::TlsError> {
        Ok(())
    }

    fn verify_certificate(
        &mut self,
        _transcript: &CipherSuite::Hash,
        _ca: &Option<Certificate>,
        _cert: CertificateRef,
    ) -> Result<(), TlsError> {
        Ok(())
    }

    fn verify_signature(&mut self, _verify: CertificateVerifyRef) -> Result<(), crate::TlsError> {
        Ok(())
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TlsConfig<'a> {
    pub(crate) server_name: Option<&'a str>,
    pub(crate) psk: Option<(&'a [u8], Vec<&'a [u8], 4>)>,
    pub(crate) signature_schemes: Vec<SignatureScheme, 16>,
    pub(crate) named_groups: Vec<NamedGroup, 16>,
    pub(crate) max_fragment_length: Option<MaxFragmentLength>,
    pub(crate) ca: Option<Certificate<'a>>,
    pub(crate) cert: Option<Certificate<'a>>,
    pub(crate) priv_key: &'a [u8],
}

pub trait TlsClock {
    fn now() -> Option<u64>;
}

pub struct NoClock;

impl TlsClock for NoClock {
    fn now() -> Option<u64> {
        None
    }
}

#[derive(Debug)]
pub struct Signature<T: PrimeCurve>
where
    SignatureSize<T>: core::ops::Add<ecdsa::der::MaxOverhead> + ArrayLength<u8>,
    ecdsa::der::MaxSize<T>: ArrayLength<u8>,
{
    signature: ecdsa::der::Signature<T>,
}

impl<T: PrimeCurve> Deref for Signature<T>
where
    SignatureSize<T>: core::ops::Add<ecdsa::der::MaxOverhead> + ArrayLength<u8>,
    ecdsa::der::MaxSize<T>: ArrayLength<u8>,
{
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.signature.as_bytes()
    }
}

pub struct Signer<'a, T: PrimeCurve, RNG: CryptoRngCore> {
    pub secret_key: SecretKey<T>,
    pub scheme: SignatureScheme,
    pub rng: &'a mut RNG,
}

impl<'a, T: PrimeCurve, RNG: CryptoRngCore> Signer<'a, T, RNG>
where
    SignatureSize<T>: core::ops::Add<ecdsa::der::MaxOverhead> + ArrayLength<u8>,
    ecdsa::der::MaxSize<T>: ArrayLength<u8>,
{
    pub fn sign(&mut self, message: &[u8]) -> Signature<T>
    where
        T: CurveArithmetic + DigestPrimitive,
        <T as CurveArithmetic>::Scalar: SignPrimitive<T>,
    {
        let signing_key = SigningKey::from(&self.secret_key);
        let signature = signing_key.sign_with_rng(self.rng, &message);

        Signature { signature }
    }

    pub fn signature_scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

pub trait CryptoProvider {
    type CipherSuite: TlsCipherSuite;
    type SecureRandom: CryptoRngCore;
    type SignatureCurve: CurveArithmetic + DigestPrimitive;

    fn rng(&mut self) -> &mut Self::SecureRandom;

    fn verifier(
        &mut self,
    ) -> Result<&mut impl TlsVerifier<'_, Self::CipherSuite>, crate::TlsError> {
        Err::<&mut NoVerify, _>(crate::TlsError::Unimplemented)
    }

    /// Decode and validate a private signing key from `key_der`.
    fn signer(
        &mut self,
        _key_der: &[u8],
    ) -> Result<Signer<Self::SignatureCurve, Self::SecureRandom>, crate::TlsError> {
        Err::<Signer<Self::SignatureCurve, Self::SecureRandom>, _>(crate::TlsError::Unimplemented)
    }
}

pub struct UnsecureProvider<CipherSuite, RNG> {
    rng: RNG,
    _marker: PhantomData<CipherSuite>,
}

impl<RNG: CryptoRngCore> UnsecureProvider<(), RNG> {
    pub fn new<CipherSuite: TlsCipherSuite>(rng: RNG) -> UnsecureProvider<CipherSuite, RNG> {
        UnsecureProvider {
            rng,
            _marker: PhantomData,
        }
    }
}

impl<CipherSuite: TlsCipherSuite, RNG: CryptoRngCore> CryptoProvider
    for UnsecureProvider<CipherSuite, RNG>
{
    type CipherSuite = CipherSuite;
    type SecureRandom = RNG;
    type SignatureCurve = NistP256;

    fn rng(&mut self) -> &mut Self::SecureRandom {
        &mut self.rng
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TlsContext<'a, Provider>
where
    Provider: CryptoProvider,
{
    pub(crate) config: &'a TlsConfig<'a>,
    pub(crate) crypto_provider: Provider,
}

impl<'a, Provider> TlsContext<'a, Provider>
where
    Provider: CryptoProvider,
{
    /// Create a new context with a given config and a crypto provider.
    pub fn new(config: &'a TlsConfig<'a>, crypto_provider: Provider) -> Self {
        Self {
            config,
            crypto_provider,
        }
    }
}

impl<'a> TlsConfig<'a> {
    pub fn new() -> Self {
        let mut config = Self {
            signature_schemes: Vec::new(),
            named_groups: Vec::new(),
            max_fragment_length: None,
            psk: None,
            server_name: None,
            ca: None,
            cert: None,
            priv_key: &[],
        };

        if cfg!(feature = "alloc") {
            config = config.enable_rsa_signatures();
        }

        unwrap!(config
            .signature_schemes
            .push(SignatureScheme::EcdsaSecp256r1Sha256)
            .ok());
        unwrap!(config
            .signature_schemes
            .push(SignatureScheme::EcdsaSecp384r1Sha384)
            .ok());
        unwrap!(config.signature_schemes.push(SignatureScheme::Ed25519).ok());

        unwrap!(config.named_groups.push(NamedGroup::Secp256r1));

        config
    }

    /// Enable RSA ciphers even if they might not be supported.
    pub fn enable_rsa_signatures(mut self) -> Self {
        unwrap!(self
            .signature_schemes
            .push(SignatureScheme::RsaPkcs1Sha256)
            .ok());
        unwrap!(self
            .signature_schemes
            .push(SignatureScheme::RsaPkcs1Sha384)
            .ok());
        unwrap!(self
            .signature_schemes
            .push(SignatureScheme::RsaPkcs1Sha512)
            .ok());
        unwrap!(self
            .signature_schemes
            .push(SignatureScheme::RsaPssRsaeSha256)
            .ok());
        unwrap!(self
            .signature_schemes
            .push(SignatureScheme::RsaPssRsaeSha384)
            .ok());
        unwrap!(self
            .signature_schemes
            .push(SignatureScheme::RsaPssRsaeSha512)
            .ok());
        self
    }

    pub fn with_server_name(mut self, server_name: &'a str) -> Self {
        self.server_name = Some(server_name);
        self
    }

    /// Configures the maximum plaintext fragment size.
    ///
    /// This option may help reduce memory size, as smaller fragment lengths require smaller
    /// read/write buffers. Note that embedded-tls does not currently use this option to fragment
    /// writes. Note that the buffers need to include some overhead over the configured fragment
    /// length.
    ///
    /// From [RFC 6066, Section 4.  Maximum Fragment Length Negotiation](https://www.rfc-editor.org/rfc/rfc6066#page-8):
    ///
    /// > Without this extension, TLS specifies a fixed maximum plaintext
    /// > fragment length of 2^14 bytes.  It may be desirable for constrained
    /// > clients to negotiate a smaller maximum fragment length due to memory
    /// > limitations or bandwidth limitations.
    ///
    /// > For example, if the negotiated length is 2^9=512, then, when using currently defined
    /// > cipher suites ([...]) and null compression, the record-layer output can be at most
    /// > 805 bytes: 5 bytes of headers, 512 bytes of application data, 256 bytes of padding,
    /// > and 32 bytes of MAC.
    pub fn with_max_fragment_length(mut self, max_fragment_length: MaxFragmentLength) -> Self {
        self.max_fragment_length = Some(max_fragment_length);
        self
    }

    /// Resets the max fragment length to 14 bits (16384).
    pub fn reset_max_fragment_length(mut self) -> Self {
        self.max_fragment_length = None;
        self
    }

    pub fn with_ca(mut self, ca: Certificate<'a>) -> Self {
        self.ca = Some(ca);
        self
    }

    pub fn with_cert(mut self, cert: Certificate<'a>) -> Self {
        self.cert = Some(cert);
        self
    }

    pub fn with_priv_key(mut self, priv_key: &'a [u8]) -> Self {
        self.priv_key = priv_key;
        self
    }

    pub fn with_psk(mut self, psk: &'a [u8], identities: &[&'a [u8]]) -> Self {
        // TODO: Remove potential panic
        self.psk = Some((psk, unwrap!(Vec::from_slice(identities).ok())));
        self
    }
}

impl<'a> Default for TlsConfig<'a> {
    fn default() -> Self {
        TlsConfig::new()
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Certificate<'a> {
    X509(&'a [u8]),
    RawPublicKey(&'a [u8]),
}
