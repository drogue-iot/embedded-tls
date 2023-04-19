use crate::cipher_suites::CipherSuite;
use crate::handshake::certificate::CertificateRef;
use crate::handshake::certificate_verify::CertificateVerify;
use crate::max_fragment_length::MaxFragmentLength;
use crate::named_groups::NamedGroup;
use crate::signature_schemes::SignatureScheme;
use crate::TlsError;
use aes_gcm::{AeadInPlace, Aes128Gcm, Aes256Gcm, KeyInit};
use core::marker::PhantomData;
use digest::core_api::BlockSizeUser;
use digest::{Digest, FixedOutput, OutputSizeUser, Reset};
use generic_array::ArrayLength;
use heapless::Vec;
use rand_core::{CryptoRng, RngCore};
pub use sha2::Sha256;
pub use sha2::Sha384;
use typenum::{Sum, U10, U12, U16, U32};

const TLS_RECORD_MAX: usize = 16384;
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
    /// Create a new verification instance.
    ///
    /// This method is called for every TLS handshake.
    ///
    /// Host verification is enabled by passing a server hostname.
    fn new(host: Option<&'a str>) -> Self;

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
    fn verify_signature(&mut self, verify: CertificateVerify) -> Result<(), crate::TlsError>;
}

pub struct NoVerify;

impl<'a, CipherSuite> TlsVerifier<'a, CipherSuite> for NoVerify
where
    CipherSuite: TlsCipherSuite,
{
    fn new(_host: Option<&str>) -> Self {
        Self
    }

    fn verify_certificate(
        &mut self,
        _transcript: &CipherSuite::Hash,
        _ca: &Option<Certificate>,
        _cert: CertificateRef,
    ) -> Result<(), TlsError> {
        Ok(())
    }

    fn verify_signature(&mut self, _verify: CertificateVerify) -> Result<(), crate::TlsError> {
        Ok(())
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TlsConfig<'a, CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    //pub(crate) cipher_suites: Vec<CipherSuite, U16>,
    pub(crate) server_name: Option<&'a str>,
    pub(crate) psk: Option<(&'a [u8], Vec<&'a [u8], 4>)>,
    pub(crate) cipher_suite: PhantomData<CipherSuite>,
    pub(crate) signature_schemes: Vec<SignatureScheme, 16>,
    pub(crate) named_groups: Vec<NamedGroup, 16>,
    pub(crate) max_fragment_length: MaxFragmentLength,
    pub(crate) ca: Option<Certificate<'a>>,
    pub(crate) cert: Option<Certificate<'a>>,
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
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TlsContext<'a, CipherSuite, RNG>
where
    CipherSuite: TlsCipherSuite,
    RNG: CryptoRng + RngCore + 'a,
{
    pub(crate) config: &'a TlsConfig<'a, CipherSuite>,
    pub(crate) rng: &'a mut RNG,
}

impl<'a, CipherSuite, RNG> TlsContext<'a, CipherSuite, RNG>
where
    CipherSuite: TlsCipherSuite,
    RNG: CryptoRng + RngCore + 'a,
{
    /// Create a new context with a given config and random number generator reference.
    pub fn new(config: &'a TlsConfig<'a, CipherSuite>, rng: &'a mut RNG) -> Self {
        Self { config, rng }
    }
}

impl<'a, CipherSuite> TlsConfig<'a, CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub fn new() -> Self {
        let mut config = Self {
            cipher_suite: PhantomData,
            signature_schemes: Vec::new(),
            named_groups: Vec::new(),
            max_fragment_length: MaxFragmentLength::Bits10,
            psk: None,
            server_name: None,
            ca: None,
            cert: None,
        };

        //config.cipher_suites.push(CipherSuite::TlsAes128GcmSha256);
        //
        if cfg!(feature = "alloc") {
            config = config.enable_rsa_signatures();
        }

        config
            .signature_schemes
            .push(SignatureScheme::EcdsaSecp256r1Sha256)
            .unwrap();
        config
            .signature_schemes
            .push(SignatureScheme::EcdsaSecp384r1Sha384)
            .unwrap();
        config
            .signature_schemes
            .push(SignatureScheme::Ed25519)
            .unwrap();

        config.named_groups.push(NamedGroup::Secp256r1).unwrap();

        config
    }

    /// Enable RSA ciphers even if they might not be supported.
    pub fn enable_rsa_signatures(mut self) -> Self {
        self.signature_schemes
            .push(SignatureScheme::RsaPkcs1Sha256)
            .unwrap();
        self.signature_schemes
            .push(SignatureScheme::RsaPkcs1Sha384)
            .unwrap();
        self.signature_schemes
            .push(SignatureScheme::RsaPkcs1Sha512)
            .unwrap();
        self.signature_schemes
            .push(SignatureScheme::RsaPssRsaeSha256)
            .unwrap();
        self.signature_schemes
            .push(SignatureScheme::RsaPssRsaeSha384)
            .unwrap();
        self.signature_schemes
            .push(SignatureScheme::RsaPssRsaeSha512)
            .unwrap();
        self
    }

    pub fn with_server_name(mut self, server_name: &'a str) -> Self {
        self.server_name = Some(server_name);
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

    pub fn with_psk(mut self, psk: &'a [u8], identities: &[&'a [u8]]) -> Self {
        // TODO: Remove potential panic
        self.psk = Some((psk, Vec::from_slice(identities).unwrap()));
        self
    }
}

impl<'a, CipherSuite> Default for TlsConfig<'a, CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
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
