use crate::cipher_suites::CipherSuite;
use crate::max_fragment_length::MaxFragmentLength;
use crate::named_groups::NamedGroup;
use crate::signature_schemes::SignatureScheme;
use aes_gcm::{AeadInPlace, Aes128Gcm, NewAead};
use core::marker::PhantomData;
use digest::core_api::BlockSizeUser;
use digest::{Digest, FixedOutput, OutputSizeUser, Reset};
use generic_array::ArrayLength;
use heapless::Vec;
use rand_core::{CryptoRng, RngCore};
pub use sha2::Sha256;
use typenum::{U12, U16};

const TLS_RECORD_MAX: usize = 16384;

pub trait TlsCipherSuite {
    const CODE_POINT: u16;
    type Cipher: NewAead<KeySize = Self::KeyLen> + AeadInPlace<NonceSize = Self::IvLen>;
    type KeyLen: ArrayLength<u8>;
    type IvLen: ArrayLength<u8>;

    type Hash: Digest + Reset + Clone + OutputSizeUser + BlockSizeUser + FixedOutput;
}

pub struct Aes128GcmSha256;
impl TlsCipherSuite for Aes128GcmSha256 {
    const CODE_POINT: u16 = CipherSuite::TlsAes128GcmSha256 as u16;
    type Cipher = Aes128Gcm;
    type KeyLen = U16;
    type IvLen = U12;

    type Hash = Sha256;
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TlsConfig<'a, CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    //pub(crate) cipher_suites: Vec<CipherSuite, U16>,
    pub(crate) server_name: Option<&'a str>,
    pub(crate) cipher_suite: PhantomData<CipherSuite>,
    pub(crate) signature_schemes: Vec<SignatureScheme, 16>,
    pub(crate) named_groups: Vec<NamedGroup, 16>,
    pub(crate) max_fragment_length: MaxFragmentLength,
    pub(crate) ca: Option<Certificate<'a>>,
    pub(crate) cert: Option<Certificate<'a>>,
    pub(crate) verify_host: bool,
    pub(crate) verify_cert: bool,
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
            server_name: None,
            verify_cert: true,
            verify_host: true,
            ca: None,
            cert: None,
        };

        #[cfg(not(feature = "webpki"))]
        {
            config.verify_cert = false;
            config.verify_host = false;
        }

        //config.cipher_suites.push(CipherSuite::TlsAes128GcmSha256);

        #[cfg(feature = "alloc")]
        {
            config
                .signature_schemes
                .push(SignatureScheme::RsaPkcs1Sha256)
                .unwrap();
            config
                .signature_schemes
                .push(SignatureScheme::RsaPkcs1Sha384)
                .unwrap();
            config
                .signature_schemes
                .push(SignatureScheme::RsaPkcs1Sha512)
                .unwrap();
            config
                .signature_schemes
                .push(SignatureScheme::RsaPssRsaeSha256)
                .unwrap();
            config
                .signature_schemes
                .push(SignatureScheme::RsaPssRsaeSha384)
                .unwrap();
            config
                .signature_schemes
                .push(SignatureScheme::RsaPssRsaeSha512)
                .unwrap();
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

    pub fn with_server_name(mut self, server_name: &'a str) -> Self {
        self.server_name = Some(server_name);
        self
    }

    pub fn verify_hostname(mut self, verify_host: bool) -> Self {
        self.verify_host = verify_host;
        self
    }

    pub fn verify_cert(mut self, verify_cert: bool) -> Self {
        self.verify_cert = verify_cert;
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
