use crate::cipher_suites::CipherSuite;
use crate::max_fragment_length::MaxFragmentLength;
use crate::named_groups::NamedGroup;
use crate::signature_schemes::SignatureScheme;
use aes_gcm::{AeadInPlace, Aes128Gcm, NewAead};
use core::marker::PhantomData;
use digest::{BlockInput, FixedOutput, Reset, Update};
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

    type Hash: Update + BlockInput + FixedOutput + Reset + Default + Clone;
    //D::BlockSize: ArrayLength<u8>,
    //D::OutputSize: ArrayLength<u8>,
    //;
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
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TlsContext<'a, CipherSuite, RNG>
where
    CipherSuite: TlsCipherSuite,
    RNG: CryptoRng + RngCore + 'static,
{
    pub(crate) config: TlsConfig<'a, CipherSuite>,
    pub(crate) rng: RNG,
    pub(crate) record_buf: &'a mut [u8],
}

impl<'a, CipherSuite, RNG> TlsContext<'a, CipherSuite, RNG>
where
    CipherSuite: TlsCipherSuite,
    RNG: CryptoRng + RngCore + 'static,
{
    /// Create a new context with a given random number generator, record buffer and config.
    ///
    /// NOTE: The record buffer should be sized to fit an encrypted TLS record and the TLS handshake
    /// record. The maximum value of a TLS record is 16 kB, which should be a safe value to use.
    pub fn new_with_config(
        rng: RNG,
        record_buf: &'a mut [u8],
        config: TlsConfig<'a, CipherSuite>,
    ) -> Self {
        if record_buf.len() < TLS_RECORD_MAX {
            warn!("Record buffer length is smaller than TLS max record size");
        }
        Self {
            config,
            rng,
            record_buf,
        }
    }

    /// Create a new context with a given random number generator and a record buffer.
    ///
    /// NOTE: The record buffer should be sized to fit an encrypted TLS record and the TLS handshake
    /// record. The maximum value of a TLS record is 16 kB, which should be a safe value to use.
    pub fn new(rng: RNG, record_buf: &'a mut [u8]) -> Self {
        Self::new_with_config(rng, record_buf, TlsConfig::new())
    }

    /// Configure the Server Name Indication (SNI) extension to be used, passing the provided server name
    /// in the handshake.
    pub fn with_server_name(mut self, server_name: &'a str) -> Self {
        self.config = self.config.with_server_name(server_name);
        self
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
        };

        //config.cipher_suites.push(CipherSuite::TlsAes128GcmSha256);

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

        config.named_groups.push(NamedGroup::Secp256r1).unwrap();

        config
    }

    pub fn with_server_name(mut self, server_name: &'a str) -> Self {
        self.server_name = Some(server_name);
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
