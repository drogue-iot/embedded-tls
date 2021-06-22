use crate::cipher_suites::CipherSuite;
use crate::max_fragment_length::MaxFragmentLength;
use crate::named_groups::NamedGroup;
use crate::signature_schemes::SignatureScheme;
use aes_gcm::{AeadInPlace, Aes128Gcm, NewAead};
use core::marker::PhantomData;
use digest::{BlockInput, Digest, FixedOutput, Reset, Update};
use generic_array::ArrayLength;
use heapless::{consts::*, Vec};
use rand_core::{CryptoRng, RngCore};
pub use sha2::Sha256;

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
pub struct Config<RNG, CipherSuite>
where
    RNG: CryptoRng + RngCore,
    CipherSuite: TlsCipherSuite,
{
    pub(crate) rng: RNG,
    //pub(crate) cipher_suites: Vec<CipherSuite, U16>,
    pub(crate) cipher_suite: PhantomData<CipherSuite>,
    pub(crate) signature_schemes: Vec<SignatureScheme, U16>,
    pub(crate) named_groups: Vec<NamedGroup, U16>,
    pub(crate) max_fragment_length: MaxFragmentLength,
}

impl<RNG, CipherSuite> Config<RNG, CipherSuite>
where
    RNG: CryptoRng + RngCore,
    CipherSuite: TlsCipherSuite,
{
    pub fn new(rng: RNG) -> Self {
        let mut config = Self {
            rng,
            cipher_suite: PhantomData,
            signature_schemes: Vec::new(),
            named_groups: Vec::new(),
            max_fragment_length: MaxFragmentLength::Bits10,
        };

        //config.cipher_suites.push(CipherSuite::TlsAes128GcmSha256);

        config
            .signature_schemes
            .push(SignatureScheme::RsaPssRsaeSha256);
        config
            .signature_schemes
            .push(SignatureScheme::RsaPssRsaeSha384);
        config
            .signature_schemes
            .push(SignatureScheme::RsaPssRsaeSha512);

        config.named_groups.push(NamedGroup::Secp256r1);

        config
    }
}
