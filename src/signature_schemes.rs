#![allow(unused_imports)]
use crate::TlsError;

#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SignatureScheme {
    /* RSASSA-PKCS1-v1_5 algorithms */
    RsaPkcs1Sha256 = 0x0401,
    RsaPkcs1Sha384 = 0x0501,
    RsaPkcs1Sha512 = 0x0601,

    /* ECDSA algorithms */
    EcdsaSecp256r1Sha256 = 0x0403,
    EcdsaSecp384r1Sha384 = 0x0503,
    EcdsaSecp521r1Sha512 = 0x0603,

    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    RsaPssRsaeSha256 = 0x0804,
    RsaPssRsaeSha384 = 0x0805,
    RsaPssRsaeSha512 = 0x0806,

    /* EdDSA algorithms */
    Ed25519 = 0x0807,
    Ed448 = 0x0808,

    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    RsaPssPssSha256 = 0x0809,
    RsaPssPssSha384 = 0x080a,
    RsaPssPssSha512 = 0x080b,

    /* Legacy algorithms */
    RsaPkcs1Sha1 = 0x0201,
    EcdsaSha1 = 0x0203,
    /* Reserved Code Points */
    //private_use(0xFE00..0xFFFF),
    //(0xFFFF)
}

impl SignatureScheme {
    pub fn of(num: u16) -> Option<Self> {
        match num {
            0x0401 => Some(Self::RsaPkcs1Sha256),
            0x0501 => Some(Self::RsaPkcs1Sha384),
            0x0601 => Some(Self::RsaPkcs1Sha512),

            0x0403 => Some(Self::EcdsaSecp256r1Sha256),
            0x0503 => Some(Self::EcdsaSecp384r1Sha384),
            0x0603 => Some(Self::EcdsaSecp521r1Sha512),

            0x0804 => Some(Self::RsaPssRsaeSha256),
            0x0805 => Some(Self::RsaPssRsaeSha384),
            0x0806 => Some(Self::RsaPssRsaeSha512),

            0x0807 => Some(Self::Ed25519),
            0x0808 => Some(Self::Ed448),

            0x0809 => Some(Self::RsaPssPssSha256),
            0x080a => Some(Self::RsaPssPssSha384),
            0x080b => Some(Self::RsaPssPssSha512),

            0x0201 => Some(Self::RsaPkcs1Sha1),
            0x0203 => Some(Self::EcdsaSha1),
            _ => None,
        }
    }
}

#[cfg(all(not(feature = "alloc"), feature = "webpki"))]
impl TryInto<&'static webpki::SignatureAlgorithm> for SignatureScheme {
    type Error = TlsError;
    fn try_into(self) -> Result<&'static webpki::SignatureAlgorithm, Self::Error> {
        // TODO: support other schemes via 'alloc' feature
        match self {
            SignatureScheme::RsaPkcs1Sha256 => Err(TlsError::InvalidSignatureScheme),
            SignatureScheme::RsaPkcs1Sha384 => Err(TlsError::InvalidSignatureScheme),
            SignatureScheme::RsaPkcs1Sha512 => Err(TlsError::InvalidSignatureScheme),

            /* ECDSA algorithms */
            SignatureScheme::EcdsaSecp256r1Sha256 => Ok(&webpki::ECDSA_P256_SHA256),
            SignatureScheme::EcdsaSecp384r1Sha384 => Ok(&webpki::ECDSA_P384_SHA384),
            SignatureScheme::EcdsaSecp521r1Sha512 => Err(TlsError::InvalidSignatureScheme),

            /* RSASSA-PSS algorithms with public key OID rsaEncryption */
            SignatureScheme::RsaPssRsaeSha256 => Err(TlsError::InvalidSignatureScheme),
            SignatureScheme::RsaPssRsaeSha384 => Err(TlsError::InvalidSignatureScheme),
            SignatureScheme::RsaPssRsaeSha512 => Err(TlsError::InvalidSignatureScheme),

            /* EdDSA algorithms */
            SignatureScheme::Ed25519 => Ok(&webpki::ED25519),
            SignatureScheme::Ed448 => Err(TlsError::InvalidSignatureScheme),

            /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
            SignatureScheme::RsaPssPssSha256 => Err(TlsError::InvalidSignatureScheme),
            SignatureScheme::RsaPssPssSha384 => Err(TlsError::InvalidSignatureScheme),
            SignatureScheme::RsaPssPssSha512 => Err(TlsError::InvalidSignatureScheme),

            /* Legacy algorithms */
            SignatureScheme::RsaPkcs1Sha1 => Err(TlsError::InvalidSignatureScheme),
            SignatureScheme::EcdsaSha1 => Err(TlsError::InvalidSignatureScheme),
        }
    }
}

#[cfg(all(feature = "alloc", feature = "webpki"))]
impl TryInto<&'static webpki::SignatureAlgorithm> for SignatureScheme {
    type Error = TlsError;
    fn try_into(self) -> Result<&'static webpki::SignatureAlgorithm, Self::Error> {
        match self {
            SignatureScheme::RsaPkcs1Sha256 => Ok(&webpki::RSA_PKCS1_2048_8192_SHA256),
            SignatureScheme::RsaPkcs1Sha384 => Ok(&webpki::RSA_PKCS1_2048_8192_SHA384),
            SignatureScheme::RsaPkcs1Sha512 => Ok(&webpki::RSA_PKCS1_2048_8192_SHA512),

            /* ECDSA algorithms */
            SignatureScheme::EcdsaSecp256r1Sha256 => Ok(&webpki::ECDSA_P256_SHA256),
            SignatureScheme::EcdsaSecp384r1Sha384 => Ok(&webpki::ECDSA_P384_SHA384),
            SignatureScheme::EcdsaSecp521r1Sha512 => Err(TlsError::InvalidSignatureScheme),

            /* RSASSA-PSS algorithms with public key OID rsaEncryption */
            SignatureScheme::RsaPssRsaeSha256 => Ok(&webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY),
            SignatureScheme::RsaPssRsaeSha384 => Ok(&webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY),
            SignatureScheme::RsaPssRsaeSha512 => Ok(&webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY),

            /* EdDSA algorithms */
            SignatureScheme::Ed25519 => Ok(&webpki::ED25519),
            SignatureScheme::Ed448 => Err(TlsError::InvalidSignatureScheme),

            /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
            SignatureScheme::RsaPssPssSha256 => Err(TlsError::InvalidSignatureScheme),
            SignatureScheme::RsaPssPssSha384 => Err(TlsError::InvalidSignatureScheme),
            SignatureScheme::RsaPssPssSha512 => Err(TlsError::InvalidSignatureScheme),

            /* Legacy algorithms */
            SignatureScheme::RsaPkcs1Sha1 => Err(TlsError::InvalidSignatureScheme),
            SignatureScheme::EcdsaSha1 => Err(TlsError::InvalidSignatureScheme),
        }
    }
}
