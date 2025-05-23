// Based on https://github.com/FactbirdHQ/at-cryptoauth-rs/blob/master/src/cert/certificate.rs

use core::cmp::Ordering;
use der::asn1::{
    BitStringRef, GeneralizedTime, IntRef, ObjectIdentifier, SequenceOf, SetOf,
    UtcTime,
};
use der::{AnyRef, Choice, Enumerated, Sequence, ValueOrd};

#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Sequence, ValueOrd)]
pub struct AlgorithmIdentifier<'a> {
    pub oid: ObjectIdentifier,
    pub parameters: Option<AnyRef<'a>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
pub enum Version {
    /// Version 1 (default)
    V1 = 0,

    /// Version 2
    V2 = 1,

    /// Version 3
    V3 = 2,
}

impl ValueOrd for Version {
    fn value_cmp(&self, other: &Self) -> der::Result<Ordering> {
        (*self as u8).value_cmp(&(*other as u8))
    }
}

impl Default for Version {
    fn default() -> Self {
        Self::V1
    }
}

#[derive(Sequence, ValueOrd)]
pub struct DecodedCertificate<'a> {
    pub tbs_certificate: TbsCertificate<'a>,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    pub signature: BitStringRef<'a>,
}

#[derive(Debug, Sequence, ValueOrd)]
pub struct AttributeTypeAndValue<'a> {
    pub oid: ObjectIdentifier,
    pub value: AnyRef<'a>,
}

#[derive(Debug, Choice, ValueOrd)]
pub enum Time {
    #[asn1(type = "UTCTime")]
    UtcTime(UtcTime),

    #[asn1(type = "GeneralizedTime")]
    GeneralTime(GeneralizedTime),
}

#[derive(Debug, Sequence, ValueOrd)]
pub struct Validity {
    pub not_before: Time,
    pub not_after: Time,
}

#[derive(Debug, Sequence, ValueOrd)]
pub struct SubjectPublicKeyInfoRef<'a> {
    pub algorithm: AlgorithmIdentifier<'a>,
    pub public_key: BitStringRef<'a>,
}


#[derive(Debug, Sequence, ValueOrd)]
pub struct TbsCertificate<'a> {
    #[asn1(context_specific = "0", default = "Default::default")]
    pub version: Version,

    pub serial_number: IntRef<'a>,
    pub signature: AlgorithmIdentifier<'a>,
    pub issuer: SequenceOf<SetOf<AttributeTypeAndValue<'a>, 1>, 5>,

    pub validity: Validity,
    pub subject: SequenceOf<SetOf<AttributeTypeAndValue<'a>, 1>, 5>,
    pub subject_public_key_info: SubjectPublicKeyInfoRef<'a>,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub issuer_unique_id: Option<BitStringRef<'a>>,

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub subject_unique_id: Option<BitStringRef<'a>>,

    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    pub extensions: Option<AnyRef<'a>>,
}