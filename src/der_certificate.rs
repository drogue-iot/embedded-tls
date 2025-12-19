use core::cmp::Ordering;
use der::asn1::{
    BitStringRef, GeneralizedTime, IntRef, ObjectIdentifier, SequenceOf, SetOf, UtcTime,
};
use der::{AnyRef, Choice, Enumerated, Sequence, ValueOrd};

#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Sequence, ValueOrd)]
pub struct AlgorithmIdentifier<'a> {
    pub oid: ObjectIdentifier,
    pub parameters: Option<AnyRef<'a>>,
}

#[cfg(feature = "defmt")]
impl<'a> defmt::Format for AlgorithmIdentifier<'a> {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "AlgorithmIdentifier:{}", &self.oid.as_bytes())
    }
}

pub const ECDSA_SHA256: AlgorithmIdentifier = AlgorithmIdentifier {
    oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
    parameters: None,
};
pub const ECDSA_SHA384: AlgorithmIdentifier = AlgorithmIdentifier {
    oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3"),
    parameters: None,
};
pub const ED25519: AlgorithmIdentifier = AlgorithmIdentifier {
    oid: ObjectIdentifier::new_unwrap("1.3.101.112"),
    parameters: None,
};
#[cfg(feature = "rsa")]
pub const RSA_PKCS1_SHA256: AlgorithmIdentifier = AlgorithmIdentifier {
    oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
    parameters: Some(AnyRef::NULL),
};
#[cfg(feature = "rsa")]
pub const RSA_PKCS1_SHA384: AlgorithmIdentifier = AlgorithmIdentifier {
    oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12"),
    parameters: Some(AnyRef::NULL),
};
#[cfg(feature = "rsa")]
pub const RSA_PKCS1_SHA512: AlgorithmIdentifier = AlgorithmIdentifier {
    oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13"),
    parameters: Some(AnyRef::NULL),
};

#[derive(Debug, Clone, PartialEq, Eq, Copy, Enumerated)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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

#[cfg(feature = "defmt")]
impl<'a> defmt::Format for AttributeTypeAndValue<'a> {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(
            fmt,
            "Attribute:{} Value:{}",
            &self.oid.as_bytes(),
            &self.value.value()
        )
    }
}

#[derive(Debug, Choice, ValueOrd)]
pub enum Time {
    #[asn1(type = "UTCTime")]
    UtcTime(UtcTime),

    #[asn1(type = "GeneralizedTime")]
    GeneralTime(GeneralizedTime),
}

#[cfg(feature = "defmt")]
impl defmt::Format for Time {
    fn format(&self, fmt: defmt::Formatter) {
        match self {
            Time::UtcTime(utc_time) => {
                defmt::write!(fmt, "UtcTime:{}", utc_time.to_unix_duration())
            }
            Time::GeneralTime(generalized_time) => {
                defmt::write!(fmt, "GeneralTime:{}", generalized_time.to_unix_duration())
            }
        }
    }
}

#[derive(Debug, Sequence, ValueOrd)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Validity {
    pub not_before: Time,
    pub not_after: Time,
}

#[derive(Debug, Sequence, ValueOrd)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SubjectPublicKeyInfoRef<'a> {
    pub algorithm: AlgorithmIdentifier<'a>,
    pub public_key: BitStringRef<'a>,
}

#[derive(Debug, Sequence, ValueOrd)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TbsCertificate<'a> {
    #[asn1(context_specific = "0", default = "Default::default")]
    pub version: Version,

    pub serial_number: IntRef<'a>,
    pub signature: AlgorithmIdentifier<'a>,
    pub issuer: SequenceOf<SetOf<AttributeTypeAndValue<'a>, 1>, 7>,

    pub validity: Validity,
    pub subject: SequenceOf<SetOf<AttributeTypeAndValue<'a>, 1>, 7>,
    pub subject_public_key_info: SubjectPublicKeyInfoRef<'a>,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub issuer_unique_id: Option<BitStringRef<'a>>,

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub subject_unique_id: Option<BitStringRef<'a>>,

    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    pub extensions: Option<AnyRef<'a>>,
}
