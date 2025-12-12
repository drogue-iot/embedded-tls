use crate::TlsError;
use crate::config::{Certificate, TlsCipherSuite, TlsClock, TlsVerifier};
use crate::der_certificate::{DecodedCertificate, ECDSA_SHA256, ECDSA_SHA384, ED25519, Time};
#[cfg(feature = "alloc")]
use crate::der_certificate::{RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512};
use crate::extensions::extension_data::signature_algorithms::SignatureScheme;
use crate::handshake::{
    certificate::{
        Certificate as OwnedCertificate, CertificateEntryRef, CertificateRef as ServerCertificate,
    },
    certificate_verify::CertificateVerifyRef,
};
use crate::parse_buffer::ParseError;
use const_oid::ObjectIdentifier;
use core::marker::PhantomData;
use der::Decode;
use digest::Digest;
use heapless::{String, Vec};

const HOSTNAME_MAXLEN: usize = 64;
const COMMON_NAME_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

pub struct CertificateChain<'a> {
    prev: Option<&'a CertificateEntryRef<'a>>,
    chain: &'a ServerCertificate<'a>,
    idx: isize,
}

impl<'a> CertificateChain<'a> {
    pub fn new(ca: &'a CertificateEntryRef, chain: &'a ServerCertificate<'a>) -> Self {
        Self {
            prev: Some(ca),
            chain,
            idx: chain.entries.len() as isize - 1,
        }
    }
}

impl<'a> Iterator for CertificateChain<'a> {
    type Item = (&'a CertificateEntryRef<'a>, &'a CertificateEntryRef<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx < 0 {
            return None;
        }

        let cur = &self.chain.entries[self.idx as usize];
        let out = (self.prev.unwrap(), cur);

        self.prev = Some(cur);
        self.idx -= 1;

        Some(out)
    }
}

pub struct CertVerifier<CipherSuite, Clock, const CERT_SIZE: usize>
where
    Clock: TlsClock,
    CipherSuite: TlsCipherSuite,
{
    host: Option<heapless::String<64>>,
    certificate_transcript: Option<CipherSuite::Hash>,
    certificate: Option<OwnedCertificate<CERT_SIZE>>,
    _clock: PhantomData<Clock>,
}

impl<Cs, C, const CERT_SIZE: usize> Default for CertVerifier<Cs, C, CERT_SIZE>
where
    C: TlsClock,
    Cs: TlsCipherSuite,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<CipherSuite, Clock, const CERT_SIZE: usize> CertVerifier<CipherSuite, Clock, CERT_SIZE>
where
    Clock: TlsClock,
    CipherSuite: TlsCipherSuite,
{
    #[must_use]
    pub fn new() -> Self {
        Self {
            host: None,
            certificate_transcript: None,
            certificate: None,
            _clock: PhantomData,
        }
    }
}

impl<CipherSuite, Clock, const CERT_SIZE: usize> TlsVerifier<CipherSuite>
    for CertVerifier<CipherSuite, Clock, CERT_SIZE>
where
    CipherSuite: TlsCipherSuite,
    Clock: TlsClock,
{
    fn set_hostname_verification(&mut self, hostname: &str) -> Result<(), TlsError> {
        self.host.replace(
            heapless::String::try_from(hostname).map_err(|()| TlsError::InsufficientSpace)?,
        );
        Ok(())
    }

    fn verify_certificate(
        &mut self,
        transcript: &CipherSuite::Hash,
        ca: &Option<Certificate>,
        cert: ServerCertificate,
    ) -> Result<(), TlsError> {
        let ca = if let Some(ca) = ca {
            ca
        } else {
            error!("Verifying a certificate chain without ca is not implemented");
            return Err(TlsError::Unimplemented);
        };

        let mut cn = None;
        for (p, q) in CertificateChain::new(&ca.into(), &cert) {
            cn = verify_certificate(p, q, Clock::now())?;
        }
        if self.host.ne(&cn) {
            error!(
                "Hostname ({:?}) does not match CommonName ({:?})",
                self.host, cn
            );
            return Err(TlsError::InvalidCertificate);
        }

        self.certificate.replace(cert.try_into()?);
        self.certificate_transcript.replace(transcript.clone());
        Ok(())
    }

    fn verify_signature(&mut self, verify: CertificateVerifyRef) -> Result<(), TlsError> {
        let handshake_hash = unwrap!(self.certificate_transcript.take());
        let ctx_str = b"TLS 1.3, server CertificateVerify\x00";
        let mut msg: Vec<u8, 146> = Vec::new();
        msg.resize(64, 0x20).map_err(|()| TlsError::EncodeError)?;
        msg.extend_from_slice(ctx_str)
            .map_err(|()| TlsError::EncodeError)?;
        msg.extend_from_slice(&handshake_hash.finalize())
            .map_err(|()| TlsError::EncodeError)?;

        let certificate = unwrap!(self.certificate.as_ref()).try_into()?;
        verify_signature(&msg[..], &certificate, &verify)?;
        Ok(())
    }
}

fn verify_signature(
    message: &[u8],
    certificate: &ServerCertificate,
    verify: &CertificateVerifyRef,
) -> Result<(), TlsError> {
    let verified;

    let certificate =
        if let Some(CertificateEntryRef::X509(certificate)) = certificate.entries.first() {
            certificate
        } else {
            return Err(TlsError::DecodeError);
        };

    let certificate =
        DecodedCertificate::from_der(certificate).map_err(|_| TlsError::DecodeError)?;

    let public_key = certificate
        .tbs_certificate
        .subject_public_key_info
        .public_key
        .as_bytes()
        .ok_or(TlsError::DecodeError)?;

    match verify.signature_scheme {
        SignatureScheme::EcdsaSecp256r1Sha256 => {
            use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
            let verifying_key =
                VerifyingKey::from_sec1_bytes(public_key).map_err(|_| TlsError::DecodeError)?;
            let signature =
                Signature::from_der(&verify.signature).map_err(|_| TlsError::DecodeError)?;
            verified = verifying_key.verify(message, &signature).is_ok();
        }
        SignatureScheme::EcdsaSecp384r1Sha384 => {
            use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
            let verifying_key =
                VerifyingKey::from_sec1_bytes(public_key).map_err(|_| TlsError::DecodeError)?;
            let signature =
                Signature::from_der(&verify.signature).map_err(|_| TlsError::DecodeError)?;
            verified = verifying_key.verify(message, &signature).is_ok();
        }
        SignatureScheme::Ed25519 => {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            let verifying_key: VerifyingKey =
                VerifyingKey::from_bytes(public_key.try_into().unwrap())
                    .map_err(|_| TlsError::DecodeError)?;
            let signature =
                Signature::try_from(verify.signature).map_err(|_| TlsError::DecodeError)?;
            verified = verifying_key.verify(message, &signature).is_ok();
        }
        // #[cfg(feature = "alloc")]
        // SignatureScheme::RsaPkcs1Sha256 => {
        //     use rsa::{
        //         pkcs1v15::{Signature, VerifyingKey},
        //         signature::Verifier,
        //     };
        //     use sha2::Sha256;

        //     let verifying_key = VerifyingKey::<Sha256>::from_public_key_der(public_key)
        //         .map_err(|_| TlsError::DecodeError)?;

        //     let signature =
        //         Signature::try_from(verify.signature).map_err(|_| TlsError::DecodeError)?;
        //     verified = verifying_key.verify(message, &signature).is_ok();
        // }
        // #[cfg(feature = "alloc")]
        // SignatureScheme::RsaPkcs1Sha384 => {
        //     use rsa::{
        //         pkcs1::DecodeRsaPublicKey,
        //         pkcs1v15::{Signature, VerifyingKey},
        //         signature::Verifier,
        //     };
        //     use sha2::Sha384;

        //     let verifying_key =
        //         VerifyingKey::<Sha384>::from_pkcs1_der(public_key.try_into().unwrap())
        //             .map_err(|_| TlsError::DecodeError)?;

        //     let signature =
        //         Signature::try_from(verify.signature).map_err(|_| TlsError::DecodeError)?;
        //     verified = verifying_key.verify(message, &signature).is_ok();
        // }
        #[cfg(feature = "alloc")]
        SignatureScheme::RsaPssRsaeSha256 => {
            use rsa::{
                RsaPublicKey,
                pkcs1::DecodeRsaPublicKey,
                pss::{Signature, VerifyingKey},
                signature::Verifier,
            };
            use sha2::Sha256;

            let der_pubkey = RsaPublicKey::from_pkcs1_der(public_key).unwrap();
            let verifying_key = VerifyingKey::<Sha256>::from(der_pubkey);

            let signature =
                Signature::try_from(verify.signature).map_err(|_| TlsError::DecodeError)?;
            verified = verifying_key.verify(message, &signature).is_ok();
        }
        #[cfg(feature = "alloc")]
        SignatureScheme::RsaPssRsaeSha384 => {
            use rsa::{
                RsaPublicKey,
                pkcs1::DecodeRsaPublicKey,
                pss::{Signature, VerifyingKey},
                signature::Verifier,
            };
            use sha2::Sha384;

            let der_pubkey = RsaPublicKey::from_pkcs1_der(public_key).unwrap();
            let verifying_key = VerifyingKey::<Sha384>::from(der_pubkey);

            let signature =
                Signature::try_from(verify.signature).map_err(|_| TlsError::DecodeError)?;
            verified = verifying_key.verify(message, &signature).is_ok();
        }
        #[cfg(feature = "alloc")]
        SignatureScheme::RsaPssRsaeSha512 => {
            use rsa::{
                RsaPublicKey,
                pkcs1::DecodeRsaPublicKey,
                pss::{Signature, VerifyingKey},
                signature::Verifier,
            };
            use sha2::Sha512;

            let der_pubkey = RsaPublicKey::from_pkcs1_der(public_key).unwrap();
            let verifying_key = VerifyingKey::<Sha512>::from(der_pubkey);

            let signature =
                Signature::try_from(verify.signature).map_err(|_| TlsError::DecodeError)?;
            verified = verifying_key.verify(message, &signature).is_ok();
        }
        _ => {
            error!("InvalidSignatureScheme: {:?}", verify.signature_scheme);
            return Err(TlsError::InvalidSignatureScheme);
        }
    }

    if !verified {
        return Err(TlsError::InvalidSignature);
    }
    Ok(())
}

fn get_certificate_tlv_bytes<'a>(input: &[u8]) -> der::Result<&[u8]> {
    use der::{Decode, Reader, SliceReader};

    let mut reader = SliceReader::new(input)?;
    let top_header = der::Header::decode(&mut reader)?;
    top_header.tag().assert_eq(der::Tag::Sequence)?;

    let header = der::Header::peek(&mut reader)?;
    header.tag().assert_eq(der::Tag::Sequence)?;

    // Should we read the remaining two fields and call reader.finish() just be certain here?
    reader.tlv_bytes()
}

fn get_cert_time(time: Time) -> u64 {
    match time {
        Time::UtcTime(utc_time) => utc_time.to_unix_duration().as_secs(),
        Time::GeneralTime(generalized_time) => generalized_time.to_unix_duration().as_secs(),
    }
}

fn verify_certificate(
    verifier: &CertificateEntryRef,
    certificate: &CertificateEntryRef,
    now: Option<u64>,
) -> Result<Option<heapless::String<HOSTNAME_MAXLEN>>, TlsError> {
    let mut verified = false;
    let mut common_name = None;

    let ca_certificate = if let CertificateEntryRef::X509(verifier) = verifier {
        DecodedCertificate::from_der(verifier).map_err(|_| TlsError::DecodeError)?
    } else {
        return Err(TlsError::DecodeError);
    };

    if let CertificateEntryRef::X509(certificate) = certificate {
        let parsed_certificate =
            DecodedCertificate::from_der(certificate).map_err(|_| TlsError::DecodeError)?;

        let ca_public_key = ca_certificate
            .tbs_certificate
            .subject_public_key_info
            .public_key
            .as_bytes()
            .ok_or(TlsError::DecodeError)?;

        for elems in parsed_certificate.tbs_certificate.subject.iter() {
            let attrs = elems
                .get(0)
                .ok_or(TlsError::ParseError(ParseError::InvalidData))?;
            if attrs.oid == COMMON_NAME_OID {
                let mut v: Vec<u8, HOSTNAME_MAXLEN> = Vec::new();
                v.extend_from_slice(attrs.value.value())
                    .map_err(|_| TlsError::ParseError(ParseError::InvalidData))?;
                common_name = String::from_utf8(v).ok();
                debug!("CommonName: {:?}", common_name);
            }
        }

        if let Some(now) = now {
            if get_cert_time(parsed_certificate.tbs_certificate.validity.not_before) > now
                || get_cert_time(parsed_certificate.tbs_certificate.validity.not_after) < now
            {
                return Err(TlsError::InvalidCertificate);
            }
            debug!("Epoch is {} and certificate is valid!", now)
        }

        let certificate_data =
            get_certificate_tlv_bytes(certificate).map_err(|_| TlsError::DecodeError)?;

        match parsed_certificate.signature_algorithm {
            ECDSA_SHA256 => {
                use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
                let verifying_key = VerifyingKey::from_sec1_bytes(ca_public_key)
                    .map_err(|_| TlsError::DecodeError)?;

                let signature = Signature::from_der(
                    parsed_certificate
                        .signature
                        .as_bytes()
                        .ok_or(TlsError::ParseError(ParseError::InvalidData))?,
                )
                .map_err(|_| TlsError::ParseError(ParseError::InvalidData))?;

                verified = verifying_key.verify(&certificate_data, &signature).is_ok();
            }
            ECDSA_SHA384 => {
                use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
                let verifying_key = VerifyingKey::from_sec1_bytes(ca_public_key)
                    .map_err(|_| TlsError::DecodeError)?;

                let signature = Signature::from_der(
                    parsed_certificate
                        .signature
                        .as_bytes()
                        .ok_or(TlsError::ParseError(ParseError::InvalidData))?,
                )
                .map_err(|_| TlsError::ParseError(ParseError::InvalidData))?;

                verified = verifying_key.verify(&certificate_data, &signature).is_ok();
            }
            ED25519 => {
                use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                let verifying_key: VerifyingKey =
                    VerifyingKey::from_bytes(ca_public_key.try_into().unwrap())
                        .map_err(|_| TlsError::DecodeError)?;

                let signature = Signature::try_from(
                    parsed_certificate
                        .signature
                        .as_bytes()
                        .ok_or(TlsError::ParseError(ParseError::InvalidData))?,
                )
                .map_err(|_| TlsError::ParseError(ParseError::InvalidData))?;

                verified = verifying_key.verify(certificate_data, &signature).is_ok();
            }
            #[cfg(feature = "alloc")]
            a if a == RSA_PKCS1_SHA256 => {
                use rsa::{
                    pkcs1::DecodeRsaPublicKey,
                    pkcs1v15::{Signature, VerifyingKey},
                    signature::Verifier,
                };
                use sha2::Sha256;

                let verifying_key =
                    VerifyingKey::<Sha256>::from_pkcs1_der(ca_public_key).map_err(|e| {
                        error!("VerifyingKey: {}", e);
                        TlsError::DecodeError
                    })?;

                let signature = Signature::try_from(
                    parsed_certificate
                        .signature
                        .as_bytes()
                        .ok_or(TlsError::ParseError(ParseError::InvalidData))?,
                )
                .map_err(|e| {
                    error!("Signature: {}", e);
                    TlsError::ParseError(ParseError::InvalidData)
                })?;

                verified = verifying_key.verify(certificate_data, &signature).is_ok();
            }
            #[cfg(feature = "alloc")]
            a if a == RSA_PKCS1_SHA384 => {
                use rsa::{
                    pkcs1::DecodeRsaPublicKey,
                    pkcs1v15::{Signature, VerifyingKey},
                    signature::Verifier,
                };
                use sha2::Sha384;

                let verifying_key = VerifyingKey::<Sha384>::from_pkcs1_der(ca_public_key)
                    .map_err(|_| TlsError::DecodeError)?;

                let signature = Signature::try_from(
                    parsed_certificate
                        .signature
                        .as_bytes()
                        .ok_or(TlsError::ParseError(ParseError::InvalidData))?,
                )
                .map_err(|_| TlsError::ParseError(ParseError::InvalidData))?;

                verified = verifying_key.verify(certificate_data, &signature).is_ok();
            }
            #[cfg(feature = "alloc")]
            a if a == RSA_PKCS1_SHA512 => {
                use rsa::{
                    pkcs1::DecodeRsaPublicKey,
                    pkcs1v15::{Signature, VerifyingKey},
                    signature::Verifier,
                };
                use sha2::Sha512;

                let verifying_key = VerifyingKey::<Sha512>::from_pkcs1_der(ca_public_key)
                    .map_err(|_| TlsError::DecodeError)?;

                let signature = Signature::try_from(
                    parsed_certificate
                        .signature
                        .as_bytes()
                        .ok_or(TlsError::ParseError(ParseError::InvalidData))?,
                )
                .map_err(|_| TlsError::ParseError(ParseError::InvalidData))?;

                verified = verifying_key.verify(certificate_data, &signature).is_ok();
            }
            _ => {
                error!(
                    "Unsupported signature alg: {:?}",
                    parsed_certificate.signature_algorithm
                );
                return Err(TlsError::InvalidSignatureScheme);
            }
        }
    }

    if !verified {
        return Err(TlsError::InvalidCertificate);
    }

    Ok(common_name)
}
