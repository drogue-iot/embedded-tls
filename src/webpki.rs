use crate::TlsError;
use crate::decoded_certificate::DecodedCertificate;
use crate::config::{Certificate, TlsCipherSuite, TlsClock, TlsVerifier};
use crate::extensions::extension_data::signature_algorithms::SignatureScheme;
use crate::handshake::{
    certificate::{
        Certificate as OwnedCertificate, CertificateEntryRef, CertificateRef as ServerCertificate,
    },
    certificate_verify::CertificateVerifyRef,
};
use crate::parse_buffer::ParseError;
use core::marker::PhantomData;
use digest::Digest;
use heapless::Vec;
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
        verify_certificate(self.host.as_deref(), ca, &cert, Clock::now())?;
        self.certificate.replace(cert.try_into()?);
        self.certificate_transcript.replace(transcript.clone());
        Ok(())
    }

    fn verify_signature(&mut self, verify: CertificateVerifyRef) -> Result<(), TlsError> {
        let handshake_hash = unwrap!(self.certificate_transcript.take());
        let ctx_str = b"TLS 1.3, server CertificateVerify\x00";
        let mut msg: Vec<u8, 130> = Vec::new();
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
    let mut verified = false;

    if certificate.entries.len() != 1 {
        return Err(TlsError::InvalidCertificate);
    }

    let certificate = if let CertificateEntryRef::X509(certificate) = certificate.entries[0] {
        certificate
    } else {
        return Err(TlsError::Unimplemented);
    };

    use der::Decode;

    let certificate =
        DecodedCertificate::from_der(certificate).map_err(|_e| TlsError::DecodeError)?;

    let public_key = certificate
        .tbs_certificate
        .subject_public_key_info
        .public_key
        .as_bytes()
        .ok_or(TlsError::DecodeError)?;

    match verify.signature_scheme {
        SignatureScheme::EcdsaSecp256r1Sha256 => {
            use p256::ecdsa::{VerifyingKey, signature::Verifier};

            let verifying_key =
                VerifyingKey::from_sec1_bytes(public_key).map_err(|_e| TlsError::DecodeError)?;
            let signature = p256::ecdsa::Signature::from_der(&verify.signature)
                .map_err(|_| TlsError::DecodeError)?;

            verified = verifying_key.verify(message, &signature).is_ok();
        }
        _ => {
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
    top_header.tag.assert_eq(der::Tag::Sequence)?;

    let header = der::Header::peek(&mut reader)?;
    header.tag.assert_eq(der::Tag::Sequence)?;

    // Should we read the remaining two fields and call reader.finish() just be certain here?
    reader.tlv_bytes()
}

fn verify_certificate(
    verify_host: Option<&str>,
    ca: &Option<Certificate>,
    certificate: &ServerCertificate,
    now: Option<u64>,
) -> Result<(), TlsError> {
    let mut verified = false;
    let mut host_verified = false;

    let ca = if let Some(Certificate::X509(ca)) = ca {
        ca
    } else {
        return Err(TlsError::Unimplemented);
    };

    // TODO: Support intermediates...

    use der::Decode;

    let ca_certificate =
        DecodedCertificate::from_der(ca).map_err(|_e| TlsError::DecodeError)?;

    if let CertificateEntryRef::X509(certificate) = certificate.entries[0] {
        let parsed_certificate = DecodedCertificate::from_der(certificate)
            .map_err(|_e| TlsError::DecodeError)?;

        let ca_public_key = ca_certificate
            .tbs_certificate
            .subject_public_key_info
            .public_key
            .as_bytes()
            .ok_or(TlsError::DecodeError)?;

        use p256::ecdsa::{VerifyingKey, signature::Verifier};

        let verifying_key =
            VerifyingKey::from_sec1_bytes(ca_public_key).map_err(|_e| TlsError::DecodeError)?;

        info!(
            "Signature alg: {:?}",
            parsed_certificate.signature_algorithm
        );

        let signature = p256::ecdsa::Signature::from_der(
            parsed_certificate
                .signature
                .as_bytes()
                .ok_or(TlsError::ParseError(ParseError::InvalidData))?,
        )
        .map_err(|_| TlsError::ParseError(ParseError::InvalidData))?;

        let certificate_data =
            get_certificate_tlv_bytes(certificate).map_err(|e| TlsError::DecodeError)?;

        verified = verifying_key.verify(&certificate_data, &signature).is_ok();
    }

    if !verified {
        return Err(TlsError::InvalidCertificate);
    }

    if !host_verified && verify_host.is_some() {
        return Err(TlsError::InvalidCertificate);
    }
    Ok(())
}
