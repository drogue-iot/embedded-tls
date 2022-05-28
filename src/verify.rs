use crate::config::{Certificate, TlsCipherSuite, TlsConfig};
use crate::handshake::{
    certificate::{CertificateEntryRef, CertificateRef as ServerCertificate},
    certificate_verify::CertificateVerify,
};
use crate::TlsError;
use webpki::DnsNameRef;

static ALL_SIGALGS: &[&webpki::SignatureAlgorithm] = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::ED25519,
];

pub(crate) fn verify_signature<'a, CipherSuite>(
    config: &TlsConfig<'a, CipherSuite>,
    message: &[u8],
    certificate: ServerCertificate,
    verify: CertificateVerify,
) -> Result<(), TlsError>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    let mut verified = false;
    if config.verify_cert {
        if !certificate.entries.is_empty() {
            // TODO: Support intermediates...
            if let CertificateEntryRef::X509(certificate) = certificate.entries[0] {
                let cert = webpki::EndEntityCert::try_from(certificate).map_err(|e| {
                    warn!("Error loading cert: {:?}", e);
                    TlsError::DecodeError
                })?;

                trace!(
                    "Verifying with signature scheme {:?}",
                    verify.signature_scheme
                );
                info!("Signature: {:x?}", verify.signature);
                let pkisig = verify.signature_scheme.try_into()?;
                match cert.verify_signature(pkisig, message, verify.signature) {
                    Ok(_) => {
                        verified = true;
                    }
                    Err(e) => {
                        info!("Error verifying signature: {:?}", e);
                    }
                }
            }
        }
    }
    if !verified && config.verify_cert {
        return Err(TlsError::InvalidSignature);
    }
    Ok(())
}

pub(crate) fn verify_certificate<'a, CipherSuite>(
    config: &TlsConfig<'a, CipherSuite>,
    certificate: &ServerCertificate,
    now: Option<u64>,
) -> Result<(), TlsError>
where
    CipherSuite: TlsCipherSuite + 'static,
{
    let mut verified = false;
    let mut host_verified = false;
    if config.verify_cert {
        if let Some(Certificate::X509(ca)) = config.ca {
            let trust = webpki::TrustAnchor::try_from_cert_der(ca).map_err(|e| {
                warn!("Error loading CA: {:?}", e);
                TlsError::DecodeError
            })?;
            let anchors = &[trust];
            let anchors = webpki::TLSServerTrustAnchors(anchors);

            trace!("We got {} certificate entries", certificate.entries.len());

            if !certificate.entries.is_empty() {
                // TODO: Support intermediates...
                if let CertificateEntryRef::X509(certificate) = certificate.entries[0] {
                    let cert = webpki::EndEntityCert::try_from(certificate).map_err(|e| {
                        warn!("Error loading cert: {:?}", e);
                        TlsError::DecodeError
                    })?;

                    let time = if let Some(now) = now {
                        webpki::Time::from_seconds_since_unix_epoch(now)
                    } else {
                        // If no clock is provided, use certificate notAfter as the timestamp, if available
                        if let Ok(validity) = cert.validity() {
                            validity.not_after
                        } else {
                            webpki::Time::from_seconds_since_unix_epoch(0)
                        }
                    };
                    info!("Certificate is loaded!");
                    match cert.verify_is_valid_tls_server_cert(ALL_SIGALGS, &anchors, &[], time) {
                        Ok(_) => verified = true,
                        Err(e) => {
                            warn!("Error verifying certificate: {:?}", e);
                        }
                    }

                    if config.verify_host && config.server_name.is_some() {
                        match cert.verify_is_valid_for_dns_name(
                            DnsNameRef::try_from_ascii_str(config.server_name.unwrap()).unwrap(),
                        ) {
                            Ok(_) => host_verified = true,
                            Err(e) => {
                                warn!("Error verifying host: {:?}", e);
                            }
                        }
                    }
                }
            }
        }
    } else {
        // Disable host verification if cert verification is disabled
        host_verified = true;
    }
    if !verified && config.verify_cert {
        return Err(TlsError::InvalidCertificate);
    }

    if !host_verified && config.verify_host {
        return Err(TlsError::InvalidCertificate);
    }
    Ok(())
}
