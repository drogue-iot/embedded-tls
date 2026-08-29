//! Server-side TLS handshake encoding helpers.

use crate::TlsError;
use crate::buffer::CryptoBuffer;
use crate::extensions::ExtensionType;
use crate::extensions::extension_data::key_share::{KeyShareEntry, KeyShareServerHello};
use crate::extensions::extension_data::supported_groups::NamedGroup;
use crate::extensions::extension_data::supported_versions::{SupportedVersionsServerHello, TLS13};
use crate::extensions::messages::ServerHelloExtension;
use crate::handshake::HandshakeType;
use crate::handshake::LEGACY_VERSION;

/// Owned copy of a key share extracted from `ParsedClientHello`.
/// Needed because the record buffer is reused between reads (e.g. HRR flow).
pub(crate) struct OwnedKeyShare {
    pub group: NamedGroup,
    pub bytes: [u8; 65], // 65 for P-256 uncompressed, 32 for X25519
    pub len: usize,
}

/// Owned copy of ALPN protocols extracted from `ParsedClientHello`.
pub(crate) struct OwnedAlpn {
    pub data: [[u8; 32]; 4],
    pub lens: [usize; 4],
    pub count: usize,
}

impl OwnedAlpn {
    pub fn new() -> Self {
        Self {
            data: [[0u8; 32]; 4],
            lens: [0; 4],
            count: 0,
        }
    }
}

/// Encode a `ServerHello` handshake message (type byte + u24 length + payload).
pub fn encode_server_hello(
    buf: &mut CryptoBuffer<'_>,
    random: &[u8; 32],
    session_id: &[u8],
    cipher_suite: u16,
    server_public_key: &[u8],
    group: NamedGroup,
) -> Result<(), TlsError> {
    buf.push(HandshakeType::ServerHello as u8)
        .map_err(|_| TlsError::EncodeError)?;

    buf.with_u24_length(|buf| {
        // Legacy version
        buf.push_u16(LEGACY_VERSION)?;

        // Random
        buf.extend_from_slice(random)?;

        // Session ID (echo client's)
        buf.push(session_id.len() as u8)
            .map_err(|_| TlsError::EncodeError)?;
        buf.extend_from_slice(session_id)?;

        // Cipher suite
        buf.push_u16(cipher_suite)?;

        // Compression method (null)
        buf.push(0).map_err(|_| TlsError::EncodeError)?;

        // Extensions
        buf.with_u16_length(|buf| {
            // Supported Versions extension
            ServerHelloExtension::SupportedVersions(SupportedVersionsServerHello {
                selected_version: TLS13,
            })
            .encode(buf)?;

            // Key Share extension
            ServerHelloExtension::KeyShare(KeyShareServerHello(KeyShareEntry {
                group,
                opaque: server_public_key,
            }))
            .encode(buf)?;

            Ok(())
        })
    })
}

/// Encode a `HelloRetryRequest` handshake message.
pub fn encode_hello_retry_request(
    buf: &mut CryptoBuffer<'_>,
    session_id: &[u8],
    cipher_suite: u16,
    selected_group: NamedGroup,
) -> Result<(), TlsError> {
    buf.push(HandshakeType::ServerHello as u8)
        .map_err(|_| TlsError::EncodeError)?;

    buf.with_u24_length(|buf| {
        // Legacy version
        buf.push_u16(LEGACY_VERSION)?;

        // Fixed random value for HRR
        let hrr_random = [
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65,
            0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2,
            0xC8, 0xA8, 0x33, 0x9C,
        ];
        buf.extend_from_slice(&hrr_random)?;

        // Session ID (echo client's)
        buf.push(session_id.len() as u8)
            .map_err(|_| TlsError::EncodeError)?;
        buf.extend_from_slice(session_id)?;

        // Cipher suite
        buf.push_u16(cipher_suite)?;

        // Compression method (null)
        buf.push(0).map_err(|_| TlsError::EncodeError)?;

        // Extensions
        buf.with_u16_length(|buf| {
            // Supported Versions extension
            ServerHelloExtension::SupportedVersions(SupportedVersionsServerHello {
                selected_version: TLS13,
            })
            .encode(buf)?;

            // Key Share extension — HRR uses KeyShareHelloRetryRequest format:
            // just the selected group (2 bytes), NOT a full KeyShareEntry.
            ExtensionType::KeyShare.encode(buf)?;
            buf.with_u16_length(|buf| buf.push_u16(selected_group.as_u16()))?;

            Ok(())
        })
    })
}

/// Encode an `EncryptedExtensions` handshake message.
pub fn encode_encrypted_extensions(
    buf: &mut CryptoBuffer<'_>,
    selected_alpn: Option<&[u8]>,
) -> Result<(), TlsError> {
    buf.push(HandshakeType::EncryptedExtensions as u8)
        .map_err(|_| TlsError::EncodeError)?;

    buf.with_u24_length(|buf| {
        if let Some(protocol) = selected_alpn {
            // Extensions list with ALPN
            buf.with_u16_length(|buf| {
                // ALPN extension type = 0x0010
                buf.push_u16(0x0010)?;
                // Extension data length
                buf.with_u16_length(|buf| {
                    // Protocol name list length
                    buf.with_u16_length(|buf| {
                        // Single protocol name
                        buf.push(protocol.len() as u8)
                            .map_err(|_| TlsError::EncodeError)?;
                        buf.extend_from_slice(protocol)
                    })
                })
            })
        } else {
            // Empty extensions list
            buf.push_u16(0)?;
            Ok(())
        }
    })
}

/// Encode a `CertificateRequest` handshake message.
pub fn encode_certificate_request(buf: &mut CryptoBuffer<'_>) -> Result<(), TlsError> {
    buf.push(HandshakeType::CertificateRequest as u8)
        .map_err(|_| TlsError::EncodeError)?;

    buf.with_u24_length(|buf| {
        // certificate_request_context (empty)
        buf.push(0).map_err(|_| TlsError::EncodeError)?;

        // extensions
        buf.with_u16_length(|buf| {
            // signature_algorithms extension (type 0x000D)
            buf.push_u16(0x000D)?;
            buf.with_u16_length(|buf| {
                // SignatureSchemeList
                buf.with_u16_length(|buf| {
                    // ecdsa_secp256r1_sha256 = 0x0403
                    buf.push_u16(0x0403)?;
                    // ecdsa_secp384r1_sha384 = 0x0503
                    buf.push_u16(0x0503)?;
                    // rsa_pss_rsae_sha256 = 0x0804
                    buf.push_u16(0x0804)?;
                    Ok(())
                })
            })
        })
    })
}

/// Encode a Certificate handshake message with the given DER cert chain.
pub fn encode_certificate(
    buf: &mut CryptoBuffer<'_>,
    cert_chain: &[&[u8]],
) -> Result<(), TlsError> {
    buf.push(HandshakeType::Certificate as u8)
        .map_err(|_| TlsError::EncodeError)?;

    buf.with_u24_length(|buf| {
        // Request context (empty for server)
        buf.push(0).map_err(|_| TlsError::EncodeError)?;

        // Certificate list
        buf.with_u24_length(|buf| {
            for cert_der in cert_chain {
                // Certificate data
                buf.with_u24_length(|buf| buf.extend_from_slice(cert_der))?;
                // Extensions (empty)
                buf.push_u16(0)?;
            }
            Ok(())
        })
    })
}

/// Encode a `CertificateVerify` handshake message.
pub fn encode_certificate_verify(
    buf: &mut CryptoBuffer<'_>,
    signature_scheme: u16,
    signature: &[u8],
) -> Result<(), TlsError> {
    buf.push(HandshakeType::CertificateVerify as u8)
        .map_err(|_| TlsError::EncodeError)?;

    buf.with_u24_length(|buf| {
        buf.push_u16(signature_scheme)?;
        buf.with_u16_length(|buf| buf.extend_from_slice(signature))
    })
}

/// Encode a Finished handshake message.
pub fn encode_finished(buf: &mut CryptoBuffer<'_>, verify_data: &[u8]) -> Result<(), TlsError> {
    buf.push(HandshakeType::Finished as u8)
        .map_err(|_| TlsError::EncodeError)?;

    buf.with_u24_length(|buf| buf.extend_from_slice(verify_data))
}

/// Compute ECDH shared secret for a given key share.
/// Returns (`server_public_key_bytes`, `shared_secret_bytes`, group).
pub fn compute_ecdh(
    key_share: &KeyShareEntry<'_>,
    rng: &mut impl p256::elliptic_curve::rand_core::CryptoRngCore,
) -> Result<(heapless::Vec<u8, 65>, heapless::Vec<u8, 32>, NamedGroup), TlsError> {
    match key_share.group {
        NamedGroup::Secp256r1 => {
            let client_pk = p256::PublicKey::from_sec1_bytes(key_share.opaque)
                .map_err(|_| TlsError::InvalidKeyShare)?;
            let server_secret = p256::ecdh::EphemeralSecret::random(rng);
            let server_pk = p256::EncodedPoint::from(&server_secret.public_key());
            let shared = server_secret.diffie_hellman(&client_pk);

            let mut pk_bytes = heapless::Vec::new();
            pk_bytes
                .extend_from_slice(server_pk.as_bytes())
                .map_err(|_| TlsError::EncodeError)?;
            let mut secret_bytes = heapless::Vec::new();
            secret_bytes
                .extend_from_slice(shared.raw_secret_bytes())
                .map_err(|_| TlsError::EncodeError)?;

            Ok((pk_bytes, secret_bytes, NamedGroup::Secp256r1))
        }
        #[cfg(feature = "x25519")]
        NamedGroup::X25519 => {
            if key_share.opaque.len() != 32 {
                return Err(TlsError::InvalidKeyShare);
            }
            let mut client_key_bytes = [0u8; 32];
            client_key_bytes.copy_from_slice(key_share.opaque);
            let client_pk = x25519_dalek::PublicKey::from(client_key_bytes);

            let server_secret = x25519_dalek::EphemeralSecret::random_from_rng(rng);
            let server_pk = x25519_dalek::PublicKey::from(&server_secret);
            let shared = server_secret.diffie_hellman(&client_pk);

            let mut pk_bytes = heapless::Vec::new();
            pk_bytes
                .extend_from_slice(server_pk.as_bytes())
                .map_err(|_| TlsError::EncodeError)?;
            let mut secret_bytes = heapless::Vec::new();
            secret_bytes
                .extend_from_slice(shared.as_bytes())
                .map_err(|_| TlsError::EncodeError)?;

            Ok((pk_bytes, secret_bytes, NamedGroup::X25519))
        }
        _ => Err(TlsError::InvalidKeyShare),
    }
}
