#![no_std]
#![allow(incomplete_features)]
#![allow(dead_code)]
#![allow(non_snake_case)]
#![cfg_attr(feature = "async", feature(generic_associated_types))]
#![cfg_attr(feature = "async", feature(type_alias_impl_trait))]

//! Embedded-TLS is a Rust-native TLS 1.3 implementation that works in a no-std environment. The
//! implementation is work in progress, but the [example clients](https://github.com/drogue-iot/embedded-tls/tree/main/examples) should work against the [rustls](https://github.com/ctz/rustls) echo server.
//!
//! The client supports both async and blocking modes. By default, the `async` and `std` features are enabled. The `async` feature requires Rust nightly, while the blocking feature works on Rust stable.
//!
//! To use the async mode, import `embedded_tls::*`. To use the blocking mode, import `embedded_tls::blocking::*`.
//!
//! Some features like certificate validation are still not implemented, have a look at [open issues](https://github.com/drogue-iot/embedded-tls/issues).
//! Only supports writing/receiving one frame at a time, hence using a frame buffer larger than 16k is not currently needed.  You may use a lower frame buffer size, but there is no guarantee that it will be able to parse any TLS 1.3 frame.
//!
//! Usage of this crate should fit in 20 kB of RAM assuming a frame buffer of 16 kB (max TLS record size). This is not including the space used to hold the CA and any client certificates.
//!
//! Some memory usage statistics for async operation:
//!
//! * TlsConnection: frame_buffer size + 2kB for the rest. This can probably be reduced with some additional tuning.
//! * Handshake stack usage: currently at 2 kB
//! * Write stack usage: currently at 560 B
//! * Read stack usage: currently at 232 B
//!
//!
//! NOTE: This is very fresh and is probably not meeting all parts of the TLS 1.3 spec. If you find anything you'd like to get implemented, feel free to raise an issue.

//! # Example
//!
//! ```
//! use embedded_tls::*;
//! use embedded_io::adapters::FromTokio;
//! use rand::rngs::OsRng;
//! use tokio::net::TcpStream;
//!
//! #[tokio::main]
//! async fn main() {
//!     let stream = TcpStream::connect("http.sandbox.drogue.cloud:443").await.expect("error creating TCP connection");
//!
//!     println!("TCP connection opened");
//!     let mut record_buffer = [0; 16384];
//!     let config = TlsConfig::new()
//!         .verify_cert(false)
//!         .with_server_name("http.sandbox.drogue.cloud");
//!     let mut tls: TlsConnection<FromTokio<TcpStream>, Aes128GcmSha256> =
//!         TlsConnection::new(FromTokio::new(stream), &mut record_buffer);
//!
//!     tls.open::<OsRng, NoClock, 4096>(TlsContext::new(&config, &mut OsRng)).await.expect("error establishing TLS connection");
//!
//!     println!("TLS session opened");
//! }
//! ```

pub(crate) mod fmt;

use parse_buffer::ParseError;
pub mod alert;
mod application_data;
pub mod blocking;
mod buffer;
mod certificate_types;
mod change_cipher_spec;
mod cipher_suites;
mod config;
mod connection;
mod content_types;
mod crypto_engine;
mod extensions;
mod handshake;
mod key_schedule;
mod max_fragment_length;
mod named_groups;
mod parse_buffer;
mod record;
mod signature_schemes;
mod supported_versions;

#[cfg(feature = "webpki")]
mod verify;

// TODO: Fix `ring` crate to build for ARM embedded targets
#[cfg(not(feature = "webpki"))]
mod verify {
    pub(crate) fn verify_signature<'a, CipherSuite>(
        config: &crate::config::TlsConfig<'a, CipherSuite>,
        _message: &[u8],
        _certificate: crate::handshake::certificate::CertificateRef,
        _verify: crate::handshake::certificate_verify::CertificateVerify,
    ) -> Result<(), crate::TlsError>
    where
        CipherSuite: crate::config::TlsCipherSuite + 'static,
    {
        if config.verify_cert {
            todo!("Not implemented!")
        } else {
            Ok(())
        }
    }

    pub(crate) fn verify_certificate<'a, CipherSuite>(
        config: &crate::config::TlsConfig<'a, CipherSuite>,
        _certificate: &crate::handshake::certificate::CertificateRef,
        _now: Option<u64>,
    ) -> Result<(), crate::TlsError>
    where
        CipherSuite: crate::config::TlsCipherSuite + 'static,
    {
        if config.verify_cert {
            todo!("Not implemented!")
        } else {
            Ok(())
        }
    }
}

#[cfg(feature = "async")]
mod tls_connection;

#[cfg(feature = "async")]
pub use tls_connection::*;

#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TlsError {
    ConnectionClosed,
    Unimplemented,
    MissingHandshake,
    HandshakeAborted(alert::AlertLevel, alert::AlertDescription),
    IoError,
    InternalError,
    InvalidRecord,
    UnknownContentType,
    InvalidNonceLength,
    InvalidTicketLength,
    UnknownExtensionType,
    InsufficientSpace,
    InvalidHandshake,
    InvalidCipherSuite,
    InvalidSignatureScheme,
    InvalidSignature,
    InvalidExtensionsLength,
    InvalidSessionIdLength,
    InvalidSupportedVersions,
    InvalidApplicationData,
    InvalidKeyShare,
    InvalidCertificate,
    InvalidCertificateEntry,
    InvalidCertificateRequest,
    UnableToInitializeCryptoEngine,
    ParseError(ParseError),
    OutOfMemory,
    CryptoError,
    EncodeError,
    DecodeError,
    Io(embedded_io::ErrorKind),
}

#[cfg(feature = "std")]
mod stdlib {
    extern crate std;
    use crate::config::TlsClock;

    use std::time::SystemTime;
    impl TlsClock for SystemTime {
        fn now() -> Option<u64> {
            Some(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            )
        }
    }
}

#[cfg(feature = "std")]
pub use stdlib::*;
