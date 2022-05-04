#![no_std]
#![allow(incomplete_features)]
#![allow(dead_code)]
#![allow(non_snake_case)]
#![cfg_attr(feature = "async", feature(generic_associated_types))]
#![cfg_attr(feature = "async", feature(type_alias_impl_trait))]

//! Drogue-TLS is a Rust-native TLS 1.3 implementation that works in a no-std environment. The
//! implementation is work in progress, but the [example clients](https://github.com/drogue-iot/drogue-tls/tree/main/examples) should work against the [rustls](https://github.com/ctz/rustls) echo server.
//!
//! NOTE: This crate has been replaced by [embedded-tls](https://crates.io/crates/embedded-tls).
//!

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
pub mod traits;

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
}

#[cfg(all(feature = "tokio", feature = "async"))]
mod runtime {
    use crate::{
        traits::{AsyncRead, AsyncWrite},
        TlsError,
    };
    use core::future::Future;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    impl AsyncWrite for TcpStream {
        #[rustfmt::skip]
        type WriteFuture<'m> = impl Future<Output = Result<usize, TlsError>> + 'm where Self: 'm;
        fn write<'m>(&'m mut self, buf: &'m [u8]) -> Self::WriteFuture<'m> {
            async move {
                AsyncWriteExt::write(self, buf)
                    .await
                    .map_err(|_| TlsError::IoError)
            }
        }
    }

    impl AsyncRead for TcpStream {
        #[rustfmt::skip]
        type ReadFuture<'m> = impl Future<Output = Result<usize, TlsError>> + 'm where Self: 'm;
        fn read<'m>(&'m mut self, buf: &'m mut [u8]) -> Self::ReadFuture<'m> {
            async move {
                AsyncReadExt::read(self, buf)
                    .await
                    .map_err(|_| TlsError::IoError)
            }
        }
    }
}

#[cfg(all(feature = "futures", feature = "async"))]
mod runtime {
    use crate::{
        traits::{AsyncRead, AsyncWrite},
        TlsError,
    };
    use core::future::Future;
    use futures::io::{AsyncReadExt, AsyncWriteExt};

    impl<W: AsyncWriteExt + Unpin> AsyncWrite for W {
        #[rustfmt::skip]
        type WriteFuture<'m> where Self: 'm = impl Future<Output = core::result::Result<usize, TlsError>> + 'm;
        fn write<'m>(&'m mut self, buf: &'m [u8]) -> Self::WriteFuture<'m> {
            async move {
                Ok(AsyncWriteExt::write(self, buf)
                    .await
                    .map_err(|_| TlsError::IoError)?)
            }
        }
    }

    impl<R: AsyncReadExt + Unpin> AsyncRead for R {
        #[rustfmt::skip]
        type ReadFuture<'m> where Self: 'm = impl Future<Output = core::result::Result<usize, TlsError>> + 'm;
        fn read<'m>(&'m mut self, buf: &'m mut [u8]) -> Self::ReadFuture<'m> {
            async move {
                Ok(AsyncReadExt::read(self, buf)
                    .await
                    .map_err(|_| TlsError::IoError)?)
            }
        }
    }
}

#[cfg(all(feature = "async", any(feature = "tokio", feature = "futures")))]
pub use runtime::*;

#[cfg(feature = "std")]
mod stdlib {
    extern crate std;
    use crate::{
        config::TlsClock,
        traits::{Read as TlsRead, Write as TlsWrite},
        TlsError,
    };
    use std::io::{Read, Write};

    impl<R> TlsRead for R
    where
        R: Read,
    {
        fn read<'m>(&'m mut self, buf: &'m mut [u8]) -> Result<usize, TlsError> {
            let len = Read::read(self, buf).map_err(|_| TlsError::IoError)?;
            Ok(len)
        }
    }

    impl<W> TlsWrite for W
    where
        W: Write,
    {
        fn write<'m>(&'m mut self, buf: &'m [u8]) -> Result<usize, TlsError> {
            let len = Write::write(self, buf).map_err(|_| TlsError::IoError)?;
            Ok(len)
        }
    }

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
