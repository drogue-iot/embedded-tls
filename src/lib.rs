#![macro_use]
#![no_std]
#![allow(incomplete_features)]
#![allow(dead_code)]
#![feature(generic_associated_types)]
#![feature(min_type_alias_impl_trait)]
//! An async, no-alloc TLS 1.3 client implementation for embedded devices.
//!
//!
//! Only supports writing/receiving one frame at a time, hence using a frame buffer larger than 16k is not currently needed.  You may use a lower frame buffer size, but there is no guarantee that it will be able to parse any TLS 1.3 frame.
//!
//!
//! Usage of this crate should fit in 20 kB of RAM assuming a frame buffer of 16 kB (max TLS record size). Some memory usage statistics:

//! # Example
//!
//! ```
//! use drogue_tls::*;
//! use core::future::Future;
//! use rand::rngs::OsRng;
//! use std::error::Error;
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//! use tokio::net::TcpStream;
//!
//! #[tokio::main]
//! async fn main() {
//!     let stream = TcpStream::connect("http.sandbox.drogue.cloud:443").await.expect("error creating TCP connection");
//!
//!     println!("TCP connection opened");
//!     let tls_config: TlsConfig<Aes128GcmSha256> = TlsConfig::new().with_server_name("http.sandbox.drogue.cloud");
//!     let mut tls: TlsConnection<OsRng, TcpStream, Aes128GcmSha256, 16384> =
//!         TlsConnection::new(tls_config, OsRng, stream);
//!
//!     tls.open().await.expect("error establishing TLS connection");
//!
//!     println!("TLS session opened");
//! }
//! ```

pub(crate) mod fmt;

use core::future::Future;
use parse_buffer::ParseError;
pub mod alert;
pub mod application_data;
pub mod buffer;
pub mod certificate_types;
pub mod change_cipher_spec;
pub mod cipher_suites;
pub mod config;
pub mod content_types;
pub mod crypto_engine;
pub mod extensions;
pub mod handshake;
pub mod key_schedule;
pub mod max_fragment_length;
pub mod named_groups;
pub mod parse_buffer;
pub mod record;
pub mod signature_schemes;
pub mod supported_versions;
pub mod tls_connection;

pub use config::*;
pub use tls_connection::*;

#[derive(Debug, Copy, Clone)]
pub enum TlsError {
    Unimplemented,
    MissingHandshake,
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
    UnableToInitializeCryptoEngine,
    ParseError(ParseError),
    CryptoError,
    EncodeError,
    DecodeError,
}

pub trait AsyncWrite {
    type WriteFuture<'m>: Future<Output = Result<usize, TlsError>>
    where
        Self: 'm;
    fn write<'m>(&'m mut self, buf: &'m [u8]) -> Self::WriteFuture<'m>;
}

pub trait AsyncRead {
    type ReadFuture<'m>: Future<Output = Result<usize, TlsError>>
    where
        Self: 'm;
    fn read<'m>(&'m mut self, buf: &'m mut [u8]) -> Self::ReadFuture<'m>;
}

#[cfg(feature = "tokio")]
mod runtime {
    use super::{AsyncRead, AsyncWrite, TlsError};
    use core::future::Future;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    impl AsyncWrite for TcpStream {
        #[rustfmt::skip]
        type WriteFuture<'m> where Self: 'm = impl Future<Output = Result<usize, TlsError>> + 'm;
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
        type ReadFuture<'m> where Self: 'm = impl Future<Output = Result<usize, TlsError>> + 'm;
        fn read<'m>(&'m mut self, buf: &'m mut [u8]) -> Self::ReadFuture<'m> {
            async move {
                AsyncReadExt::read(self, buf)
                    .await
                    .map_err(|_| TlsError::IoError)
            }
        }
    }
}

#[cfg(feature = "embassy")]
mod runtime {
    use super::{AsyncRead, AsyncWrite, TlsError};
    use core::future::Future;
    use embassy::io::{AsyncBufReadExt, AsyncWriteExt};

    impl<W: AsyncWriteExt> AsyncWrite for W {
        #[rustfmt::skip]
        type WriteFuture<'m> where Self: 'm = impl Future<Output = core::result::Result<usize, TlsError>> + 'm;
        fn write<'m>(&'m mut self, buf: &'m [u8]) -> Self::WriteFuture<'m> {
            async move { Ok(self.write(buf).await.map_err(|_| TlsError::IoError)?) }
        }
    }

    impl<R: AsyncBufReadExt> AsyncRead for R {
        #[rustfmt::skip]
        type ReadFuture<'m> where Self: 'm = impl Future<Output = core::result::Result<usize, TlsError>> + 'm;
        fn read<'m>(&'m mut self, buf: &'m mut [u8]) -> Self::ReadFuture<'m> {
            async move { Ok(self.read(buf).await.map_err(|_| TlsError::IoError)?) }
        }
    }
}

#[cfg(feature = "futures")]
mod runtime {
    use super::{AsyncRead, AsyncWrite, TlsError};
    use core::future::Future;
    use futures::io::{AsyncReadExt, AsyncWriteExt};

    impl<W: AsyncWriteExt + Unpin> AsyncWrite for W {
        #[rustfmt::skip]
        type WriteFuture<'m> where Self: 'm = impl Future<Output = core::result::Result<usize, TlsError>> + 'm;
        fn write<'m>(&'m mut self, buf: &'m [u8]) -> Self::WriteFuture<'m> {
            async move { Ok(self.write(buf).await.map_err(|_| TlsError::IoError)?) }
        }
    }

    impl<R: AsyncReadExt + Unpin> AsyncRead for R {
        #[rustfmt::skip]
        type ReadFuture<'m> where Self: 'm = impl Future<Output = core::result::Result<usize, TlsError>> + 'm;
        fn read<'m>(&'m mut self, buf: &'m mut [u8]) -> Self::ReadFuture<'m> {
            async move { Ok(self.read(buf).await.map_err(|_| TlsError::IoError)?) }
        }
    }
}

#[cfg(any(feature = "tokio", feature = "embassy", feature = "futures"))]
pub use runtime::*;
