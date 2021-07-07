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
//!     let mut record_buffer = [0; 16384];
//!     let tls_context = TlsContext::new(OsRng, &mut record_buffer)
//!         .with_server_name("http.sandbox.drogue.cloud");
//!     let mut tls: TlsConnection<OsRng, TcpStream, Aes128GcmSha256> =
//!         TlsConnection::new(tls_context, stream);
//!
//!     tls.open().await.expect("error establishing TLS connection");
//!
//!     println!("TLS session opened");
//! }
//! ```

pub(crate) mod fmt;

use parse_buffer::ParseError;
pub mod alert;
pub mod application_data;
//pub mod blocking;
pub mod blocking;
pub mod buffer;
pub mod certificate_types;
pub mod change_cipher_spec;
pub mod cipher_suites;
pub mod config;
mod connection;
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
pub mod traits;

pub use tls_connection::*;

#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TlsError {
    ConnectionClosed,
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

#[cfg(feature = "tokio")]
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
    use crate::{
        traits::{AsyncRead, AsyncWrite},
        TlsError,
    };
    use core::future::Future;
    use embassy::io::{AsyncBufReadExt, AsyncWriteExt};

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

    impl<R: AsyncBufReadExt + Unpin> AsyncRead for R {
        #[rustfmt::skip]
        type ReadFuture<'m> where Self: 'm = impl Future<Output = core::result::Result<usize, TlsError>> + 'm;
        fn read<'m>(&'m mut self, buf: &'m mut [u8]) -> Self::ReadFuture<'m> {
            async move {
                Ok(AsyncBufReadExt::read(self, buf)
                    .await
                    .map_err(|_| TlsError::IoError)?)
            }
        }
    }
}

#[cfg(feature = "futures")]
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

#[cfg(any(feature = "tokio", feature = "embassy", feature = "futures"))]
pub use runtime::*;

#[cfg(feature = "std")]
pub mod stdlib {
    extern crate std;
    use crate::{
        traits::{Read as TlsRead, Write as TlsWrite},
        TlsError,
    };
    use std::io::{Read, Write};
    use std::net::TcpStream;

    impl TlsRead for TcpStream {
        fn read<'m>(&'m mut self, buf: &'m mut [u8]) -> Result<usize, TlsError> {
            let len = Read::read(self, buf).map_err(|_| TlsError::IoError)?;
            Ok(len)
        }
    }

    impl TlsWrite for TcpStream {
        fn write<'m>(&'m mut self, buf: &'m [u8]) -> Result<usize, TlsError> {
            let len = Write::write(self, buf).map_err(|_| TlsError::IoError)?;
            Ok(len)
        }
    }
}

#[cfg(feature = "std")]
pub use stdlib::*;
