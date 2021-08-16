#![macro_use]
#![no_std]
#![allow(incomplete_features)]
#![allow(dead_code)]
#![cfg_attr(feature = "async", feature(generic_associated_types))]
#![cfg_attr(feature = "async", feature(type_alias_impl_trait))]

//! Drogue-TLS is a Rust-native TLS 1.3 implementation that works in a no-std environment. The
//! implementation is work in progress, but the [example clients](https://github.com/drogue-iot/drogue-tls/tree/main/examples) should work against the [rustls](https://github.com/ctz/rustls) echo server.
//!
//! The client supports both async and blocking modes. By default, the `async` and `std` features are enabled. The `async` feature requires Rust nightly, while the blocking feature works on Rust stable.
//! 
//! To use the async mode, import `drogue_tls::*`. To use the blocking mode, import `drogue_tls::blocking::*`.
//! 
//! Some features like certificate validation are still not implemented, have a look at [open issues](https://github.com/drogue-iot/drogue-tls/issues).
//! Only supports writing/receiving one frame at a time, hence using a frame buffer larger than 16k is not currently needed.  You may use a lower frame buffer size, but there is no guarantee that it will be able to parse any TLS 1.3 frame.
//! 
//! Usage of this crate should fit in 20 kB of RAM assuming a frame buffer of 16 kB (max TLS record size). This is not including the space used to hold the CA and any client certificates, which is not yet supported.
//! 
//! NOTE: This is very fresh and is probably not meeting all parts of the TLS 1.3 spec. Things like certificate validation and client certificate support is not complete.

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
mod alert;
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
}

#[cfg(feature = "std")]
pub use stdlib::*;
