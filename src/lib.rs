#![macro_use]
#![no_std]
#![allow(incomplete_features)]
#![allow(dead_code)]
#![feature(generic_associated_types)]
use core::future::Future;

use parse_buffer::ParseError;

pub(crate) mod fmt;

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

#[derive(Debug, Copy, Clone)]
pub enum TlsError {
    Unimplemented,
    MissingHandshake,
    IoError,
    InternalError,
    InvalidRecord,
    UnknownContentType,
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
