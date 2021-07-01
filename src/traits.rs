use crate::TlsError;
use core::future::Future;

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
