#[derive(Debug)]
pub enum Error<E> {
    NotFound,
    PermissionDenied,
    ConnectionRefused,
    ConnectionReset,
    ConnectionAborted,
    NotConnected,
    AddrInUse,
    AddrNotAvailable,
    BrokenPipe,
    AlreadyExists,
    WouldBlock,
    InvalidInput,
    InvalidData,
    TimedOut,
    WriteZero,
    Interrupted,
    Other(E),
    UnexpectedEof,
}

pub type Result<T, E> = core::result::Result<T, Error<E>>;

pub trait Read {
    type IoError;
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::IoError>;
}

pub trait Write {
    type IoError;
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::IoError>;
    fn flush(&mut self) -> Result<(), Self::IoError>;
}