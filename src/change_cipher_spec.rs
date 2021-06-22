use crate::parse_buffer::ParseBuffer;
use crate::{AsyncRead, AsyncWrite, TlsError};
use heapless::{ArrayLength, Vec};

#[derive(Debug, Copy, Clone)]
pub struct ChangeCipherSpec {}

impl ChangeCipherSpec {
    pub async fn read<T: AsyncRead>(socket: &mut T, len: u16) -> Result<Self, TlsError> {
        log::info!("application data of len={}", len);
        let mut buf: [u8; 2048] = [0; 2048];

        let mut num_read = 0;

        loop {
            num_read += socket
                .read(&mut buf[num_read..len as usize])
                .await
                .map_err(|_| TlsError::InvalidRecord)?;

            if num_read == len as usize {
                log::info!("read change cipher spec fully");
                break;
            }
        }
        Ok(Self {})
    }

    pub fn parse<N: ArrayLength<u8>>(buf: &mut ParseBuffer) -> Result<Self, TlsError> {
        Ok(Self {})
    }
}
