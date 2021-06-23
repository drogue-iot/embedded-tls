use crate::parse_buffer::ParseBuffer;
use crate::TlsError;
use heapless::ArrayLength;

#[derive(Debug, Copy, Clone)]
pub struct ChangeCipherSpec {}

impl ChangeCipherSpec {
    pub async fn read(rx_buf: &mut [u8]) -> Result<Self, TlsError> {
        info!("change cipher spec of len={}", rx_buf.len());
        // TODO: Decode data
        Ok(Self {})
    }

    pub fn parse<N: ArrayLength<u8>>(_: &mut ParseBuffer) -> Result<Self, TlsError> {
        Ok(Self {})
    }
}
