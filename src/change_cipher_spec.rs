use crate::{
    buffer::CryptoBuffer,
    parse_buffer::ParseBuffer,
    TlsError,
};
use generic_array::ArrayLength;

#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ChangeCipherSpec {}

impl ChangeCipherSpec {
    pub fn new() -> Self {
        Self {}
    }

    pub fn read(_rx_buf: &mut [u8]) -> Result<Self, TlsError> {
        // info!("change cipher spec of len={}", rx_buf.len());
        // TODO: Decode data
        Ok(Self {})
    }

    pub fn parse<N: ArrayLength<u8>>(_: &mut ParseBuffer) -> Result<Self, TlsError> {
        Ok(Self {})
    }

    pub(crate) fn encode(&self, buf: &mut CryptoBuffer<'_>) -> Result<(), TlsError> {
        buf.push(1).map_err(|_| TlsError::EncodeError)?;
        Ok(())
    }
}

impl Default for ChangeCipherSpec {
    fn default() -> Self {
        ChangeCipherSpec::new()
    }
}
