use crate::TlsError;
use crate::buffer::CryptoBuffer;
use crate::parse_buffer::ParseBuffer;

#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ChangeCipherSpec {}

#[allow(clippy::unnecessary_wraps)] // TODO
impl ChangeCipherSpec {
    pub fn new() -> Self {
        Self {}
    }

    pub fn read(_rx_buf: &mut [u8]) -> Result<Self, TlsError> {
        // info!("change cipher spec of len={}", rx_buf.len());
        // TODO: Decode data
        Ok(Self {})
    }

    #[allow(dead_code)]
    pub fn parse(_: &mut ParseBuffer) -> Result<Self, TlsError> {
        Ok(Self {})
    }

    #[allow(dead_code, clippy::unused_self)]
    pub(crate) fn encode(self, buf: &mut CryptoBuffer<'_>) -> Result<(), TlsError> {
        buf.push(1).map_err(|_| TlsError::EncodeError)?;
        Ok(())
    }
}

impl Default for ChangeCipherSpec {
    fn default() -> Self {
        ChangeCipherSpec::new()
    }
}
