use crate::buffer::CryptoBuffer;
use crate::extensions::ExtensionType;
use crate::parse_buffer::{ParseBuffer, ParseError};
use crate::TlsError;

use heapless::Vec;

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum PskKeyExchangeMode {
    PskKe = 0,
    PskDheKe = 1,
}
impl PskKeyExchangeMode {
    fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        match buf.read_u8()? {
            0 => Ok(Self::PskKe),
            1 => Ok(Self::PskDheKe),
            other => {
                warn!("Read unknown PskKeyExchangeMode: {}", other);
                Err(ParseError::InvalidData)
            }
        }
    }

    fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.push(*self as u8).map_err(|_| TlsError::EncodeError)
    }
}

pub struct PskKeyExchangeModes<const N: usize> {
    pub modes: Vec<PskKeyExchangeMode, N>,
}
impl<const N: usize> PskKeyExchangeModes<N> {
    pub const EXTENSION_TYPE: ExtensionType = ExtensionType::PskKeyExchangeModes;

    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        let data_length = buf.read_u8()?;

        let mut data = buf.slice(data_length as usize)?;
        let mut modes = Vec::new();
        while !data.is_empty() {
            modes
                .push(PskKeyExchangeMode::parse(&mut data)?)
                .map_err(|_| ParseError::InsufficientSpace)?;
        }

        Ok(Self { modes })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u8_length(|buf| {
            for mode in self.modes.iter() {
                mode.encode(buf)?;
            }
            Ok(())
        })
    }
}
