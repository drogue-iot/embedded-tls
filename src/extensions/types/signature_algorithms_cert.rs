use crate::buffer::CryptoBuffer;
use crate::extensions::types::signature_algorithms::SignatureScheme;
use crate::extensions::ExtensionType;
use crate::parse_buffer::{ParseBuffer, ParseError};
use crate::TlsError;

use heapless::Vec;

pub struct SignatureAlgorithmsCert<const N: usize> {
    pub supported_signature_algorithms: Vec<SignatureScheme, N>,
}

impl<const N: usize> SignatureAlgorithmsCert<N> {
    pub const EXTENSION_TYPE: ExtensionType = ExtensionType::SignatureAlgorithmsCert;

    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        let data_length = buf.read_u16()?;

        let mut data = buf.slice(data_length as usize)?;
        let mut supported_signature_algorithms = Vec::new();
        while !data.is_empty() {
            supported_signature_algorithms
                .push(SignatureScheme::parse(&mut data)?)
                .map_err(|_| ParseError::InsufficientSpace)?;
        }

        Ok(Self {
            supported_signature_algorithms,
        })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u16_length(|buf| {
            for &a in self.supported_signature_algorithms.iter() {
                buf.push_u16(a as u16).map_err(|_| TlsError::EncodeError)?;
            }
            Ok(())
        })
    }
}
