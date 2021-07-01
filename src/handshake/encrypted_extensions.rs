use crate::extensions::server::ServerExtension;

use crate::parse_buffer::ParseBuffer;
use crate::TlsError;
use heapless::{consts::*, Vec};

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EncryptedExtensions<'a> {
    extensions: Vec<ServerExtension<'a>, U16>,
}

impl<'a> EncryptedExtensions<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<EncryptedExtensions<'a>, TlsError> {
        //let extensions_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        let extensions_len = buf
            .read_u16()
            .map_err(|_| TlsError::InvalidExtensionsLength)?;
        // info!("extensions length: {}", extensions_len);
        let extensions =
            ServerExtension::parse_vector(&mut buf.slice(extensions_len as usize).unwrap())?;
        Ok(Self { extensions })
    }
}
