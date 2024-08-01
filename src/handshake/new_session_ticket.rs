use core::marker::PhantomData;

use crate::extensions::messages::NewSessionTicketExtension;
use crate::parse_buffer::ParseBuffer;
use crate::{unused, TlsError};

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NewSessionTicket<'a> {
    _todo: PhantomData<&'a ()>,
}

impl<'a> NewSessionTicket<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<NewSessionTicket<'a>, TlsError> {
        let lifetime = buf.read_u32()?;
        let age_add = buf.read_u32()?;

        let nonce_length = buf.read_u8()?;
        let nonce = buf
            .slice(nonce_length as usize)
            .map_err(|_| TlsError::InvalidNonceLength)?;

        let ticket_length = buf.read_u16()?;
        let ticket = buf
            .slice(ticket_length as usize)
            .map_err(|_| TlsError::InvalidTicketLength)?;

        let extensions = NewSessionTicketExtension::parse_vector::<1>(buf)?;

        unused((lifetime, age_add, nonce, ticket, extensions));
        Ok(Self { _todo: PhantomData })
    }
}
