use heapless::{consts::*, Vec};

use crate::cipher_suites::CipherSuite;
use crate::crypto_engine::CryptoEngine;
use crate::extensions::common::KeyShareEntry;
use crate::extensions::server::ServerExtension;
use crate::handshake::Random;
use crate::parse_buffer::ParseBuffer;
use crate::TlsError;
use p256::ecdh::{EphemeralSecret, SharedSecret};
use p256::PublicKey;
use sha2::Digest;

#[derive(Debug)]
pub struct NewSessionTicket {
    lifetime: u32,
    age_add: u32,
    nonce: Vec<u8, U256>,
    ticket: Vec<u8, U256>,
    extensions: Vec<ServerExtension, U16>,
}

impl NewSessionTicket {
    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, TlsError> {
        let lifetime = buf.read_u32()?;
        let age_add = buf.read_u32()?;

        let nonce_length = buf.read_u8()?;
        let mut nonce = Vec::new();
        buf.copy(&mut nonce, nonce_length as usize)
            .map_err(|_| TlsError::InvalidNonceLength)?;

        let mut ticket = Vec::new();
        let ticket_length = buf.read_u16()?;
        if ticket_length > 255 {
            // Store slice instead?
            buf.slice(ticket_length as usize)?;
        } else {
            buf.copy(&mut ticket, ticket_length as usize)
                .map_err(|_| TlsError::InvalidTicketLength)?;
        }

        let _extensions_length = buf
            .read_u16()
            .map_err(|_| TlsError::InvalidExtensionsLength)?;
        let extensions = ServerExtension::parse_vector(buf)?;

        Ok(Self {
            lifetime,
            age_add,
            nonce,
            ticket,
            extensions,
        })
    }
}
