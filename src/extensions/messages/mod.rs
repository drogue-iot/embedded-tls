use crate::{extensions::ExtensionType, parse_buffer::ParseError};

pub mod client_hello;
pub mod encrypted_extensions;
pub mod server_hello;

fn unexpected_extension_type(ext_type: ExtensionType) -> ParseError {
    warn!("Read unexpected ExtensionType: {:?}", ext_type);
    // TODO: parse should return this TlsError:
    // Section 4.2.  Extensions
    // If an implementation receives an extension
    // which it recognizes and which is not specified for the message in
    // which it appears, it MUST abort the handshake with an
    // "illegal_parameter" alert.
    // return Err(TlsError::AbortHandshake(
    //     AlertLevel::Fatal,
    //     AlertDescription::IllegalParameter,
    // ));
    ParseError::InvalidData
}
