use crate::extensions::server::ServerExtension;
use crate::extensions::ExtensionType;
use crate::parse_buffer::ParseBuffer;
use crate::TlsError;
use heapless::Vec;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CertificateRequestRef<'a> {
    pub(crate) request_context: &'a [u8],
}

impl<'a> CertificateRequestRef<'a> {
    // Source: https://www.rfc-editor.org/rfc/rfc8446#section-4.2 table, rows marked with CR
    const ALLOWED_EXTENSIONS: &[ExtensionType] = &[
        ExtensionType::StatusRequest,
        ExtensionType::SignatureAlgorithms,
        ExtensionType::SignedCertificateTimestamp,
        ExtensionType::CertificateAuthorities,
        ExtensionType::OidFilters,
        ExtensionType::SignatureAlgorithmsCert,
    ];

    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<CertificateRequestRef<'a>, TlsError> {
        let request_context_len = buf
            .read_u8()
            .map_err(|_| TlsError::InvalidCertificateRequest)?;
        let request_context = buf
            .slice(request_context_len as usize)
            .map_err(|_| TlsError::InvalidCertificateRequest)?;

        let _extensions_length = buf
            .read_u16()
            .map_err(|_| TlsError::InvalidExtensionsLength)?;
        //info!("sh 5 {}", extensions_length);

        // Validate extensions
        ServerExtension::parse_vector::<6>(buf, Self::ALLOWED_EXTENSIONS)?;

        Ok(Self {
            request_context: request_context.as_slice(),
        })
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CertificateRequest {
    pub(crate) request_context: Vec<u8, 256>,
}

impl<'a> TryFrom<CertificateRequestRef<'a>> for CertificateRequest {
    type Error = TlsError;
    fn try_from(cert: CertificateRequestRef<'a>) -> Result<Self, Self::Error> {
        let mut request_context = Vec::new();
        request_context
            .extend_from_slice(cert.request_context)
            .map_err(|_| TlsError::InsufficientSpace)?;
        Ok(Self { request_context })
    }
}
