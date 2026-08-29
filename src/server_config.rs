//! Server-specific TLS configuration

use crate::config::CryptoProvider;

/// Server TLS configuration
pub struct TlsServerConfig<'a> {
    /// Server certificate chain (DER-encoded X.509), leaf first
    pub(crate) cert_chain: &'a [&'a [u8]],
    /// Server name (optional)
    pub(crate) server_name: Option<&'a str>,
    /// Whether to request client certificate authentication
    pub(crate) client_auth: bool,
    /// ALPN protocols supported by the server, in preference order
    pub(crate) alpn_protocols: Option<&'a [&'a [u8]]>,
}

impl<'a> TlsServerConfig<'a> {
    /// Create a new server configuration with the given certificate chain.
    ///
    /// The cert chain should be DER-encoded X.509 certificates, leaf first.
    #[must_use]
    pub fn new(cert_chain: &'a [&'a [u8]]) -> Self {
        Self {
            cert_chain,
            server_name: None,
            client_auth: false,
            alpn_protocols: None,
        }
    }

    /// Set server name.
    #[must_use]
    pub fn with_server_name(mut self, name: &'a str) -> Self {
        self.server_name = Some(name);
        self
    }

    /// Request client certificate authentication (mTLS).
    #[must_use]
    pub fn with_client_auth(mut self) -> Self {
        self.client_auth = true;
        self
    }

    /// Set ALPN protocols supported by the server, in preference order.
    #[must_use]
    pub fn with_alpn(mut self, protocols: &'a [&'a [u8]]) -> Self {
        self.alpn_protocols = Some(protocols);
        self
    }
}

/// Server TLS context combining config and crypto provider.
pub struct TlsServerContext<'a, Provider>
where
    Provider: CryptoProvider,
{
    pub(crate) config: &'a TlsServerConfig<'a>,
    pub(crate) crypto_provider: Provider,
}

impl<'a, Provider> TlsServerContext<'a, Provider>
where
    Provider: CryptoProvider,
{
    pub fn new(config: &'a TlsServerConfig<'a>, crypto_provider: Provider) -> Self {
        Self {
            config,
            crypto_provider,
        }
    }
}
