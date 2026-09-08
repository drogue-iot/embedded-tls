#![cfg(feature = "webpki")]

use aes_gcm::Aes128Gcm;
use embedded_io_adapters::tokio_1::FromTokio;
use embedded_tls::webpki::CertVerifier;
use embedded_tls::{Aes128GcmSha256, CryptoProvider, TlsVerifier};
use hmac::Hmac;
use sha2::Sha256;
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::SystemTime;

mod tlsserver;

static LOG_INIT: OnceLock<()> = OnceLock::new();

struct WebPkiProvider<'a> {
    rng: rand::rngs::OsRng,
    verifier: CertVerifier<'a, Sha256, SystemTime, 4096>,
}

impl CryptoProvider for WebPkiProvider<'_> {
    type CipherSuite = Aes128GcmSha256;
    type Signature = &'static [u8];
    type Hash = Sha256;
    type Hmac = Hmac<Sha256>;
    type Aead = Aes128Gcm;

    fn rng(&mut self) -> impl embedded_tls::CryptoRngCore {
        &mut self.rng
    }

    fn aead(&mut self, key: &[u8]) -> Result<Self::Aead, embedded_tls::TlsError> {
        use aes_gcm::aead::KeyInit;
        Self::Aead::new_from_slice(key).map_err(|_| embedded_tls::TlsError::CryptoError)
    }

    fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Sha256>, embedded_tls::TlsError> {
        Ok(&mut self.verifier)
    }
}

fn init_log() {
    LOG_INIT.get_or_init(|| {
        env_logger::init();
    });
}

async fn setup() -> SocketAddr {
    init_log();

    use mio::net::TcpListener;
    use std::net::{IpAddr, Ipv4Addr};

    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("cannot listen on port");

    let addr = listener
        .local_addr()
        .expect("error retrieving socket address");

    std::thread::spawn(move || {
        tlsserver::run(listener);
    });

    log::info!("Server at {:?}", addr);
    addr
}

#[tokio::test]
async fn test_server_certificate_validation() {
    use embedded_tls::*;

    let addr = setup().await;
    let pem = include_str!("data/ca-cert.pem");
    let der = pem_parser::pem_to_der(pem);

    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("error connecting to server");

    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];

    // Hostname verification is not enabled
    let config = TlsConfig::new();

    let mut tls = TlsConnection::new(
        FromTokio::new(stream),
        &mut read_record_buffer,
        &mut write_record_buffer,
    );

    let open_fut = tls.open(TlsContext::new(
        &config,
        WebPkiProvider {
            rng: rand::rngs::OsRng,
            verifier: CertVerifier::new(Certificate::X509(&der[..])),
        },
    ));

    open_fut.await.expect("error establishing TLS connection");

    tls.close()
        .await
        .map_err(|(_, e)| e)
        .expect("error closing session");
}
