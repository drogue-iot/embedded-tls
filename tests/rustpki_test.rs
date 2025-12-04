#![cfg(feature = "rustpki")]

use embedded_io_adapters::tokio_1::FromTokio;
use embedded_tls::pki::CertVerifier;
use embedded_tls::{Aes128GcmSha256, CryptoProvider, SignatureScheme, TlsError, TlsVerifier};
use p256::SecretKey;
use p256::ecdsa::{DerSignature, SigningKey};
use rand_core::OsRng;
use signature::SignerMut;
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::SystemTime;

mod tlsserver;

static LOG_INIT: OnceLock<()> = OnceLock::new();

#[derive(Default)]
struct RustPkiProvider {
    rng: rand::rngs::OsRng,
    verifier: CertVerifier<Aes128GcmSha256, SystemTime, 4096>,
}

impl CryptoProvider for RustPkiProvider {
    type CipherSuite = Aes128GcmSha256;
    type Signature = DerSignature;

    fn rng(&mut self) -> impl embedded_tls::CryptoRngCore {
        &mut self.rng
    }

    fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Aes128GcmSha256>, TlsError> {
        Ok(&mut self.verifier)
    }

    fn signer(
        &mut self,
        key_der: &[u8],
    ) -> Result<(impl SignerMut<Self::Signature>, SignatureScheme), TlsError> {
        let secret_key =
            SecretKey::from_sec1_der(key_der).map_err(|_| TlsError::InvalidPrivateKey)?;

        Ok((
            SigningKey::from(&secret_key),
            SignatureScheme::EcdsaSecp256r1Sha256,
        ))
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

    let config = TlsConfig::new()
        .with_ca(Certificate::X509(&der[..]))
        .with_server_name("localhost");

    let mut tls = TlsConnection::new(
        FromTokio::new(stream),
        &mut read_record_buffer,
        &mut write_record_buffer,
    );

    let open_fut = tls.open(TlsContext::new(
        &config,
        RustPkiProvider {
            rng: OsRng,
            verifier: CertVerifier::new(),
        },
    ));

    open_fut.await.expect("error establishing TLS connection");

    tls.close()
        .await
        .map_err(|(_, e)| e)
        .expect("error closing session");
}

#[tokio::test]
async fn test_mutual_certificate_validation() {
    use embedded_tls::*;

    let addr = setup().await;
    let ca_pem = include_str!("data/ca-cert.pem");
    let ca_der = pem_parser::pem_to_der(ca_pem);

    let cli_pem = include_str!("data/client-cert.pem");
    let cli_der = pem_parser::pem_to_der(cli_pem);

    let key_pem = include_str!("data/client-key.pem");
    let key_der = pem_parser::pem_to_der(key_pem);

    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("error connecting to server");

    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];

    let config = TlsConfig::new()
        .with_ca(Certificate::X509(&ca_der[..]))
        .with_server_name("localhost")
        .with_cert(Certificate::X509(&cli_der[..]))
        .with_priv_key(&key_der);

    let mut tls = TlsConnection::new(
        FromTokio::new(stream),
        &mut read_record_buffer,
        &mut write_record_buffer,
    );

    let open_fut = tls.open(TlsContext::new(
        &config,
        RustPkiProvider {
            rng: OsRng,
            verifier: CertVerifier::new(),
        },
    ));

    open_fut.await.expect("error establishing TLS connection");

    tls.close()
        .await
        .map_err(|(_, e)| e)
        .expect("error closing session");
}
