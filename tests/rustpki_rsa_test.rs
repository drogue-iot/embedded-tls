#![cfg(all(feature = "rustpki", feature = "alloc"))]
use embedded_io_adapters::tokio_1::FromTokio;
use embedded_tls::pki::CertVerifier;
use embedded_tls::{Aes128GcmSha256, CryptoProvider, TlsError, TlsVerifier};
use rand_core::OsRng;
use rustls::server::AllowAnyAnonymousOrAuthenticatedClient;
use std::net::SocketAddr;
use std::sync::Once;
use std::time::SystemTime;

mod tlsserver;

static LOG_INIT: Once = Once::new();
static INIT: Once = Once::new();
static mut ADDR: Option<SocketAddr> = None;

#[derive(Default)]
struct RustPkiProvider {
    rng: rand::rngs::OsRng,
    verifier: CertVerifier<Aes128GcmSha256, SystemTime, 4096>,
}

impl CryptoProvider for RustPkiProvider {
    type CipherSuite = Aes128GcmSha256;
    type Signature = &'static [u8];

    fn rng(&mut self) -> impl embedded_tls::CryptoRngCore {
        &mut self.rng
    }

    fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Aes128GcmSha256>, TlsError> {
        Ok(&mut self.verifier)
    }
}

fn init_log() {
    LOG_INIT.call_once(|| {
        env_logger::init();
    });
}

fn setup() -> SocketAddr {
    use mio::net::TcpListener;
    init_log();
    INIT.call_once(|| {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let listener = TcpListener::bind(addr).expect("cannot listen on port");
        let addr = listener
            .local_addr()
            .expect("error retrieving socket address");

        std::thread::spawn(move || {
            use tlsserver::*;

            let versions = &[&rustls::version::TLS13];

            let test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");

            let ca = load_certs(&test_dir.join("data").join("rsa-ca-cert.pem"));
            let certs = load_certs(&test_dir.join("data").join("rsa-server-cert.pem"));
            let privkey = load_private_key(&test_dir.join("data").join("rsa-server-key.pem"));

            let mut client_auth_roots = rustls::RootCertStore::empty();
            for root in ca.iter() {
                client_auth_roots.add(root).unwrap()
            }

            let client_cert_verifier =
                AllowAnyAnonymousOrAuthenticatedClient::new(client_auth_roots);

            let config = rustls::ServerConfig::builder()
                .with_cipher_suites(rustls::ALL_CIPHER_SUITES)
                .with_kx_groups(&rustls::ALL_KX_GROUPS)
                .with_protocol_versions(versions)
                .unwrap()
                .with_client_cert_verifier(client_cert_verifier.boxed())
                .with_single_cert(certs, privkey)
                .unwrap();

            run_with_config(listener, config);
        });
        #[allow(static_mut_refs)]
        unsafe {
            ADDR.replace(addr)
        };
    });
    unsafe { ADDR.unwrap() }
}

#[tokio::test]
async fn test_server_certificate_validation() {
    use embedded_tls::*;

    let addr = setup();
    let pem = include_str!("data/rsa-ca-cert.pem");
    let der = pem_parser::pem_to_der(pem);

    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("error connecting to server");

    let mut read_record_buffer = [0; 16640];
    let mut write_record_buffer = [0; 16640];

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
