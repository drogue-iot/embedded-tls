#![cfg(all(feature = "rustpki", feature = "rsa"))]
use digest::FixedOutputReset;
use embedded_io_adapters::tokio_1::FromTokio;
use embedded_tls::pki::CertVerifier;
use embedded_tls::{Aes128GcmSha256, CryptoProvider, SignatureScheme, TlsError, TlsVerifier};
use rand_core::CryptoRng;
use rsa::pkcs8::DecodePrivateKey;
use rustls::server::WebPkiClientVerifier;
use sha2::{Digest, Sha256};
use signature::RandomizedSigner;
use std::net::SocketAddr;
use std::sync::{Arc, Once};
use std::time::SystemTime;

mod tlsserver;

static LOG_INIT: Once = Once::new();
static INIT: Once = Once::new();
static mut ADDR: Option<SocketAddr> = None;

struct RsaPssSigningKey<D: Digest> {
    key: rsa::pss::SigningKey<D>,
}

impl<D: Digest + FixedOutputReset> signature::Signer<Box<[u8]>> for RsaPssSigningKey<D> {
    fn try_sign(&self, msg: &[u8]) -> Result<Box<[u8]>, rsa::signature::Error> {
        let signature = self.key.try_sign_with_rng(&mut rand::rng(), msg)?;
        Ok(signature.into())
    }
}

#[derive(Default)]
struct RustPkiProvider {
    verifier: CertVerifier<Aes128GcmSha256, SystemTime, 4096>,
}

impl CryptoProvider for RustPkiProvider {
    type CipherSuite = Aes128GcmSha256;
    type Signature = Box<[u8]>;

    fn rng(&mut self) -> impl CryptoRng {
        rand::rng()
    }

    fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Aes128GcmSha256>, TlsError> {
        Ok(&mut self.verifier)
    }

    fn signer(
        &mut self,
        key_der: &[u8],
    ) -> Result<(impl signature::Signer<Self::Signature>, SignatureScheme), embedded_tls::TlsError>
    {
        let private_key =
            rsa::RsaPrivateKey::from_pkcs8_der(key_der).map_err(|_| TlsError::InvalidPrivateKey)?;
        let signer = RsaPssSigningKey {
            key: rsa::pss::SigningKey::<Sha256>::new(private_key),
        };

        Ok((signer, SignatureScheme::RsaPssRsaeSha256))
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

            let test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");

            let ca = load_certs(&test_dir.join("data").join("rsa-ca-cert.pem"));
            let certs = load_certs(&test_dir.join("data").join("rsa-server-cert.pem"));
            let privkey = load_private_key(&test_dir.join("data").join("rsa-server-key.pem"));

            let mut client_auth_roots = rustls::RootCertStore::empty();
            for root in ca.into_iter() {
                client_auth_roots.add(root).unwrap()
            }

            let client_cert_verifier = WebPkiClientVerifier::builder(Arc::new(client_auth_roots))
                .allow_unauthenticated()
                .build()
                .unwrap();

            let config = rustls::ServerConfig::builder()
                .with_client_cert_verifier(client_cert_verifier)
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

    let cli_pem = include_str!("data/rsa-client-cert.pem");
    let cli_der = pem_parser::pem_to_der(cli_pem);

    let key_pem = include_str!("data/rsa-client-key.pem");
    let key_der = pem_parser::pem_to_der(key_pem);

    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("error connecting to server");

    let mut read_record_buffer = [0; 16640];
    let mut write_record_buffer = [0; 16640];

    let config = TlsConfig::new()
        .with_ca(Certificate::X509(&der[..]))
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
            verifier: CertVerifier::new(),
        },
    ));

    open_fut.await.expect("error establishing TLS connection");

    tls.close()
        .await
        .map_err(|(_, e)| e)
        .expect("error closing session");
}
