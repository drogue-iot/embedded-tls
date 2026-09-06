#![cfg(all(feature = "rustpki", feature = "rsa"))]
use aes_gcm::Aes128Gcm;
use digest::FixedOutputReset;
use embedded_io_adapters::tokio_1::FromTokio;
use embedded_tls::CryptoRngCore;
use embedded_tls::pki::CertVerifier;
use embedded_tls::{
    Aes128GcmSha256, CryptoProvider, SignatureScheme, TlsError, crypto_traits::AesGcmAead,
};
use hmac::Hmac;
use rsa::pkcs8::DecodePrivateKey;
use sha2::{Digest, Sha256};
use signature::RandomizedSigner;
use signature::Signer;
use std::net::SocketAddr;
use std::sync::Once;
use std::time::SystemTime;

mod tlsserver;

static LOG_INIT: Once = Once::new();
static INIT: Once = Once::new();
static mut ADDR: Option<SocketAddr> = None;

struct RsaPssSigningKey<D: Digest, R: CryptoRngCore> {
    rng: core::cell::RefCell<R>,
    key: rsa::pss::SigningKey<D>,
}

impl<D: Digest + FixedOutputReset, R: CryptoRngCore> Signer<rsa::pss::Signature>
    for RsaPssSigningKey<D, R>
{
    fn try_sign(&self, msg: &[u8]) -> Result<rsa::pss::Signature, rsa::signature::Error> {
        self.key.try_sign_with_rng(&mut *self.rng.borrow_mut(), msg)
    }
}

struct RustPkiProvider<'a> {
    rng: rand::rngs::ThreadRng,
    verifier: CertVerifier<'a, Sha256, SystemTime, 4096>,
    priv_key: Option<&'a [u8]>,
    client_cert: Option<embedded_tls::Certificate<&'a [u8]>>,
}

impl CryptoProvider for RustPkiProvider<'_> {
    type CipherSuite = Aes128GcmSha256;
    type Signature = rsa::pss::Signature;
    type Hash = Sha256;
    type Hmac = Hmac<Sha256>;
    type Aead = AesGcmAead<Aes128Gcm>;

    fn rng(&mut self) -> impl embedded_tls::CryptoRngCore {
        &mut self.rng
    }

    fn aead(&mut self, key: &[u8]) -> Result<Self::Aead, embedded_tls::TlsError> {
        AesGcmAead::new(key)
    }

    fn signer(&mut self) -> Result<(impl Signer<Self::Signature>, SignatureScheme), TlsError> {
        let key_der = self.priv_key.ok_or(TlsError::InvalidPrivateKey)?;
        let private_key =
            rsa::RsaPrivateKey::from_pkcs8_der(key_der).map_err(|_| TlsError::InvalidPrivateKey)?;
        let signer = RsaPssSigningKey {
            rng: core::cell::RefCell::new(&mut self.rng),
            key: rsa::pss::SigningKey::<Sha256>::new(private_key),
        };

        Ok((signer, SignatureScheme::RsaPssRsaeSha256))
    }

    fn client_cert(&mut self) -> Option<embedded_tls::Certificate<impl AsRef<[u8]>>> {
        self.client_cert.clone()
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

            let _ca = load_certs(&test_dir.join("data").join("rsa-ca-cert.pem"));
            let certs = load_certs(&test_dir.join("data").join("rsa-server-cert.pem"));
            let privkey = load_private_key(&test_dir.join("data").join("rsa-server-key.pem"));

            let config = rustls::ServerConfig::builder()
                .with_no_client_auth()
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

    let config = TlsConfig::new().with_server_name("localhost");

    let mut tls = TlsConnection::new(
        FromTokio::new(stream),
        &mut read_record_buffer,
        &mut write_record_buffer,
    );

    let open_fut = tls.open(TlsContext::new(
        &config,
        RustPkiProvider {
            rng: rand::rng(),
            verifier: CertVerifier::new(Certificate::X509(&der[..])),
            priv_key: Some(&key_der),
            client_cert: Some(Certificate::X509(&cli_der[..])),
        },
    ));

    open_fut.await.expect("error establishing TLS connection");

    tls.close()
        .await
        .map_err(|(_, e)| e)
        .expect("error closing session");
}
