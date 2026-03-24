//! TLS 1.3 server example using tokio.
//!
//! Listens on 127.0.0.1:12345, accepts one connection, performs a TLS handshake,
//! reads a message, echoes it back, and shuts down.
//!
//! Generate test certs first:  bash tests/data/gen_test_certs.sh
//!
//! Run:    cargo run -p tls-server-tokio
//! Test:   echo "hello" | openssl s_client -connect 127.0.0.1:12345 \
//!             -CAfile tests/data/ca-cert.pem -tls1_3 -quiet

use embedded_io_adapters::tokio_1::FromTokio;
use embedded_io_async::Write as _;
use embedded_tls::*;
use rand::rngs::OsRng;
use rand_core::CryptoRngCore;
use std::error::Error;
use tokio::net::TcpListener;

struct ServerProvider {
    rng: OsRng,
    key_der: Vec<u8>,
}

impl CryptoProvider for ServerProvider {
    type CipherSuite = Aes128GcmSha256;
    type Signature = p256::ecdsa::DerSignature;

    fn rng(&mut self) -> impl CryptoRngCore {
        &mut self.rng
    }

    fn signer(
        &mut self,
    ) -> Result<(impl signature::SignerMut<Self::Signature>, SignatureScheme), TlsError> {
        use ecdsa::elliptic_curve::SecretKey;
        use p256::ecdsa::SigningKey;
        let sk = SecretKey::from_sec1_der(&self.key_der)
            .map_err(|_| TlsError::InvalidPrivateKey)?;
        Ok((SigningKey::from(&sk), SignatureScheme::EcdsaSecp256r1Sha256))
    }
}

fn load_certs(path: &str) -> Vec<Vec<u8>> {
    let f = std::fs::File::open(path).expect("cannot open cert file");
    rustls_pemfile::certs(&mut std::io::BufReader::new(f)).expect("cannot parse certs")
}

fn load_key(path: &str) -> Vec<u8> {
    let f = std::fs::File::open(path).expect("cannot open key file");
    let mut r = std::io::BufReader::new(f);
    loop {
        match rustls_pemfile::read_one(&mut r).expect("cannot parse key") {
            Some(rustls_pemfile::Item::ECKey(k)) => return k,
            Some(rustls_pemfile::Item::PKCS8Key(k)) => return k,
            None => panic!("no private key found"),
            _ => {}
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let certs = load_certs("tests/data/chain-cert.pem");
    let key = load_key("tests/data/im-server-key.pem");

    let listener = TcpListener::bind("127.0.0.1:12345").await?;
    log::info!("Listening on 127.0.0.1:12345");

    let (stream, peer) = listener.accept().await?;
    log::info!("Accepted connection from {peer}");

    let cert_refs: Vec<&[u8]> = certs.iter().map(|c| c.as_slice()).collect();
    let config = TlsServerConfig::new(&cert_refs);
    let context = TlsServerContext::new(
        &config,
        ServerProvider { rng: OsRng, key_der: key },
    );

    let mut read_buf = [0; 16384];
    let mut write_buf = [0; 16384];
    let mut tls = TlsConnection::new(
        FromTokio::new(stream),
        &mut read_buf,
        &mut write_buf,
    );

    tls.open_server(context).await.expect("TLS handshake failed");
    log::info!("TLS handshake complete");

    let mut rx = [0; 4096];
    let n = tls.read(&mut rx).await.expect("read failed");
    log::info!("Received: {:?}", core::str::from_utf8(&rx[..n]));

    tls.write_all(&rx[..n]).await.expect("write failed");
    tls.flush().await.expect("flush failed");
    log::info!("Echoed {} bytes", n);

    tls.close().await.ok();
    Ok(())
}
