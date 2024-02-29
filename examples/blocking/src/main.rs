use embedded_io::Write as _;
use embedded_io_adapters::std::FromStd;
use embedded_tls::blocking::*;
use embedded_tls::webpki::CertVerifier;
use rand::rngs::OsRng;
use std::net::TcpStream;
use std::time::SystemTime;

struct Provider {
    rng: OsRng,
    verifier: CertVerifier<Aes128GcmSha256, SystemTime, 4096>,
}

impl CryptoProvider for Provider {
    type CipherSuite = Aes128GcmSha256;

    type Signature = &'static [u8];

    fn rng(&mut self) -> impl embedded_tls::CryptoRngCore {
        &mut self.rng
    }

    fn verifier(
        &mut self,
    ) -> Result<&mut impl TlsVerifier<Self::CipherSuite>, embedded_tls::TlsError> {
        Ok(&mut self.verifier)
    }
}

fn main() {
    env_logger::init();
    let stream = TcpStream::connect("127.0.0.1:12345").expect("error connecting to server");

    log::info!("Connected");
    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];
    let config = TlsConfig::new().with_server_name("localhost");
    let mut tls = TlsConnection::new(
        FromStd::new(stream),
        &mut read_record_buffer,
        &mut write_record_buffer,
    );

    tls.open(TlsContext::new(
        &config,
        Provider {
            rng: OsRng,
            verifier: CertVerifier::new(),
        },
    ))
    .expect("error establishing TLS connection");

    tls.write_all(b"ping").expect("error writing data");
    tls.flush().expect("error flushing data");

    let mut rx_buf = [0; 4096];
    let sz = tls.read(&mut rx_buf).expect("error reading data");
    log::info!("Read {} bytes: {:?}", sz, &rx_buf[..sz]);
}
