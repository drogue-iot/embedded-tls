#![macro_use]

use std::net::SocketAddr;
use std::sync::OnceLock;

use embedded_io::{Read, Write};
use embedded_io_adapters::std::FromStd;

mod tlsserver;

static ADDR: OnceLock<SocketAddr> = OnceLock::new();

fn setup() -> SocketAddr {
    use mio::net::TcpListener;

    *ADDR.get_or_init(|| {
        env_logger::init();

        let mut crypto_provider = rustls::crypto::ring::default_provider();
        crypto_provider.tls12_cipher_suites = Vec::new();
        crypto_provider.tls13_cipher_suites =
            rustls::crypto::ring::ALL_TLS13_CIPHER_SUITES.to_vec();
        crypto_provider.kx_groups = rustls::crypto::ring::ALL_KX_GROUPS.to_vec();
        crypto_provider.install_default().unwrap();

        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let listener = TcpListener::bind(addr).expect("cannot listen on port");
        let addr = listener
            .local_addr()
            .expect("error retrieving socket address");

        std::thread::spawn(move || {
            use tlsserver::*;

            let test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");

            let certs = load_certs(&test_dir.join("data").join("server-cert.pem"));
            let privkey = load_private_key(&test_dir.join("data").join("server-key.pem"));

            let mut config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, privkey)
                .unwrap();

            config.max_early_data_size = 512;

            run_with_config(listener, config);
        });

        addr
    })
}

#[test]
fn early_data_ignored() {
    use embedded_tls::blocking::*;
    use std::net::TcpStream;

    let addr = setup();
    let pem = include_str!("data/ca-cert.pem");
    let der = pem_parser::pem_to_der(pem);

    let stream = TcpStream::connect(addr).expect("error connecting to server");

    log::info!("Connected");
    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];
    let config = TlsConfig::new()
        .with_ca(Certificate::X509(&der[..]))
        .with_server_name("localhost");

    let mut tls = TlsConnection::new(
        FromStd::new(stream),
        &mut read_record_buffer,
        &mut write_record_buffer,
    );

    tls.open(TlsContext::new(
        &config,
        UnsecureProvider::new::<Aes128GcmSha256>(rand::rng()),
    ))
    .expect("error establishing TLS connection");

    tls.write_all(b"ping").expect("Failed to write data");
    tls.flush().expect("Failed to flush");

    let mut buffer = [0; 4];
    tls.read_exact(&mut buffer).expect("Failed to read data");

    tls.close()
        .map_err(|(_, e)| e)
        .expect("error closing session");
}
