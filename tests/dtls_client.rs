#![macro_use]
#![allow(incomplete_features)]
#![feature(async_fn_in_trait)]
#![feature(impl_trait_projections)]
use embedded_io::adapters::FromTokio;
use embedded_tls::*;
use openssl::ssl;
use openssl::ssl::{SslContext, SslFiletype, SslMethod, SslVerifyMode};
use rand::rngs::OsRng;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::net::TcpListener;
use std::sync::Once;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio::time::Duration;
use tokio_dtls_stream_sink::Server as DtlsServer;

static INIT: Once = Once::new();

fn setup() -> (SocketAddr, JoinHandle<()>) {
    INIT.call_once(|| {
        env_logger::init();
    });

    const DEFAULT_CIPHERS: &[&str] = &["PSK"];
    let mut builder = SslContext::builder(SslMethod::dtls()).unwrap();
    builder
        .set_private_key_file("tests/data/server-key.pem", ssl::SslFiletype::PEM)
        .unwrap();
    builder
        .set_certificate_chain_file("tests/data/server-cert.pem")
        .unwrap();
    builder.set_cipher_list(&DEFAULT_CIPHERS.join(",")).unwrap();
    builder.set_psk_server_callback(move |_ssl, identity, secret_mut| {
        if let Some(b"vader") = identity {
            secret_mut[..4].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
            Ok(4)
        } else {
            Ok(0)
        }
    });
    let dtls = builder.build();

    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    let socket = UdpSocket::bind(addr).expect("cannot listen on port");
    let mut buf = [0; 1024];
    let mut server = DtlsServer::new(socket);

    let h = tokio::task::spawn(async move || match server.accept(dtls.as_ref()).await {
        Ok(mut conn) => {
            let mut buf = [0; 64];
            let len = conn.read(&mut buf[..]).unwrap();
            conn.write(&buf[..len]).unwrap();
        }
        Err(e) => {
            log::warn!("Error when accepting session: {:?}", e);
        }
    });
    (addr, h)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dtls() {
    let (addr, h) = setup();
    timeout(Duration::from_secs(120), async move {
        let caddr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let stream = UdpSocket::bind(caddr).unwrap();

        let mut record_buffer = [0; 16384];
        let config = TlsConfig::new()
            .with_version(TlsVersion::DTLS_1_2)
            .with_psk(&[0xaa, 0xbb, 0xcc, 0xdd], &[b"vader"])
            .with_server_name("localhost");

        let mut session: DtlsSession<Aes128GcmSha256> =
            DtlsSession::new(FromTokio::new(stream), &mut record_buffer);

        let mut rng = OsRng;
        assert!(session
            .open::<OsRng, NoVerify>(TlsContext::new(&config, &mut rng))
            .await
            .is_ok());
        println!("DTLS session opened");

        session.send(b"ping").await.unwrap();

        println!("DTLS data written");
        let mut rx = [0; 4];
        let l = session.recv(&mut rx[..]).await.unwrap();

        println!("DTLS data read");
        assert_eq!(4, l);
        assert_eq!(b"ping", &rx[..l]);

        h.await.unwrap();
    })
    .await
    .unwrap();
}
