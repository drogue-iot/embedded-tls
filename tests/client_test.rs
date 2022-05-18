#![macro_use]
#![allow(incomplete_features)]
#![feature(generic_associated_types)]
#![feature(type_alias_impl_trait)]
use embedded_io::adapters::{FromStd, FromTokio};
use rand::rngs::OsRng;
use std::net::SocketAddr;
use std::sync::Once;

mod tlsserver;

static INIT: Once = Once::new();
static mut ADDR: Option<SocketAddr> = None;

fn setup() -> SocketAddr {
    use mio::net::TcpListener;
    INIT.call_once(|| {
        env_logger::init();

        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let listener = TcpListener::bind(addr).expect("cannot listen on port");
        let addr = listener
            .local_addr()
            .expect("error retrieving socket address");

        std::thread::spawn(move || {
            tlsserver::run(listener);
        });
        unsafe { ADDR.replace(addr) };
    });
    unsafe { ADDR.unwrap() }
}

#[tokio::test]
async fn test_ping() {
    use embedded_tls::*;
    use std::time::SystemTime;
    use tokio::net::TcpStream;
    let addr = setup();
    let pem = include_str!("data/ca-cert.pem");
    let der = pem_parser::pem_to_der(pem);

    let stream = TcpStream::connect(addr)
        .await
        .expect("error connecting to server");

    log::info!("Connected");
    let mut record_buffer = [0; 16384];
    let config = TlsConfig::new()
        .with_ca(Certificate::X509(&der[..]))
        .with_server_name("localhost");

    let mut tls: TlsConnection<FromTokio<TcpStream>, Aes128GcmSha256> =
        TlsConnection::new(FromTokio::new(stream), &mut record_buffer);

    let sz = core::mem::size_of::<TlsConnection<FromTokio<TcpStream>, Aes128GcmSha256>>();
    log::info!("SIZE of connection is {}", sz);

    let mut rng = OsRng;
    let open_fut = tls.open::<OsRng, SystemTime, 4096>(TlsContext::new(&config, &mut rng));
    log::info!("SIZE of open fut is {}", core::mem::size_of_val(&open_fut));
    open_fut.await.expect("error establishing TLS connection");

    let write_fut = tls.write(b"ping");
    log::info!(
        "SIZE of write fut is {}",
        core::mem::size_of_val(&write_fut)
    );
    write_fut.await.expect("error writing data");

    let mut rx_buf = [0; 4096];
    let read_fut = tls.read(&mut rx_buf);
    log::info!("SIZE of read fut is {}", core::mem::size_of_val(&read_fut));
    let sz = read_fut.await.expect("error reading data");
    assert_eq!(4, sz);
    assert_eq!(b"ping", &rx_buf[..sz]);
    log::info!("Read {} bytes: {:?}", sz, &rx_buf[..sz]);

    tls.close().await.expect("error closing session");
}

#[test]
fn test_blocking_ping() {
    use embedded_tls::blocking::*;
    use std::net::TcpStream;
    use std::time::SystemTime;

    let addr = setup();
    let pem = include_str!("data/ca-cert.pem");
    let der = pem_parser::pem_to_der(pem);
    let stream = TcpStream::connect(addr).expect("error connecting to server");

    log::info!("Connected");
    let mut record_buffer = [0; 16384];
    let config = TlsConfig::new()
        .with_ca(Certificate::X509(&der[..]))
        .with_server_name("localhost");

    let mut tls: TlsConnection<FromStd<TcpStream>, Aes128GcmSha256> =
        TlsConnection::new(FromStd::new(stream), &mut record_buffer);

    tls.open::<OsRng, SystemTime, 4096>(TlsContext::new(&config, &mut OsRng))
        .expect("error establishing TLS connection");

    tls.write(b"ping").expect("error writing data");

    let mut rx_buf = [0; 4096];
    let sz = tls.read(&mut rx_buf).expect("error reading data");
    assert_eq!(4, sz);
    assert_eq!(b"ping", &rx_buf[..sz]);
    log::info!("Read {} bytes: {:?}", sz, &rx_buf[..sz]);

    tls.close().expect("error closing session");
}
