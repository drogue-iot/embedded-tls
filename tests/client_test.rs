#![macro_use]
#![allow(incomplete_features)]
#![feature(generic_associated_types)]
#![feature(min_type_alias_impl_trait)]
use drogue_tls::*;
use mio::net::TcpListener;
use rand::rngs::OsRng;
use std::net::SocketAddr;
use std::sync::Once;
use tokio::net::TcpStream;

mod tlsserver;

static INIT: Once = Once::new();

fn setup() -> std::io::Result<SocketAddr> {
    INIT.call_once(|| {
        env_logger::init();
    });

    let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    let listener = TcpListener::bind(addr).expect("cannot listen on port");
    let addr = listener.local_addr()?;

    std::thread::spawn(move || {
        tlsserver::run(listener);
    });
    Ok(addr)
}

#[tokio::test]
async fn test_ping() {
    let addr = setup().expect("error initializing test");
    let stream = TcpStream::connect(addr)
        .await
        .expect("error connecting to server");

    log::info!("Connected");
    let mut record_buffer = [0; 16384];
    let tls_context = TlsContext::new(OsRng, &mut record_buffer);
    let mut tls: TlsConnection<OsRng, TcpStream, Aes128GcmSha256> =
        TlsConnection::new(tls_context, stream);

    let sz = std::mem::size_of::<TlsConnection<OsRng, TcpStream, Aes128GcmSha256>>();
    log::info!("SIZE of connection is {}", sz);

    let open_fut = tls.open();
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
