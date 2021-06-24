#![macro_use]
#![allow(incomplete_features)]
#![feature(generic_associated_types)]
#![feature(min_type_alias_impl_trait)]
use core::future::Future;
use drogue_tls::{config::*, tls_connection::*, AsyncRead, AsyncWrite, TlsError};
use mio::net::TcpListener;
use rand::rngs::OsRng;
use std::net::SocketAddr;
use std::sync::Once;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

mod tlsserver;

static INIT: Once = Once::new();

fn setup() -> std::io::Result<SocketAddr> {
    INIT.call_once(|| {
        env_logger::init();
    });

    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

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
    let socket = Socket { stream };

    log::info!("Connected");
    let tls_config: Config<OsRng, Aes128GcmSha256> = Config::new(OsRng);
    let mut tls: TlsConnection<OsRng, Socket, Aes128GcmSha256, 4096, 4096> =
        TlsConnection::new(&tls_config, socket);

    tls.open().await.expect("error establishing TLS connection");
    tls.write(b"ping").await.expect("error writing data");

    let mut rx_buf = [0; 4096];
    let sz = tls.read(&mut rx_buf).await.expect("error reading data");
    assert_eq!(4, sz);
    assert_eq!(b"ping", &rx_buf[..sz]);
    log::info!("Read {} bytes: {:?}", sz, &rx_buf[..sz]);
}

pub struct Socket {
    stream: TcpStream,
}

impl AsyncWrite for Socket {
    #[rustfmt::skip]
    type WriteFuture<'m> where Self: 'm = impl Future<Output = Result<usize, TlsError>> + 'm;
    fn write<'m>(&'m mut self, buf: &'m [u8]) -> Self::WriteFuture<'m> {
        async move { self.stream.write(buf).await.map_err(|_| TlsError::IoError) }
    }
}

impl AsyncRead for Socket {
    #[rustfmt::skip]
    type ReadFuture<'m> where Self: 'm = impl Future<Output = Result<usize, TlsError>> + 'm;
    fn read<'m>(&'m mut self, buf: &'m mut [u8]) -> Self::ReadFuture<'m> {
        async move { self.stream.read(buf).await.map_err(|_| TlsError::IoError) }
    }
}
