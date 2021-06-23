#![macro_use]
#![allow(incomplete_features)]
#![feature(generic_associated_types)]
#![feature(min_type_alias_impl_trait)]

use core::future::Future;
use drogue_tls::{config::*, tls_connection::*, AsyncRead, AsyncWrite, TlsError};
use heapless::consts;
use rand::rngs::OsRng;
use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let mut stream = TcpStream::connect("127.0.0.1:12345").await?;
    let socket = Socket { stream };

    log::info!("Connected");
    let tls_config: Config<OsRng, Aes128GcmSha256> = Config::new(OsRng);
    let mut tls: TlsConnection<OsRng, Socket, Aes128GcmSha256, consts::U4096, consts::U4096> =
        TlsConnection::new(&tls_config, socket);

    tls.open().await.expect("error establishing TLS connection");
    tls.write(b"ping").await.expect("error writing data");

    let mut rx_buf = [0; 4096];
    let sz = tls.read(&mut rx_buf).await.expect("error reading data");
    log::info!("Read {} bytes: {:?}", sz, &rx_buf[..sz]);

    Ok(())
}

pub struct Socket {
    stream: TcpStream,
}

impl AsyncWrite for Socket {
    #[rustfmt::skip]
    type WriteFuture<'m> where Self: 'm = impl Future<Output = Result<usize, TlsError>> + 'm;
    fn write<'m>(&'m mut self, buf: &'m [u8]) -> Self::WriteFuture<'m> {
        async move {
            Ok(self
                .stream
                .write(buf)
                .await
                .map_err(|_| TlsError::IoError)?)
        }
    }
}

impl AsyncRead for Socket {
    #[rustfmt::skip]
    type ReadFuture<'m> where Self: 'm = impl Future<Output = Result<usize, TlsError>> + 'm;
    fn read<'m>(&'m mut self, buf: &'m mut [u8]) -> Self::ReadFuture<'m> {
        async move { Ok(self.stream.read(buf).await.map_err(|_| TlsError::IoError)?) }
    }
}
