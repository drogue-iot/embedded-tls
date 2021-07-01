#![macro_use]
#![allow(incomplete_features)]
#![feature(generic_associated_types)]
#![feature(min_type_alias_impl_trait)]

use drogue_tls::*;
use rand::rngs::OsRng;
use std::error::Error;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let stream = TcpStream::connect("127.0.0.1:12345").await?;

    log::info!("Connected");
    let mut record_buffer = [0; 16384];
    let tls_context = TlsContext::new(OsRng, &mut record_buffer).with_server_name("example.com");
    let mut tls: TlsConnection<OsRng, TcpStream, Aes128GcmSha256> =
        TlsConnection::new(tls_context, stream);

    tls.open().await.expect("error establishing TLS connection");

    tls.write(b"ping").await.expect("error writing data");

    let mut rx_buf = [0; 4096];
    let sz = tls.read(&mut rx_buf).await.expect("error reading data");
    log::info!("Read {} bytes: {:?}", sz, &rx_buf[..sz]);

    Ok(())
}
