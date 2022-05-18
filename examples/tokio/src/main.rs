#![macro_use]
#![allow(incomplete_features)]
#![feature(generic_associated_types)]

use embedded_io::adapters::FromTokio;
use embedded_tls::*;
use rand::rngs::OsRng;
use std::error::Error;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let stream = TcpStream::connect("127.0.0.1:12345").await?;

    log::info!("Connected");
    let mut record_buffer = [0; 16384];
    let config = TlsConfig::new()
        .with_server_name("localhost")
        .verify_cert(false);
    let mut rng = OsRng;
    let mut tls: TlsConnection<FromTokio<TcpStream>, Aes128GcmSha256> =
        TlsConnection::new(FromTokio::new(stream), &mut record_buffer);

    tls.open::<OsRng, std::time::SystemTime, 4096>(TlsContext::new(&config, &mut rng))
        .await
        .expect("error establishing TLS connection");

    tls.write(b"ping").await.expect("error writing data");

    let mut rx_buf = [0; 4096];
    let sz = tls.read(&mut rx_buf).await.expect("error reading data");
    log::info!("Read {} bytes: {:?}", sz, &rx_buf[..sz]);

    Ok(())
}
