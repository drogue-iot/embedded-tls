#![macro_use]

use embedded_io::adapters::FromTokio;
use embedded_io::asynch::Write as _;
use embedded_tls::*;
use rand::rngs::OsRng;
use std::error::Error;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let stream = TcpStream::connect("127.0.0.1:12345").await?;

    log::info!("Connected");
    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];
    let config = TlsConfig::new().with_server_name("localhost");
    let mut rng = OsRng;
    let mut tls: TlsConnection<FromTokio<TcpStream>, Aes128GcmSha256> = TlsConnection::new(
        FromTokio::new(stream),
        &mut read_record_buffer,
        &mut write_record_buffer,
    );

    tls.open::<OsRng, NoVerify>(TlsContext::new(&config, &mut rng))
        .await
        .expect("error establishing TLS connection");

    tls.write_all(b"ping").await.expect("error writing data");
    tls.flush().await.expect("error flushing data");

    let mut rx_buf = [0; 4096];
    let sz = tls.read(&mut rx_buf).await.expect("error reading data");
    log::info!("Read {} bytes: {:?}", sz, &rx_buf[..sz]);

    Ok(())
}
