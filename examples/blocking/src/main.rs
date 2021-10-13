use drogue_tls::blocking::*;
use rand::rngs::OsRng;
use std::net::TcpStream;
use std::time::SystemTime;

fn main() {
    env_logger::init();
    let stream = TcpStream::connect("127.0.0.1:12345").expect("error connecting to server");

    log::info!("Connected");
    let mut record_buffer = [0; 16384];
    let tls_context = TlsContext::new(OsRng, &mut record_buffer)
        .with_server_name("localhost")
        .verify_cert(false);
    let mut tls: TlsConnection<OsRng, SystemTime, TcpStream, Aes128GcmSha256> =
        TlsConnection::new(tls_context, stream);

    tls.open().expect("error establishing TLS connection");

    tls.write(b"ping").expect("error writing data");

    let mut rx_buf = [0; 4096];
    let sz = tls.read(&mut rx_buf).expect("error reading data");
    log::info!("Read {} bytes: {:?}", sz, &rx_buf[..sz]);
}
