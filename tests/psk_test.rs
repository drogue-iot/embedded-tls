#![macro_use]
#![allow(incomplete_features)]
#![feature(async_fn_in_trait)]
#![feature(impl_trait_projections)]
use embedded_io::adapters::FromTokio;
use embedded_tls::*;
use rand::rngs::OsRng;
use std::process::Command;
use std::sync::Once;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio::time::Duration;

static INIT: Once = Once::new();

fn setup() -> tokio::task::JoinHandle<()> {
    INIT.call_once(|| {
        env_logger::init();
    });

    let h = tokio::task::spawn_blocking(move || {
        let mut child = Command::new("openssl")
            .arg("s_server")
            .arg("-tls1_3")
            .arg("-psk_identity")
            .arg("vader")
            .arg("-psk")
            .arg("aabbccdd")
            .arg("-key")
            .arg("tests/data/server-key.pem")
            .arg("-cert")
            .arg("tests/data/server-cert.pem")
            .arg("-ciphersuites")
            .arg("TLS_AES_128_GCM_SHA256")
            .arg("-naccept")
            .arg("1")
            .spawn()
            .expect("failed to execute process");
        println!("Process completed: {:?}", child.wait().unwrap());
    });
    println!("Returning join handle");
    h
}

#[tokio::test(flavor = "multi_thread")]
async fn test_psk_open() {
    timeout(Duration::from_secs(120), async move {
        let _h = setup();
        println!("Setup complete");
        tokio::time::sleep(core::time::Duration::from_secs(10)).await;

        println!("Connectiong...");
        let stream = TcpStream::connect("127.0.0.1:4433")
            .await
            .expect("error connecting to server");

        println!("Connected");
        let mut record_buffer = [0; 16384];
        let config = TlsConfig::new()
            .with_psk(&[0xaa, 0xbb, 0xcc, 0xdd], &[b"vader"])
            .with_server_name("localhost");

        let mut tls: TlsConnection<FromTokio<TcpStream>, Aes128GcmSha256> =
            TlsConnection::new(FromTokio::new(stream), &mut record_buffer);

        let mut rng = OsRng;
        assert!(tls
            .open::<OsRng, NoVerify>(TlsContext::new(&config, &mut rng))
            .await
            .is_ok());
        println!("TLS session opened");
    })
    .await
    .unwrap();
}
