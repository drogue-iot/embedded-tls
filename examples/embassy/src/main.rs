#![allow(incomplete_features)]
#![feature(type_alias_impl_trait)]
#![feature(async_fn_in_trait)]
#![feature(impl_trait_projections)]

use clap::Parser;
use embassy_executor::{Executor, Spawner};
use embassy_net::tcp::TcpSocket;
use embassy_net::{ConfigStrategy, Ipv4Address, Ipv4Cidr, Stack, StackResources};
use embedded_tls::{Aes128GcmSha256, NoVerify, TlsConfig, TlsConnection, TlsContext};
use heapless::Vec;
use log::*;
use rand::{rngs::OsRng, RngCore};
use static_cell::StaticCell;

mod tuntap;

use crate::tuntap::TunTapDevice;

macro_rules! singleton {
    ($val:expr) => {{
        type T = impl Sized;
        static STATIC_CELL: StaticCell<T> = StaticCell::new();
        STATIC_CELL.init_with(move || $val)
    }};
}

#[derive(Parser)]
#[clap(version = "1.0")]
struct Opts {
    /// TAP device name
    #[clap(long, default_value = "tap0")]
    tap: String,
    /// use a static IP instead of DHCP
    #[clap(long)]
    static_ip: bool,
}

#[embassy_executor::task]
async fn net_task(stack: &'static Stack<TunTapDevice>) -> ! {
    stack.run().await
}

#[embassy_executor::task]
async fn main_task(spawner: Spawner) {
    let opts: Opts = Opts::parse();

    // Init network device
    let device = TunTapDevice::new(&opts.tap).unwrap();

    // Choose between dhcp or static ip
    let config = if opts.static_ip {
        ConfigStrategy::Static(embassy_net::Config {
            address: Ipv4Cidr::new(Ipv4Address::new(192, 168, 69, 2), 24),
            dns_servers: Vec::new(),
            gateway: Some(Ipv4Address::new(192, 168, 69, 1)),
        })
    } else {
        ConfigStrategy::Dhcp
    };

    // Generate random seed
    let mut seed = [0; 8];
    OsRng.fill_bytes(&mut seed);
    let seed = u64::from_le_bytes(seed);

    // Init network stack
    let stack = &*singleton!(Stack::new(
        device,
        config,
        singleton!(StackResources::<1, 2, 8>::new()),
        seed
    ));

    // Launch network task
    spawner.spawn(net_task(stack)).unwrap();

    // Then we can use it!
    let mut rx_buffer = [0; 4096];
    let mut tx_buffer = [0; 4096];
    let mut socket = TcpSocket::new(stack, &mut rx_buffer, &mut tx_buffer);

    socket.set_timeout(Some(embassy_net::SmolDuration::from_secs(10)));

    let remote_endpoint = (Ipv4Address::new(192, 168, 69, 100), 8000);
    log::info!("connecting to {:?}...", remote_endpoint);
    let r = socket.connect(remote_endpoint).await;
    if let Err(e) = r {
        warn!("connect error: {:?}", e);
        return;
    }
    log::info!("TCP connected!");

    let mut record_buffer = [0; 16384];
    let mut rng = OsRng;
    let config = TlsConfig::new().with_server_name("example.com");
    let mut tls: TlsConnection<TcpSocket, Aes128GcmSha256> =
        TlsConnection::new(socket, &mut record_buffer);

    tls.open::<OsRng, NoVerify>(TlsContext::new(&config, &mut rng))
        .await
        .expect("error establishing TLS connection");

    tls.write(b"ping").await.expect("error writing data");

    let mut rx_buf = [0; 128];
    let sz = tls.read(&mut rx_buf[..]).await.expect("error reading data");

    log::info!("Read {} bytes: {:?}", sz, &rx_buf[..sz]);
}

static EXECUTOR: StaticCell<Executor> = StaticCell::new();

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .filter_module("async_io", log::LevelFilter::Info)
        .format_timestamp_nanos()
        .init();

    let executor = EXECUTOR.init(Executor::new());
    executor.run(|spawner| {
        spawner.spawn(main_task(spawner)).unwrap();
    });
}
