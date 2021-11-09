#![macro_use]
#![allow(incomplete_features)]
#![feature(generic_associated_types)]
#![no_std]
#![no_main]

use nrf52833_hal as hal;
use panic_halt as _;

use drogue_tls::blocking::*;

use cortex_m_rt::entry;
use log::LevelFilter;
use rtt_logger::RTTLogger;
use rtt_target::rtt_init_print;

use hal::rng::Rng;

static LOGGER: RTTLogger = RTTLogger::new(LevelFilter::Info);

#[entry]
fn main() -> ! {
    rtt_init_print!();

    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(log::LevelFilter::Info);

    let p = hal::pac::Peripherals::take().unwrap();
    let mut rng = Rng::new(p.RNG);
    log::info!("Connected");
    let mut record_buffer = [0; 16384];
    let config = TlsConfig::new().with_server_name("example.com");
    let mut tls: TlsConnection<Dummy, Aes128GcmSha256> =
        TlsConnection::new(Dummy {}, &mut record_buffer[..]);

    tls.open::<Rng, NoClock, 4096>(TlsContext::new(&config, &mut rng))
        .expect("error establishing TLS connection");

    tls.write(b"ping").expect("error writing data");

    let mut rx_buf = [0; 4096];
    let sz = tls.read(&mut rx_buf).expect("error reading data");
    log::info!("Read {} bytes: {:?}", sz, &rx_buf[..sz]);
    loop {}
}

pub struct Dummy;

impl drogue_tls::traits::Read for Dummy {
    fn read<'m>(&'m mut self, _: &'m mut [u8]) -> Result<usize, TlsError> {
        todo!()
    }
}
impl drogue_tls::traits::Write for Dummy {
    fn write<'m>(&'m mut self, _: &'m [u8]) -> Result<usize, TlsError> {
        todo!()
    }
}
