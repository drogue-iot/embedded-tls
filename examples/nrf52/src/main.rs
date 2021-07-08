#![macro_use]
#![allow(incomplete_features)]
#![feature(generic_associated_types)]
#![feature(min_type_alias_impl_trait)]
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
    let rng = Rng::new(p.RNG);
    log::info!("Connected");
    let mut record_buffer = [0; 16384];
    let tls_context = TlsContext::new(rng, &mut record_buffer).with_server_name("example.com");
    let mut tls: TlsConnection<Rng, Dummy, Aes128GcmSha256> =
        TlsConnection::new(tls_context, Dummy {});

    tls.open().expect("error establishing TLS connection");

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
