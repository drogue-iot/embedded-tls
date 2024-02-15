#![no_std]
#![no_main]

use core::convert::Infallible;

use defmt_rtt as _;
use nrf52833_hal as hal;
use panic_probe as _;

use embedded_io::Write as _;
use embedded_tls::blocking::*;

use cortex_m_rt::entry;

use hal::rng::Rng;

#[entry]
fn main() -> ! {
    let p = hal::pac::Peripherals::take().unwrap();
    let rng = Rng::new(p.RNG);
    defmt::info!("Connected");
    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];
    let config = TlsConfig::new().with_server_name("example.com");
    let mut tls = TlsConnection::new(Dummy {}, &mut read_record_buffer, &mut write_record_buffer);

    tls.open(TlsContext::new(
        &config,
        UnsecureProvider::new::<Aes128GcmSha256>(rng),
    ))
    .expect("error establishing TLS connection");

    tls.write_all(b"ping").expect("error writing data");
    tls.flush().expect("error flushing data");

    let mut rx_buf = [0; 4096];
    let sz = tls.read(&mut rx_buf).expect("error reading data");
    defmt::info!("Read {} bytes: {:?}", sz, &rx_buf[..sz]);
    loop {}
}

pub struct Dummy;

impl embedded_io::ErrorType for Dummy {
    type Error = Infallible;
}

impl embedded_io::Read for Dummy {
    fn read<'m>(&'m mut self, _: &'m mut [u8]) -> Result<usize, Self::Error> {
        todo!()
    }
}
impl embedded_io::Write for Dummy {
    fn write<'m>(&'m mut self, _: &'m [u8]) -> Result<usize, Self::Error> {
        todo!()
    }
    fn flush<'m>(&'m mut self) -> Result<(), Self::Error> {
        todo!()
    }
}
