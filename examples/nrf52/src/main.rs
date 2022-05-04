#![no_std]
#![no_main]

use defmt_rtt as _;
use nrf52833_hal as hal;
use panic_probe as _;

use embedded_tls::blocking::*;

use cortex_m_rt::entry;

use hal::rng::Rng;

#[entry]
fn main() -> ! {
    let p = hal::pac::Peripherals::take().unwrap();
    let mut rng = Rng::new(p.RNG);
    defmt::info!("Connected");
    let mut record_buffer = [0; 16384];
    let config = TlsConfig::new().with_server_name("example.com");
    let mut tls: TlsConnection<Dummy, Aes128GcmSha256> =
        TlsConnection::new(Dummy {}, &mut record_buffer[..]);

    tls.open::<Rng, NoClock, 4096>(TlsContext::new(&config, &mut rng))
        .expect("error establishing TLS connection");

    tls.write(b"ping").expect("error writing data");

    let mut rx_buf = [0; 4096];
    let sz = tls.read(&mut rx_buf).expect("error reading data");
    defmt::info!("Read {} bytes: {:?}", sz, &rx_buf[..sz]);
    loop {}
}

pub struct Dummy;

impl embedded_tls::traits::Read for Dummy {
    fn read<'m>(&'m mut self, _: &'m mut [u8]) -> Result<usize, TlsError> {
        todo!()
    }
}
impl embedded_tls::traits::Write for Dummy {
    fn write<'m>(&'m mut self, _: &'m [u8]) -> Result<usize, TlsError> {
        todo!()
    }
}
