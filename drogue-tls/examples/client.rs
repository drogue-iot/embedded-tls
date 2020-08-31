/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

extern crate mbedtls;

use std::io::{self, stdin, stdout, Write};
use std::net::TcpStream;

use mbedtls::rng::CtrDrbg;
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::{Config, Context};
use mbedtls::x509::Certificate;
use mbedtls::Result as TlsResult;

#[path = "../tests/support/mod.rs"]
mod support;
use support::entropy::entropy_new;
use support::keys;

fn result_main(addr: &str) -> TlsResult<()> {
    let mut entropy = entropy_new();
    let mut rng = CtrDrbg::new(&mut entropy, None)?;
    let mut cert = Certificate::from_pem(keys::PEM_CERT)?;
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    config.set_rng(Some(&mut rng));
    config.set_ca_list(Some(&mut *cert), None);
    let mut ctx = Context::new(&config)?;

    let mut conn = TcpStream::connect(addr).unwrap();
    let mut session = ctx.establish(&mut conn, None)?;

    let mut line = String::new();
    stdin().read_line(&mut line).unwrap();
    session.write_all(line.as_bytes()).unwrap();
    io::copy(&mut session, &mut stdout()).unwrap();
    Ok(())
}

fn main() {
    let mut args = std::env::args();
    args.next();
    result_main(
        &args
            .next()
            .expect("supply destination in command-line argument"),
    )
    .unwrap();
}
