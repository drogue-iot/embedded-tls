/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

extern crate mbedtls;

use mbedtls::hash::Type::Sha256;
use mbedtls::pk::Pk;
use mbedtls::Error;

mod support;
use support::rand::test_rng;

const RSA_BITS: u32 = 2048;
const EXPONENT: u32 = 0x10001;

#[test]
fn sign_verify() {
    let mut k = Pk::generate_rsa(&mut test_rng(), RSA_BITS, EXPONENT).unwrap();

    let data = b"SIGNATURE TEST SIGNATURE TEST SI";
    let mut signature = [0u8; RSA_BITS as usize / 8];

    assert_eq!(
        k.sign(Sha256, data, &mut signature, &mut test_rng())
            .unwrap(),
        signature.len()
    );
    k.verify(Sha256, data, &signature).unwrap();
}

#[test]
fn buffer_too_small() {
    let mut k = Pk::generate_rsa(&mut test_rng(), RSA_BITS, EXPONENT).unwrap();

    let data = b"SIGNATURE TEST SIGNATURE TEST SI";
    let mut signature = [0u8; RSA_BITS as usize / 8 - 1];

    assert_eq!(
        k.sign(Sha256, data, &mut signature, &mut test_rng()).err(),
        Some(Error::PkSigLenMismatch)
    );
}

#[test]
fn encrypt_decrypt() {
    let mut k = Pk::generate_rsa(&mut test_rng(), RSA_BITS, EXPONENT).unwrap();

    let plain = b"ENCRYPT TEST ENCRYPT TEST ENCRYP";
    let mut cipher = [0u8; RSA_BITS as usize / 8];
    let mut decrypted = [0u8; 32];

    assert_eq!(
        k.encrypt(plain, &mut cipher, &mut test_rng()).unwrap(),
        cipher.len()
    );
    assert_eq!(
        k.decrypt(&cipher, &mut decrypted, &mut test_rng()).unwrap(),
        plain.len()
    );
    assert_eq!(plain, &decrypted);
}
