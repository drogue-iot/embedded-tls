/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

extern crate mbedtls;

use mbedtls::hash::Type as MdType;
use mbedtls::hash::{pbkdf2_hmac, pbkdf_pkcs12};

#[test]
fn test_pbkdf2() {
    let mut output = [0u8; 48];

    let salt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

    let iterations = 10000;
    let passphrase = b"xyz";

    pbkdf2_hmac(MdType::Sha256, passphrase, &salt, iterations, &mut output).unwrap();

    assert_eq!(output[0..4], [0xDE, 0xFD, 0x29, 0x87]);

    assert_eq!(output[44..48], [0xE7, 0x0B, 0x72, 0xD0]);
}

#[test]
fn test_pkcs12_pbe() {
    // Test data from OpenSSL

    let mut output1 = [0u8; 24];
    let mut output2 = [0u8; 8];
    let mut output3 = [0u8; 20];

    let salt = [0x0A, 0x58, 0xCF, 0x64, 0x53, 0x0D, 0x82, 0x3F];
    let password = b"\x00\x73\x00\x6D\x00\x65\x00\x67\x00\x00";

    pbkdf_pkcs12(MdType::Sha1, password, &salt, 1, 1, &mut output1).unwrap();
    pbkdf_pkcs12(MdType::Sha1, password, &salt, 2, 1, &mut output2).unwrap();

    assert_eq!(
        output1,
        [
            0x8A, 0xAA, 0xE6, 0x29, 0x7B, 0x6C, 0xB0, 0x46, 0x42, 0xAB, 0x5B, 0x07, 0x78, 0x51,
            0x28, 0x4E, 0xB7, 0x12, 0x8F, 0x1A, 0x2A, 0x7F, 0xBC, 0xA3
        ]
    );
    assert_eq!(output2, [0x79, 0x99, 0x3D, 0xFE, 0x04, 0x8D, 0x3B, 0x76]);

    let salt = [0x3D, 0x83, 0xC0, 0xE4, 0x54, 0x6A, 0xC1, 0x40];
    pbkdf_pkcs12(MdType::Sha1, password, &salt, 3, 1, &mut output3).unwrap();
    assert_eq!(
        output3,
        [
            0x8D, 0x96, 0x7D, 0x88, 0xF6, 0xCA, 0xA9, 0xD7, 0x14, 0x80, 0x0A, 0xB3, 0xD4, 0x80,
            0x51, 0xD6, 0x3F, 0x73, 0xA3, 0x12
        ]
    );

    let mut output_1000iter = [0u8; 24];
    let salt = [0x16, 0x82, 0xC0, 0xFC, 0x5B, 0x3F, 0x7E, 0xC5];
    let password = [
        0x00, 0x71, 0x00, 0x75, 0x00, 0x65, 0x00, 0x65, 0x00, 0x67, 0x00, 0x00,
    ];

    pbkdf_pkcs12(
        MdType::Sha1,
        &password,
        &salt,
        1,
        1000,
        &mut output_1000iter,
    )
    .unwrap();
    assert_eq!(
        output_1000iter,
        [
            0x48, 0x3D, 0xD6, 0xE9, 0x19, 0xD7, 0xDE, 0x2E, 0x8E, 0x64, 0x8B, 0xA8, 0xF8, 0x62,
            0xF3, 0xFB, 0xFB, 0xDC, 0x2B, 0xCB, 0x2C, 0x02, 0x95, 0x7F
        ]
    );
}
