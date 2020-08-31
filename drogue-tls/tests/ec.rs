/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

extern crate mbedtls;

use mbedtls::hash::Md;
use mbedtls::hash::Type;
use mbedtls::hash::Type::Sha256;
use mbedtls::pk::{Pk, ECDSA_MAX_LEN};
use mbedtls::Error;

mod support;
use support::rand::test_rng;

// This is a test key generated with the pk::generate_ec_secp256r1 test.
const TEST_KEY_PEM: &'static str = "-----BEGIN EC PRIVATE KEY-----
MHgCAQEEIQCE4WNND2Lx24xc1Q4LPR/CygNZDEOmZF5tmwCTL5CVN6AKBggqhkjO
PQMBB6FEA0IABKlh7VJ0BOcpyY/EWjQjod5K1zGFvOXLm8EPVv/9uQJ/HL4lZxFH
kK4RGxVhveMLxLkqfyWb/N3PyU1nWdr2ZXU=
-----END EC PRIVATE KEY-----
\0";

const RFC6979_P256_KEY: &'static str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgya+p2EW6dRZrXCFX
Z7HWk05Qw9s26JsSe4piKxIPZyGhRANCAARg/tS6JVqdMclh63TGNW1owEm4kjth
+mzmaWIuYPKftnkD/hAIuLyZpBrp6VYovGTy8bIMLX6fUXejwpTURiKZ
-----END PRIVATE KEY-----
\0";

const RFC6979_P521_KEY: &'static str = "-----BEGIN PRIVATE KEY-----
MIHtAgEAMBAGByqGSM49AgEGBSuBBAAjBIHVMIHSAgEBBEH60G2qYro7JdL7QBM9
p1cgXeZ/W7ABj+6MhuG2jH51yqiW6zLx9HxwhVg2ptFvzBRm9tj77GfbiewMCLDp
lrg1OKGBiQOBhgAEAYlFUNB4WTLgDqojtpTyE/jDEh+G3JegTlpxZ9tOW803ESPU
bkXba11TcKfyD7YzFV04/6FtK9dh3KxHS5ovUCOkAEkxAclizU0v3feCKF5kWEE5
wvkbR/h/+CNU1mMPdGoooNsldBtbNKgoAIsirMI/kk+q+9TTP4HqZpVt/qor/fz1
-----END PRIVATE KEY-----
\0";

#[test]
fn sign_verify() {
    let mut k = Pk::from_private_key(TEST_KEY_PEM.as_bytes(), None).unwrap();

    let data = b"SIGNATURE TEST SIGNATURE TEST SI";
    let mut signature1 = [0u8; ECDSA_MAX_LEN];
    let mut signature2 = [0u8; ECDSA_MAX_LEN];

    let mut rng = test_rng();
    let len = k
        .sign(Sha256, data, &mut signature1, &mut rng)
        .unwrap();
    k.verify(Sha256, data, &signature1[0..len]).unwrap();

    let len = k
        .sign(Sha256, data, &mut signature2, &mut rng)
        .unwrap();
    k.verify(Sha256, data, &signature2[0..len]).unwrap();

    // Default ECDSA is randomized
    assert!(&signature1[..] != &signature2[..]);
}

#[test]
fn verify_failure() {
    let mut k = Pk::from_private_key(TEST_KEY_PEM.as_bytes(), None).unwrap();

    let data = b"SIGNATURE TEST SIGNATURE TEST SI";
    let mut signature = [0u8; ECDSA_MAX_LEN];

    let len = k
        .sign(Sha256, data, &mut signature, &mut test_rng())
        .unwrap();
    k.verify(Sha256, data, &signature[0..len]).unwrap();
    signature[0] ^= 1u8;
    k.verify(Sha256, data, &signature[0..len])
        .err()
        .expect("Verify of corrupted signature should fail");
}

#[test]
fn sign_verify_rfc6979_sig() {
    fn to_hex(bin: &[u8]) -> String {
        let mut s = "".to_owned();
        for b in bin {
            s.push_str(&format!("{:02X}", b));
        }
        return s;
    }

    fn test_rfc6979_sig(pk: &mut Pk, input: &str, md: Type, expected: &str) {
        let mut digest = [0u8; 64];
        let digest_len = Md::hash(md, input.as_bytes(), &mut digest).unwrap();
        let mut signature = [0u8; ECDSA_MAX_LEN];

        let sig_len = pk
            .sign_deterministic(md, &digest[0..digest_len], &mut signature, &mut test_rng())
            .unwrap();

        assert_eq!(to_hex(&signature[0..sig_len]), expected);

        pk.verify(md, &digest[0..digest_len], &signature[0..sig_len])
            .unwrap();
    }

    let mut p256 = Pk::from_private_key(RFC6979_P256_KEY.as_bytes(), None).unwrap();

    test_rfc6979_sig(&mut p256, "sample", Type::Sha1,
			 "3044022061340C88C3AAEBEB4F6D667F672CA9759A6CCAA9FA8811313039EE4A35471D3202206D7F147DAC089441BB2E2FE8F7A3FA264B9C475098FDCF6E00D7C996E1B8B7EB");

    test_rfc6979_sig(&mut p256, "sample", Type::Sha224,
			 "3045022053B2FFF5D1752B2C689DF257C04C40A587FABABB3F6FC2702F1343AF7CA9AA3F022100B9AFB64FDC03DC1A131C7D2386D11E349F070AA432A4ACC918BEA988BF75C74C");

    test_rfc6979_sig(&mut p256, "sample", Type::Sha256,
			 "3046022100EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716022100F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");

    test_rfc6979_sig(&mut p256, "sample", Type::Sha384,
			 "304402200EAFEA039B20E9B42309FB1D89E213057CBF973DC0CFC8F129EDDDC800EF771902204861F0491E6998B9455193E34E7B0D284DDD7149A74B95B9261F13ABDE940954");

    test_rfc6979_sig(&mut p256, "sample", Type::Sha512,
			 "30450221008496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F0002202362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE");

    test_rfc6979_sig(&mut p256, "test", Type::Sha1,
			 "304402200CBCC86FD6ABD1D99E703E1EC50069EE5C0B4BA4B9AC60E409E8EC5910D81A89022001B9D7B73DFAA60D5651EC4591A0136F87653E0FD780C3B1BC872FFDEAE479B1");

    test_rfc6979_sig(&mut p256, "test", Type::Sha224,
			 "3046022100C37EDB6F0AE79D47C3C27E962FA269BB4F441770357E114EE511F662EC34A692022100C820053A05791E521FCAAD6042D40AEA1D6B1A540138558F47D0719800E18F2D");

    test_rfc6979_sig(&mut p256, "test", Type::Sha256,
			 "3045022100F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D383670220019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083");

    test_rfc6979_sig(&mut p256, "test", Type::Sha384,
			 "304602210083910E8B48BB0C74244EBDF7F07A1C5413D61472BD941EF3920E623FBCCEBEB60221008DDBEC54CF8CD5874883841D712142A56A8D0F218F5003CB0296B6B509619F2C");

    test_rfc6979_sig(&mut p256, "test", Type::Sha512,
			 "30440220461D93F31B6540894788FD206C07CFA0CC35F46FA3C91816FFF1040AD1581A04022039AF9F15DE0DB8D97E72719C74820D304CE5226E32DEDAE67519E840D1194E55");

    let mut p521 = Pk::from_private_key(RFC6979_P521_KEY.as_bytes(), None).unwrap();

    test_rfc6979_sig(&mut p521, "sample", Type::Sha1,
			 "3081870241343B6EC45728975EA5CBA6659BBB6062A5FF89EEA58BE3C80B619F322C87910FE092F7D45BB0F8EEE01ED3F20BABEC079D202AE677B243AB40B5431D497C55D75D024200E7B0E675A9B24413D448B8CC119D2BF7B2D2DF032741C096634D6D65D0DBE3D5694625FB9E8104D3B842C1B0E2D0B98BEA19341E8676AEF66AE4EBA3D5475D5D16");

    test_rfc6979_sig(&mut p521, "sample", Type::Sha512,
			 "308187024200C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F174E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E377FA0241617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF282623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A67A");
}

#[test]
fn buffer_too_small() {
    let mut k = Pk::from_private_key(TEST_KEY_PEM.as_bytes(), None).unwrap();

    let data = b"SIGNATURE TEST SIGNATURE TEST SI";
    let mut signature = [0u8; ECDSA_MAX_LEN - 1];

    assert_eq!(
        k.sign(Sha256, data, &mut signature, &mut test_rng()).err(),
        Some(Error::PkSigLenMismatch)
    );
}
