/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use core::marker::PhantomData;
use core::ops::Range;
pub mod raw;

use crate::error::Result;

// Type-level operations
pub trait Operation: Sized {
    fn is_encrypt() -> bool;
}

#[derive(Serialize, Deserialize)]
pub enum Encryption {}
impl Operation for Encryption {
    fn is_encrypt() -> bool {
        true
    }
}

#[derive(Serialize, Deserialize)]
pub enum Decryption {}
impl Operation for Decryption {
    fn is_encrypt() -> bool {
        false
    }
}

// Type-level cipher types
pub trait Type {
    fn is_valid_mode(mode: raw::CipherMode) -> bool;
}

pub enum TraditionalNoIv {}
impl Type for TraditionalNoIv {
    fn is_valid_mode(mode: raw::CipherMode) -> bool {
        match mode {
            raw::CipherMode::ECB => true,
            _ => false,
        }
    }
}

pub enum Traditional {}
impl Type for Traditional {
    fn is_valid_mode(mode: raw::CipherMode) -> bool {
        match mode {
            raw::CipherMode::CBC
            | raw::CipherMode::CFB
            | raw::CipherMode::OFB
            | raw::CipherMode::CTR => true,
            _ => false,
        }
    }
}

pub enum Authenticated {}
impl Type for Authenticated {
    fn is_valid_mode(mode: raw::CipherMode) -> bool {
        match mode {
            raw::CipherMode::GCM | raw::CipherMode::CCM | raw::CipherMode::KW | raw::CipherMode::KWP => true,
            _ => false,
        }
    }
}

// Type-level states
pub trait State {}

pub enum Fresh {}
impl State for Fresh {}

pub enum AdditionalData {}
impl State for AdditionalData {}

pub enum CipherData {}
impl State for CipherData {}

pub enum Finished {}
impl State for Finished {}

pub struct Cipher<O: Operation, T: Type, S: State = Fresh> {
    raw_cipher: raw::Cipher,

    // mbedtls only stores the padding as function pointers, so we remember this here
    padding: raw::CipherPadding,
    _op: PhantomData<O>,
    _type: PhantomData<T>,
    _state: PhantomData<S>,
}

impl<O: Operation, T: Type, S: State> Cipher<O, T, S> {
    fn change_state<N: State>(self) -> Cipher<O, T, N> {
        self.change_type_and_state()
    }

    fn change_type_and_state<N: Type, M: State>(self) -> Cipher<O, N, M> {
        Cipher {
            raw_cipher: self.raw_cipher,
            padding: self.padding,
            _op: PhantomData,
            _type: PhantomData,
            _state: PhantomData,
        }
    }

    pub fn block_size(&self) -> usize {
        self.raw_cipher.block_size()
    }

    pub fn iv_size(&self) -> usize {
        self.raw_cipher.iv_size()
    }

    pub fn tag_size(&self) -> Option<Range<usize>> {
        if self.raw_cipher.is_authenticated() {
            Some(32..129)
        } else {
            None
        }
    }

    pub fn cipher_mode(&self) -> raw::CipherMode {
        self.raw_cipher.cipher_mode()
    }
}

impl<O: Operation, T: Type> Cipher<O, T, Fresh> {
    pub fn new(
        cipher_id: raw::CipherId,
        cipher_mode: raw::CipherMode,
        key_bit_len: u32,
    ) -> Result<Cipher<O, T, Fresh>> {
        assert!(T::is_valid_mode(cipher_mode));

        // Create raw cipher object
        let raw_cipher = raw::Cipher::setup(cipher_id, cipher_mode, key_bit_len)?;

        // Put together the structure to return
        Ok(Cipher {
            raw_cipher: raw_cipher,
            padding: raw::CipherPadding::Pkcs7,
            _op: PhantomData,
            _type: PhantomData,
            _state: PhantomData,
        })
    }

    pub fn set_parity(key: &mut [u8]) -> Result<()> {
        raw::Cipher::set_parity(key)
    }
}

impl<Op: Operation, T: Type> Cipher<Op, T, Fresh> {
    fn set_key_and_maybe_iv(&mut self, key: &[u8], iv: Option<&[u8]>) -> Result<()> {
        let cipher_op = if Op::is_encrypt() {
            raw::Operation::Encrypt
        } else {
            raw::Operation::Decrypt
        };

        // Set key
        self.raw_cipher.set_key(cipher_op, key)?;

        // Set IV
        if let Some(iv) = iv {
            self.raw_cipher.set_iv(iv)?;
        }

        // Also do a reset right here so the user can start the crypto operation right away in "CipherData"
        self.raw_cipher.reset()
    }

    pub fn set_padding(&mut self, padding: raw::CipherPadding) -> Result<()> {
        self.padding = padding;
        self.raw_cipher.set_padding(padding)
    }
}

impl<O: Operation> Cipher<O, TraditionalNoIv, Fresh> {
    pub fn set_key(mut self, key: &[u8]) -> Result<Cipher<O, Traditional, CipherData>> {
        self.set_key_and_maybe_iv(key, None)?;

        // Put together the structure to return
        Ok(self.change_type_and_state())
    }
}

impl<O: Operation> Cipher<O, Traditional, Fresh> {
    pub fn set_key_iv(
        mut self,
        key: &[u8],
        iv: &[u8],
    ) -> Result<Cipher<O, Traditional, CipherData>> {
        self.set_key_and_maybe_iv(key, Some(iv))?;

        // Put together the structure to return
        Ok(self.change_state())
    }
}

impl<O: Operation> Cipher<O, Authenticated, Fresh> {
    pub fn set_key_iv(
        mut self,
        key: &[u8],
        iv: &[u8],
    ) -> Result<Cipher<O, Authenticated, AdditionalData>> {
        self.set_key_and_maybe_iv(key, Some(iv))?;

        // Put together the structure to return
        Ok(self.change_state())
    }
}

impl<O: Operation> Cipher<O, Authenticated, AdditionalData> {
    pub fn set_ad(
        mut self,
        ad: &[u8]
    ) -> Result<Cipher<O, Authenticated, CipherData>> {

        // For AEAD add AD
        self.raw_cipher.update_ad(ad)?;

        // Put together the structure to return
        Ok(self.change_state())
    }
}

impl Cipher<Encryption, Traditional, CipherData> {
    pub fn encrypt(
        mut self,
        plain_text: &[u8],
        cipher_text: &mut [u8],
    ) -> Result<(usize, Cipher<Encryption, Traditional, Finished>)> {
        // Call the wrapper function to encrypt all
        let len = self.raw_cipher.encrypt(plain_text, cipher_text)?;

        // Put together the structure to return
        Ok((len, self.change_state()))
    }
}

impl Cipher<Decryption, Traditional, CipherData> {
    pub fn decrypt(
        mut self,
        cipher_text: &[u8],
        plain_text: &mut [u8],
    ) -> Result<(usize, Cipher<Decryption, Traditional, Finished>)> {
        // Call the wrapper function to decrypt all
        let len = self.raw_cipher.decrypt(cipher_text, plain_text)?;

        // Put together the structure to return
        Ok((len, self.change_state()))
    }
}

impl Cipher<Encryption, TraditionalNoIv, Fresh> {
    pub fn cmac(mut self,
                key: &[u8],
                in_data: &[u8],
                out_data: &mut [u8])
                -> Result<Cipher<Encryption, TraditionalNoIv, Finished>> {
        self.raw_cipher.cmac(key, in_data, out_data)?;
        Ok(self.change_state())
    }
}

impl Cipher<Encryption, Authenticated, AdditionalData> {
    pub fn encrypt_auth(
        mut self,
        ad: &[u8],
        plain_text: &[u8],
        cipher_text: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(usize, Cipher<Encryption, Authenticated, Finished>)> {
        Ok((
            self.raw_cipher
                .encrypt_auth(ad, plain_text, cipher_text, tag)?,
            self.change_state(),
        ))
    }
}

impl Cipher<Decryption, Authenticated, AdditionalData> {
    pub fn decrypt_auth(
        mut self,
        ad: &[u8],
        cipher_text: &[u8],
        plain_text: &mut [u8],
        tag: &[u8],
    ) -> Result<(usize, Cipher<Decryption, Authenticated, Finished>)> {
        Ok((
            self.raw_cipher
                .decrypt_auth(ad, cipher_text, plain_text, tag)?,
            self.change_state(),
        ))
    }
}

impl<O: Operation, T: Type> Cipher<O, T, CipherData> {
    pub fn update(
        mut self,
        in_data: &[u8],
        out_data: &mut [u8],
    ) -> Result<(usize, Cipher<O, T, CipherData>)> {
        // Call the wrapper function to do update operation (multi part)
        let len = self.raw_cipher.update(in_data, out_data)?;

        // Put together the structure to return
        Ok((len, self.change_state()))
    }

    pub fn finish(mut self, out_data: &mut [u8]) -> Result<(usize, Cipher<O, T, Finished>)> {
        // Call the wrapper function to finish operation (multi part)
        let len = self.raw_cipher.finish(out_data)?;

        // Put together the structure to return
        Ok((len, self.change_state()))
    }
}

impl<O: Operation> Cipher<O, Authenticated, Finished> {
    pub fn write_tag(mut self, out_tag: &mut [u8]) -> Result<Cipher<O, Authenticated, Finished>> {
        self.raw_cipher.write_tag(out_tag)?;

        // Put together the structure to return
        Ok(self.change_state())
    }

    pub fn check_tag(mut self, tag: &[u8]) -> Result<Cipher<O, Authenticated, Finished>> {
        self.raw_cipher.check_tag(tag)?;

        // Put together the structure to return
        Ok(self.change_state())
    }
}

#[test]
fn cmac() {
    // From NIST CAVS

    let key = [0x7c, 0x0b, 0x7d, 0xb9, 0x81, 0x1f, 0x10, 0xd0, 0x0e, 0x47, 0x6c, 0x7a, 0x0d, 0x92, 0xf6, 0xe0];
    let msg = [0x1e, 0xe0, 0xec, 0x46, 0x6d, 0x46, 0xfd, 0x84, 0x9b, 0x40, 0xc0, 0x66, 0xb4, 0xfb, 0xbd, 0x22,
               0xa2, 0x0a, 0x4d, 0x80, 0xa0, 0x08, 0xac, 0x9a, 0xf1, 0x7e, 0x4f, 0xdf, 0xd1, 0x06, 0x78, 0x5e];
    let expected = vec![0xba, 0xec, 0xdc, 0x91, 0xe9, 0xa1, 0xfc, 0x35, 0x72, 0xad, 0xf1, 0xe4, 0x23, 0x2a, 0xe2, 0x85];

    let cipher = Cipher::<_, TraditionalNoIv, _>::new(
        raw::CipherId::Aes,
        raw::CipherMode::ECB,
        (key.len() * 8) as _,
    ).unwrap();

    let mut generated = vec![0u8; 16];
    cipher.cmac(&key, &msg, &mut generated).unwrap();

    assert_eq!(generated, expected);
}

#[test]
fn ccm() {
    // Example vector C.1
    let k = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f,
    ];
    let iv = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16];
    let ad = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let p = [0x20, 0x21, 0x22, 0x23];
    let mut p_out = [0u8; 4];
    let c = [0x71, 0x62, 0x01, 0x5b];
    let mut c_out = [0u8; 4];
    let t = [0x4d, 0xac, 0x25, 0x5d];
    let mut t_out = [0u8; 4];

    let cipher = Cipher::<_, Authenticated, _>::new(
        raw::CipherId::Aes,
        raw::CipherMode::CCM,
        (k.len() * 8) as _,
    )
    .unwrap();
    let cipher = cipher.set_key_iv(&k, &iv).unwrap();
    cipher
        .encrypt_auth(&ad, &p, &mut c_out, &mut t_out)
        .unwrap();
    assert_eq!(c, c_out);
    assert_eq!(t, t_out);
    let cipher = Cipher::<_, Authenticated, _>::new(
        raw::CipherId::Aes,
        raw::CipherMode::CCM,
        (k.len() * 8) as _,
    )
    .unwrap();
    let cipher = cipher.set_key_iv(&k, &iv).unwrap();
    cipher.decrypt_auth(&ad, &c, &mut p_out, &t).unwrap();
    assert_eq!(p, p_out);
}

#[test]
fn aes_kw() {
	let k = [0x75, 0x75, 0xda, 0x3a, 0x93, 0x60, 0x7c, 0xc2, 0xbf, 0xd8, 0xce, 0xc7, 0xaa, 0xdf, 0xd9, 0xa6];
	let p = [0x42, 0x13, 0x6d, 0x3c, 0x38, 0x4a, 0x3e, 0xea, 0xc9, 0x5a, 0x06, 0x6f, 0xd2, 0x8f, 0xed, 0x3f];
	let mut p_out = [0u8; 16];
	let c = [0x03, 0x1f, 0x6b, 0xd7, 0xe6, 0x1e, 0x64, 0x3d,
	         0xf6, 0x85, 0x94, 0x81, 0x6f, 0x64, 0xca, 0xa3,
             0xf5, 0x6f, 0xab, 0xea, 0x25, 0x48, 0xf5, 0xfb];
	let mut c_out = [0u8; 24];

	let cipher = Cipher::<_, Authenticated, _>::new(raw::CipherId::Aes, raw::CipherMode::KW, (k.len() * 8) as _).unwrap();
	let cipher = cipher.set_key_iv(&k, &[]).unwrap();
	cipher.encrypt_auth(&[], &p, &mut c_out, &mut[]).unwrap();
	assert_eq!(c, c_out);
	let cipher = Cipher::<_, Authenticated, _>::new(raw::CipherId::Aes, raw::CipherMode::KW, (k.len() * 8) as _).unwrap();
	let cipher = cipher.set_key_iv(&k, &[]).unwrap();
	cipher.decrypt_auth(&[], &c, &mut p_out, &[]).unwrap();
	assert_eq!(p, p_out);
}

#[test]
fn aes_kwp() {
	let k = [0x78, 0x65, 0xe2, 0x0f, 0x3c, 0x21, 0x65, 0x9a, 0xb4, 0x69, 0x0b, 0x62, 0x9c, 0xdf, 0x3c, 0xc4];
	let p = [0xbd, 0x68, 0x43, 0xd4, 0x20, 0x37, 0x8d, 0xc8, 0x96];
	let mut p_out = [0u8; 16];
	let c = [0x41, 0xec, 0xa9, 0x56, 0xd4, 0xaa, 0x04, 0x7e,
	         0xb5, 0xcf, 0x4e, 0xfe, 0x65, 0x96, 0x61, 0xe7,
             0x4d, 0xb6, 0xf8, 0xc5, 0x64, 0xe2, 0x35, 0x00];
	let mut c_out = [0u8; 24];

	let cipher = Cipher::<_, Authenticated, _>::new(raw::CipherId::Aes, raw::CipherMode::KWP, (k.len() * 8) as _).unwrap();
	let cipher = cipher.set_key_iv(&k, &[]).unwrap();
	cipher.encrypt_auth(&[], &p, &mut c_out, &mut[]).unwrap();
	assert_eq!(c, c_out);
	let cipher = Cipher::<_, Authenticated, _>::new(raw::CipherId::Aes, raw::CipherMode::KWP, (k.len() * 8) as _).unwrap();
	let cipher = cipher.set_key_iv(&k, &[]).unwrap();
	let out_len = cipher.decrypt_auth(&[], &c, &mut p_out, &[]).unwrap().0;
	assert_eq!(p, &p_out[..out_len]);
}
