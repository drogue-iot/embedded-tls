/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use mbedtls_sys::*;

use crate::error::{Error, IntoResult, Result};

//mod serde;

define!(
    #[c_ty(cipher_id_t)]
    enum CipherId {
        None = CIPHER_ID_NONE,
        Null = CIPHER_ID_NULL,
        Aes = CIPHER_ID_AES,
        Des = CIPHER_ID_DES,
        Des3 = CIPHER_ID_3DES,
        Camellia = CIPHER_ID_CAMELLIA,
        Blowfish = CIPHER_ID_BLOWFISH,
        Arc4 = CIPHER_ID_ARC4,
    }
);

impl From<cipher_id_t> for CipherId {
    fn from(inner: cipher_id_t) -> Self {
        match inner {
            CIPHER_ID_NONE => CipherId::None,
            CIPHER_ID_NULL => CipherId::Null,
            CIPHER_ID_AES => CipherId::Aes,
            CIPHER_ID_DES => CipherId::Des,
            CIPHER_ID_3DES => CipherId::Des3,
            CIPHER_ID_CAMELLIA => CipherId::Camellia,
            CIPHER_ID_BLOWFISH => CipherId::Blowfish,
            CIPHER_ID_ARC4 => CipherId::Arc4,
            // This should be replaced with TryFrom once it is stable.
            _ => panic!("Invalid cipher_id_t"),
        }
    }
}

define!(
    #[c_ty(cipher_mode_t)]
    #[derive(Copy, Clone, Eq, PartialEq)]
    enum CipherMode {
        None = MODE_NONE,
        ECB = MODE_ECB,
        CBC = MODE_CBC,
        CFB = MODE_CFB,
        OFB = MODE_OFB,
        CTR = MODE_CTR,
        GCM = MODE_GCM,
        STREAM = MODE_STREAM,
        CCM = MODE_CCM,
        KW = MODE_KW,
        KWP = MODE_KWP,
    }
);

impl From<cipher_mode_t> for CipherMode {
    fn from(inner: cipher_mode_t) -> Self {
        match inner {
            MODE_NONE => CipherMode::None,
            MODE_ECB => CipherMode::ECB,
            MODE_CBC => CipherMode::CBC,
            MODE_CFB => CipherMode::CFB,
            MODE_OFB => CipherMode::OFB,
            MODE_CTR => CipherMode::CTR,
            MODE_GCM => CipherMode::GCM,
            MODE_STREAM => CipherMode::STREAM,
            MODE_CCM => CipherMode::CCM,
            MODE_KW => CipherMode::KW,
            MODE_KWP => CipherMode::KWP,
            // This should be replaced with TryFrom once it is stable.
            _ => panic!("Invalid cipher_mode_t"),
        }
    }
}

define!(
    #[c_ty(cipher_type_t)]
    enum CipherType {
        None = CIPHER_NONE,
        Null = CIPHER_NULL,
        Aes128Ecb = CIPHER_AES_128_ECB,
        Aes192Ecb = CIPHER_AES_192_ECB,
        Aes256Ecb = CIPHER_AES_256_ECB,
        Aes128Cbc = CIPHER_AES_128_CBC,
        Aes192Cbc = CIPHER_AES_192_CBC,
        Aes256Cbc = CIPHER_AES_256_CBC,
        Aes128Cfb128 = CIPHER_AES_128_CFB128,
        Aes192Cfb128 = CIPHER_AES_192_CFB128,
        Aes256Cfb128 = CIPHER_AES_256_CFB128,
        Aes128Ctr = CIPHER_AES_128_CTR,
        Aes192Ctr = CIPHER_AES_192_CTR,
        Aes256Ctr = CIPHER_AES_256_CTR,
        Aes128Gcm = CIPHER_AES_128_GCM,
        Aes192Gcm = CIPHER_AES_192_GCM,
        Aes256Gcm = CIPHER_AES_256_GCM,
        Camellia128Ecb = CIPHER_CAMELLIA_128_ECB,
        Camellia192Ecb = CIPHER_CAMELLIA_192_ECB,
        Camellia256Ecb = CIPHER_CAMELLIA_256_ECB,
        Camellia128Cbc = CIPHER_CAMELLIA_128_CBC,
        Camellia192Cbc = CIPHER_CAMELLIA_192_CBC,
        Camellia256Cbc = CIPHER_CAMELLIA_256_CBC,
        Camellia128Cfb128 = CIPHER_CAMELLIA_128_CFB128,
        Camellia192Cfb128 = CIPHER_CAMELLIA_192_CFB128,
        Camellia256Cfb128 = CIPHER_CAMELLIA_256_CFB128,
        Camellia128Ctr = CIPHER_CAMELLIA_128_CTR,
        Camellia192Ctr = CIPHER_CAMELLIA_192_CTR,
        Camellia256Ctr = CIPHER_CAMELLIA_256_CTR,
        Camellia128Gcm = CIPHER_CAMELLIA_128_GCM,
        Camellia192Gcm = CIPHER_CAMELLIA_192_GCM,
        Camellia256Gcm = CIPHER_CAMELLIA_256_GCM,
        DesEcb = CIPHER_DES_ECB,
        DesCbc = CIPHER_DES_CBC,
        DesEdeEcb = CIPHER_DES_EDE_ECB,
        DesEdeCbc = CIPHER_DES_EDE_CBC,
        DesEde3Ecb = CIPHER_DES_EDE3_ECB,
        DesEde3Cbc = CIPHER_DES_EDE3_CBC,
        BlowfishEcb = CIPHER_BLOWFISH_ECB,
        BlowfishCbc = CIPHER_BLOWFISH_CBC,
        BlowfishCfb64 = CIPHER_BLOWFISH_CFB64,
        BlowfishCtr = CIPHER_BLOWFISH_CTR,
        Arcfour128 = CIPHER_ARC4_128,
        Aes128Ccm = CIPHER_AES_128_CCM,
        Aes192Ccm = CIPHER_AES_192_CCM,
        Aes256Ccm = CIPHER_AES_256_CCM,
        Camellia128Ccm = CIPHER_CAMELLIA_128_CCM,
        Camellia192Ccm = CIPHER_CAMELLIA_192_CCM,
        Camellia256Ccm = CIPHER_CAMELLIA_256_CCM,
        Aes128Kw = CIPHER_AES_128_KW,
        Aes192Kw = CIPHER_AES_192_KW,
        Aes256Kw = CIPHER_AES_256_KW,
        Aes128Kwp = CIPHER_AES_128_KWP,
        Aes192Kwp = CIPHER_AES_192_KWP,
        Aes256Kwp = CIPHER_AES_256_KWP,
    }
);

define!(
    #[c_ty(cipher_padding_t)]
    #[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
    enum CipherPadding {
        Pkcs7 = PADDING_PKCS7,
        IsoIec78164 = PADDING_ONE_AND_ZEROS,
        AnsiX923 = PADDING_ZEROS_AND_LEN,
        Zeros = PADDING_ZEROS,
        None = PADDING_NONE,
    }
);

define!(
    #[c_ty(operation_t)]
    enum Operation {
        None = OPERATION_NONE,
        Decrypt = DECRYPT,
        Encrypt = ENCRYPT,
    }
);

define!(
    #[c_ty(cipher_context_t)]
    #[repr(C)]
    struct Cipher;
    const init: fn() -> Self = cipher_init;
    const drop: fn(&mut Self) = cipher_free;
    impl<'a> Into<ptr> {}
);

impl Cipher {
    // Setup routine - this should be the first function called
    // it combines several steps into one call here, they are
    // Cipher init, Cipher setup
    pub fn setup(
        cipher_id: CipherId,
        cipher_mode: CipherMode,
        key_bit_len: u32,
    ) -> Result<Cipher> {
        let mut ret = Self::init();
        unsafe {
            // Do setup with proper cipher_info based on algorithm, key length and mode
            cipher_setup(
                &mut ret.inner,
                cipher_info_from_values(cipher_id.into(), key_bit_len as i32, cipher_mode.into())
            )
            .into_result()?;
        }
        Ok(ret)
    }

    // Cipher set key - should be called after setup
    pub fn set_key(&mut self, op: Operation, key: &[u8]) -> Result<()> {
        unsafe {
            cipher_setkey(
                &mut self.inner,
                key.as_ptr(),
                (key.len() * 8) as _,
                op.into(),
            )
            .into_result_discard()
        }
    }

    pub fn set_padding(&mut self, padding: CipherPadding) -> Result<()> {
        unsafe { cipher_set_padding_mode(&mut self.inner, padding.into()).into_result_discard() }
    }

    // Cipher set IV - should be called after setup
    pub fn set_iv(&mut self, iv: &[u8]) -> Result<()> {
        unsafe { cipher_set_iv(&mut self.inner, iv.as_ptr(), iv.len()).into_result_discard() }
    }

    pub fn reset(&mut self) -> Result<()> {
        unsafe { cipher_reset(&mut self.inner).into_result_discard() }
    }

    pub fn update_ad(&mut self, ad: &[u8]) -> Result<()> {
        unsafe { cipher_update_ad(&mut self.inner, ad.as_ptr(), ad.len()).into_result_discard() }
    }

    pub fn update(&mut self, indata: &[u8], outdata: &mut [u8]) -> Result<usize> {
        // Check that minimum required space is available in outdata buffer
        let reqd_size = if unsafe { *self.inner.cipher_info }.mode == MODE_ECB {
            self.block_size()
        } else {
            indata.len() + self.block_size()
        };

        if outdata.len() < reqd_size {
            return Err(Error::CipherFullBlockExpected);
        }

        let mut olen = 0;
        unsafe {
            cipher_update(
                &mut self.inner,
                indata.as_ptr(),
                indata.len(),
                outdata.as_mut_ptr(),
                &mut olen
            )
            .into_result()?;
        }
        Ok(olen)
    }

    pub fn finish(&mut self, outdata: &mut [u8]) -> Result<usize> {
        // Check that minimum required space is available in outdata buffer
        if outdata.len() < self.block_size() {
            return Err(Error::CipherFullBlockExpected);
        }

        let mut olen = 0;
        unsafe {
            cipher_finish(&mut self.inner, outdata.as_mut_ptr(), &mut olen).into_result()?;
        }
        Ok(olen)
    }

    pub fn write_tag(&mut self, tag: &mut [u8]) -> Result<()> {
        unsafe {
            cipher_write_tag(&mut self.inner, tag.as_mut_ptr(), tag.len()).into_result_discard()
        }
    }

    pub fn check_tag(&mut self, tag: &[u8]) -> Result<()> {
        unsafe { cipher_check_tag(&mut self.inner, tag.as_ptr(), tag.len()).into_result_discard() }
    }

    // Utility function to get block size for the selected / setup cipher_info
    pub fn block_size(&self) -> usize {
        unsafe { (*self.inner.cipher_info).block_size as usize }
    }

    // Utility function to get IV size for the selected / setup cipher_info
    pub fn iv_size(&self) -> usize {
        unsafe { (*self.inner.cipher_info).iv_size as usize }
    }

    pub fn cipher_mode(&self) -> CipherMode {
        unsafe { (*self.inner.cipher_info).mode.into() }
    }

    // Utility function to get mdoe for the selected / setup cipher_info
    pub fn is_authenticated(&self) -> bool {
        unsafe {
            if (*self.inner.cipher_info).mode == MODE_GCM
                || (*self.inner.cipher_info).mode == MODE_CCM
            {
                return true;
            } else {
                return false;
            }
        }
    }

    // Utility function to set odd parity - used for DES keys
    pub fn set_parity(key: &mut [u8]) -> Result<()> {
        unsafe { des_key_set_parity(key.as_mut_ptr()) }
        Ok(())
    }

    pub fn encrypt(&mut self, plain: &[u8], cipher: &mut [u8]) -> Result<usize> {
        self.do_crypto(plain, cipher)
    }

    pub fn decrypt(&mut self, cipher: &[u8], plain: &mut [u8]) -> Result<usize> {
        self.do_crypto(cipher, plain)
    }

    pub fn encrypt_auth(
        &mut self,
        ad: &[u8],
        plain: &[u8],
        cipher: &mut [u8],
        tag: &mut [u8],
    ) -> Result<usize> {
        if plain.len() > cipher.len() {
            return Err(Error::CipherBadInputData);
        }

        let iv = self.inner.iv;
        let iv_len = self.inner.iv_size;
        let mut cipher_len = cipher.len();
        unsafe {
            cipher_auth_encrypt(
                &mut self.inner,
                iv.as_ptr(),
                iv_len,
                ad.as_ptr(),
                ad.len(),
                plain.as_ptr(),
                plain.len(),
                cipher.as_mut_ptr(),
                &mut cipher_len,
                tag.as_mut_ptr(),
                tag.len(),
            )
            .into_result()?
        };

        Ok(cipher_len)
    }

    pub fn decrypt_auth(
        &mut self,
        ad: &[u8],
        cipher: &[u8],
        plain: &mut [u8],
        tag: &[u8],
    ) -> Result<usize> {
        // For AES KW and KWP cipher text length can be greater than plain text length
        if self.is_authenticated() && cipher.len() > plain.len() {
            return Err(Error::CipherBadInputData);
        }

        let iv = self.inner.iv;
        let iv_len = self.inner.iv_size;
        let mut plain_len = plain.len();
        unsafe {
            cipher_auth_decrypt(
                &mut self.inner,
                iv.as_ptr(),
                iv_len,
                ad.as_ptr(),
                ad.len(),
                cipher.as_ptr(),
                cipher.len(),
                plain.as_mut_ptr(),
                &mut plain_len,
                tag.as_ptr(),
                tag.len(),
            )
            .into_result()?
        };

        Ok(plain_len)
    }

    fn do_crypto(&mut self, indata: &[u8], outdata: &mut [u8]) -> Result<usize> {
        self.reset()?;

        // The total number of bytes writte to outdata so far. It's safe to
        // use this as a start index for slicing: &slice[slice.len()..] will
        // return an empty slice, it doesn't panic.
        let mut total_len = 0;

        if unsafe { *self.inner.cipher_info }.mode == MODE_ECB {
            // ECB mode requires single-block updates
            for chunk in indata.chunks(self.block_size()) {
                let len = self.update(chunk, &mut outdata[total_len..])?;
                total_len += len;
            }
        } else {
            total_len = self.update(indata, outdata)?;
            total_len += self.finish(&mut outdata[total_len..])?;
        }

        Ok(total_len)
    }

    pub fn cmac(&mut self, key: &[u8], data: &[u8], outdata: &mut [u8]) -> Result<()> {
        // Check that outdata buffer has enough space
        if outdata.len() < self.block_size() {
            return Err(Error::CipherFullBlockExpected);
        }
        self.reset()?;
        unsafe {
            cipher_cmac(&*self.inner.cipher_info, key.as_ptr(), (key.len() * 8) as _, data.as_ptr(), data.len(), 
                        outdata.as_mut_ptr()).into_result()?;
        }
        Ok(())
    }

}

#[test]
fn no_overflow() {
    let mut c = Cipher::setup(CipherId::Aes, CipherMode::CBC, 128).unwrap();
    c.set_key(Operation::Encrypt, &[0u8; 16]).unwrap();
    c.set_iv(&[0u8; 16]).unwrap();
    let mut out = [0u8; 48];
    let encrypt_result = c.encrypt(&[0u8; 16][..], &mut out[..16]);
    assert_eq!(out[16..], [0u8; 32]);
    encrypt_result.expect_err("Returned OK with too small buffer");
}

#[test]
fn one_part_ecb() {
    let mut c = Cipher::setup(CipherId::Aes, CipherMode::ECB, 128).unwrap();
    c.set_key(
        Operation::Encrypt,
        b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
    )
    .unwrap();
    let mut out = [0u8; 48];
    let len = c.encrypt(b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff", &mut out).unwrap();
    assert_eq!(len, 32);
    assert_eq!(&out[..len], b"\x69\xc4\xe0\xd8\x6a\x7b\x04\x30\xd8\xcd\xb7\x80\x70\xb4\xc5\x5a\x69\xc4\xe0\xd8\x6a\x7b\x04\x30\xd8\xcd\xb7\x80\x70\xb4\xc5\x5a");
}

#[test]
fn cmac_test() {
    let mut c = Cipher::setup(CipherId::Aes, CipherMode::ECB, 128).unwrap();
    let mut out = [0u8; 16];
    c.cmac(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
           b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff", &mut out).expect("Success in CMAC");
    assert_eq!(&out, b"\x38\x7b\x36\x22\x8b\xa7\x77\x44\x5b\xaf\xa0\x36\x45\xb9\x40\x10");
}
