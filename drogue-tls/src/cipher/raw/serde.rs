/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
use crate::cipher::*;
use core::fmt;
use core::marker::PhantomData;
use core::mem::size_of;
use core::ptr;
use core::slice::from_raw_parts;
use core::str;
use core::result::Result;
use mbedtls_sys::*;
use serde;
use serde::de::Unexpected;
use serde::ser::SerializeSeq;
use serde::{de, ser};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

struct Bytes<T: BytesSerde>(T);

#[derive(Serialize, Deserialize)]
enum SavedCipher {
    Encryption(SavedRawCipher, raw::CipherPadding),
    Decryption(SavedRawCipher, raw::CipherPadding),
}

// Custom serialization in serde.rs to force encoding as sequence.
#[derive(Deserialize)]
pub struct SavedRawCipher {
    cipher_id: cipher_id_t,
    cipher_mode: cipher_mode_t,
    key_bit_len: u32,
    context: Bytes<cipher_context_t>,
    algorithm_ctx: AlgorithmContext,
}

#[derive(Serialize, Deserialize)]
enum AlgorithmContext {
    Aes(Bytes<aes_context>),
    Des(Bytes<des_context>),
    Des3(Bytes<des3_context>),
    Gcm {
        context: Bytes<gcm_context>,
        inner_cipher_ctx: Box<SavedRawCipher>
    }
}

// Serialization support for cipher structs. We only support serialization in the "data" state.

impl<Op: Operation, T: Type> Serialize for Cipher<Op, T, CipherData> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let saved_raw_cipher = unsafe {
            let cipher_context = self.raw_cipher.inner;
            serialize_raw_cipher(cipher_context)
                .map_err(ser::Error::custom)?
        };

        match Op::is_encrypt() {
            true => SavedCipher::Encryption(saved_raw_cipher, self.padding).serialize(s),
            false => SavedCipher::Decryption(saved_raw_cipher, self.padding).serialize(s),
        }
    }
}

unsafe fn serialize_raw_cipher(mut cipher_context: cipher_context_t)
    -> Result<SavedRawCipher, &'static str> {

    let cipher_id = (*(*cipher_context.cipher_info).base).cipher;
    let cipher_mode = (*cipher_context.cipher_info).mode;
    let key_bit_len = (*cipher_context.cipher_info).key_bitlen;

    // Null the cipher info now that we've extracted the important bits.
    cipher_context.cipher_info = ::core::ptr::null();

    // We only allow certain modes that we know have serialization-safe context
    // structures. If adding GCM/CCM support, be aware that they don't use the same
    // context types as the conventional modes.
    let algorithm_ctx = match (cipher_id, cipher_mode) {
        (CIPHER_ID_AES, MODE_CBC)
        | (CIPHER_ID_AES, MODE_CTR)
        | (CIPHER_ID_AES, MODE_CFB)
        | (CIPHER_ID_AES, MODE_ECB) => {
            let mut aes_context = *(cipher_context.cipher_ctx as *const aes_context);
            aes_context.rk = ::core::ptr::null_mut();
            AlgorithmContext::Aes(Bytes(aes_context))
        }
        (CIPHER_ID_DES, MODE_CBC)
        | (CIPHER_ID_DES, MODE_CTR)
        | (CIPHER_ID_DES, MODE_CFB) => {
            AlgorithmContext::Des(Bytes(*(cipher_context.cipher_ctx as *const des_context)))
        }
        (CIPHER_ID_3DES, MODE_CBC)
        | (CIPHER_ID_3DES, MODE_CTR)
        | (CIPHER_ID_3DES, MODE_CFB) => AlgorithmContext::Des3(Bytes(
            *(cipher_context.cipher_ctx as *const des3_context),
        )),
        (CIPHER_ID_AES, MODE_GCM) => {
            let gcm_context = *(cipher_context.cipher_ctx as *const gcm_context);

            let inner_ctx = gcm_context.cipher_ctx;

            let inner_saved_cipher = serialize_raw_cipher(inner_ctx)?;

            AlgorithmContext::Gcm {
                context: Bytes(gcm_context),
                inner_cipher_ctx: Box::new(inner_saved_cipher)
            }
        },
        _ => {
            return Err("unsupported algorithm for serialization");
        }
    };

    // Null the algorithm context
    cipher_context.cipher_ctx = ::core::ptr::null_mut();

    // Null function pointers
    cipher_context.add_padding = None;
    cipher_context.get_padding = None;

    Ok(SavedRawCipher {
        cipher_id: cipher_id,
        cipher_mode: cipher_mode,
        key_bit_len: key_bit_len,
        context: Bytes(cipher_context),
        algorithm_ctx: algorithm_ctx,
    })
}

impl<'de, Op: Operation, T: Type> Deserialize<'de> for Cipher<Op, T, CipherData> {
    fn deserialize<D>(d: D) -> Result<Cipher<Op, T, CipherData>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let saved_cipher: SavedCipher = SavedCipher::deserialize(d)?;

        let (raw, padding) = match saved_cipher {
            SavedCipher::Encryption(..) if !Op::is_encrypt() => {
                return Err(de::Error::invalid_value(
                    Unexpected::Other("incorrect cipher operation"),
                    &"encryption",
                ));
            }
            SavedCipher::Decryption(..) if Op::is_encrypt() => {
                return Err(de::Error::invalid_value(
                    Unexpected::Other("incorrect cipher operation"),
                    &"decryption",
                ));
            }
            SavedCipher::Encryption(raw, padding) | SavedCipher::Decryption(raw, padding)
            => {
                (raw, padding)
            }
        };

        unsafe {
            let raw_cipher = deserialize_raw_cipher(raw, padding)
                .map_err(|(e1, e2)| de::Error::invalid_value(Unexpected::Other(e1), &e2))?;
            Ok(Cipher {
                raw_cipher: raw_cipher,
                padding: padding,
                _op: PhantomData,
                _type: PhantomData,
                _state: PhantomData,
            })
        }
    }
}

unsafe fn deserialize_raw_cipher(raw: SavedRawCipher, padding: raw::CipherPadding)
    -> Result<raw::Cipher, (&'static str, &'static str)> {

    let mut raw_cipher = match raw::Cipher::setup(
        raw.cipher_id.into(),
        raw.cipher_mode.into(),
        raw.key_bit_len,
    ) {
        Ok(raw) => raw,
        Err(_) => {
            return Err(("bad cipher parameters", "valid parameters"));
        }
    };

    if raw.cipher_mode == MODE_CBC {
        raw_cipher
            .set_padding(padding)
            .map_err(|_| ("bad padding mode", "valid mode"))?;
    }

    let cipher_context = &mut raw_cipher.inner;

    match (raw.cipher_id, raw.algorithm_ctx) {
        (CIPHER_ID_AES, AlgorithmContext::Aes(Bytes(aes_ctx))) => {
            let ret_aes_ctx = cipher_context.cipher_ctx as *mut aes_context;
            *ret_aes_ctx = aes_ctx;
            // aes_ctx.rk needs to be a pointer to aes_ctx.buf, which holds the round keys.
            // We don't adjust for the padding needed on VIA Padlock (see definition of
            // mbedtls_aes_context in the mbedTLS source).
            (*ret_aes_ctx).rk = &mut (*ret_aes_ctx).buf[0];
        }
        (CIPHER_ID_DES, AlgorithmContext::Des(Bytes(des_ctx))) => {
            *(cipher_context.cipher_ctx as *mut des_context) = des_ctx
        }
        (CIPHER_ID_3DES, AlgorithmContext::Des3(Bytes(des3_ctx))) => {
            *(cipher_context.cipher_ctx as *mut des3_context) = des3_ctx
        }
        (CIPHER_ID_AES, AlgorithmContext::Gcm {
            context: Bytes(mut gcm_ctx),
            inner_cipher_ctx
        }) => {
            let inner_raw_cipher = deserialize_raw_cipher(*inner_cipher_ctx, raw::CipherPadding::None)?;
            gcm_ctx.cipher_ctx = inner_raw_cipher.into_inner();

            *(cipher_context.cipher_ctx as *mut gcm_context) = gcm_ctx;
        }
        _ => {
            return Err(("bad algorithm", "valid algorithm"));
        }
    };

    cipher_context.key_bitlen = raw.context.0.key_bitlen;
    cipher_context.operation = raw.context.0.operation;
    cipher_context.unprocessed_data = raw.context.0.unprocessed_data;
    cipher_context.unprocessed_len = raw.context.0.unprocessed_len;
    cipher_context.iv = raw.context.0.iv;
    cipher_context.iv_size = raw.context.0.iv_size;

    Ok(raw_cipher)
}

// Serialization support for raw cipher structs. Custom serialization as a sequence to save the
// space of encoding all the member names.

impl Serialize for SavedRawCipher {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = s.serialize_seq(Some(5))?;
        seq.serialize_element(&self.cipher_id)?;
        seq.serialize_element(&self.cipher_mode)?;
        seq.serialize_element(&self.key_bit_len)?;
        seq.serialize_element(&self.context)?;
        seq.serialize_element(&self.algorithm_ctx)?;
        seq.end()
    }
}

// Byte block serialization support
// (Note: serde_cbor represents each element in a u8 Vec or slice as an
// integer, which uses two bytes except for most values.)

unsafe trait BytesSerde: Sized {
    fn read_slice(s: &[u8]) -> Option<Self> {
        unsafe {
            if s.len() == size_of::<Self>() {
                Some(ptr::read(s.as_ptr() as *const Self))
            } else {
                None
            }
        }
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

impl<T: BytesSerde> Serialize for Bytes<T> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_bytes(self.0.as_slice())
    }
}

impl<'de, T: BytesSerde> Deserialize<'de> for Bytes<T> {
    fn deserialize<D>(d: D) -> Result<Bytes<T>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BytesVisitor<T: BytesSerde>(PhantomData<T>);
        impl<'de, T: BytesSerde> de::Visitor<'de> for BytesVisitor<T> {
            type Value = Bytes<T>;

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                T::read_slice(v)
                    .map(Bytes)
                    .ok_or_else(|| E::invalid_length(v.len(), &self))
            }

            /*
            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_bytes(&v)
            }
             */

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{}", size_of::<T>())
            }
        }

        d.deserialize_bytes(BytesVisitor(PhantomData))
    }
}

unsafe impl BytesSerde for cipher_context_t {}
unsafe impl BytesSerde for aes_context {}
unsafe impl BytesSerde for des_context {}
unsafe impl BytesSerde for des3_context {}
unsafe impl BytesSerde for gcm_context {}

// If the C API changes, the serde implementation needs to be reviewed for correctness.

unsafe fn _check_cipher_context_t_size(ctx: cipher_context_t) -> [u8; 96] {
    ::core::mem::transmute(ctx)
}

unsafe fn _check_aes_context_size(ctx: aes_context) -> [u8; 288] {
    ::core::mem::transmute(ctx)
}

unsafe fn _check_des_context_size(ctx: des_context) -> [u8; 128] {
    ::core::mem::transmute(ctx)
}

unsafe fn _check_des3_context_size(ctx: des3_context) -> [u8; 384] {
    ::core::mem::transmute(ctx)
}

unsafe fn _check_gcm_context_size(ctx: gcm_context) -> [u8; 424] { ::core::mem::transmute(ctx) }
