/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

//! Module to parse PKCS12/PFX files. Use Pfx::parse to get started

// Note that PKCS12/PFX uses the metaphor of a physical safe being used to
// protect the users data, resulting in various data structures with
// names like AuthenticatedSafe and SafeContents. These have nothing to do
// with Rust's notion of safety.

#[forbid(unsafe_code)]
#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;

use core::result::Result as StdResult;

#[cfg(feature = "pkcs12_rc2")]
extern crate block_modes;
#[cfg(feature = "pkcs12_rc2")]
extern crate rc2;

use core::fmt;

#[cfg(feature = "std")]
use std::error::Error as StdError;

use yasna::models::ObjectIdentifier;
use yasna::tags::*;
pub use yasna::{ASN1Error, ASN1ErrorKind};
use yasna::{ASN1Result, BERDecodable, BERReader, BERReaderSeq, Tag};

use crate::cipher::raw::{CipherId, CipherMode};
use crate::cipher::{Cipher, Decryption, Fresh, Traditional};
use crate::hash::{pbkdf_pkcs12, Md, MdInfo, Type as MdType};
use crate::pk::Pk;
use crate::x509::Certificate;
use crate::Error as MbedtlsError;

// Constants for various object identifiers used in PKCS12:

const PKCS7_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 1];
const PKCS7_ENCRYPTED_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 6];

const PKCS9_FRIENDLY_NAME: &[u64] = &[1, 2, 840, 113549, 1, 9, 20];
const PKCS9_X509_CERT: &[u64] = &[1, 2, 840, 113549, 1, 9, 22, 1];

const PKCS12_BAG_KEY: &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 1];
const PKCS12_BAG_PKCS8_KEY: &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 2];
const PKCS12_BAG_CERT: &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 3];
/*
const PKCS12_BAG_CRL          : &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 4];
const PKCS12_BAG_SECRET       : &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 5];
const PKCS12_BAG_SAFE_CONTENT : &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 6];
*/

const PKCS12_PBE_SHA_3DES_168: &[u64] = &[1, 2, 840, 113549, 1, 12, 1, 3];
const PKCS12_PBE_SHA_3DES_112: &[u64] = &[1, 2, 840, 113549, 1, 12, 1, 4];
const PKCS12_PBE_SHA_RC2_128: &[u64] = &[1, 2, 840, 113549, 1, 12, 1, 5];
const PKCS12_PBE_SHA_RC2_40: &[u64] = &[1, 2, 840, 113549, 1, 12, 1, 6];

const OID_SHA1: &[u64] = &[1, 3, 14, 3, 2, 26];
const OID_SHA256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
const OID_SHA384: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 2];
const OID_SHA512: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 3];

fn read_struct_from_bytes<T: BERDecodable>(der: &[u8]) -> ASN1Result<T> {
    yasna::decode_der::<T>(der)
}

fn read_struct<T: BERDecodable>(reader: &mut BERReaderSeq) -> ASN1Result<T> {
    read_struct_from_bytes(&reader.next().read_der()?)
}

fn read_string_type(der: &[u8]) -> ASN1Result<String> {
    yasna::parse_der(der, |reader| {
        let tag = reader.lookahead_tag()?;

        match tag {
            TAG_UTF8STRING => reader.read_utf8string(),
            TAG_PRINTABLESTRING => reader.read_printable_string(),
            TAG_NUMERICSTRING => reader.read_numeric_string(),

            // Support reading some string types not supported by yasna...
            TAG_IA5STRING => {
                // IA5 is (roughly speaking) equivalent to ASCII
                reader.read_tagged_implicit(TAG_IA5STRING, |reader| {
                    let bytes = reader.read_bytes()?;
                    Ok(String::from_utf8(bytes)
                        .map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))?)
                })
            }

            TAG_BMPSTRING => reader.read_tagged_implicit(TAG_BMPSTRING, |reader| {
                let bytes = reader.read_bytes()?;
                if bytes.len() % 2 != 0 {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                }

                let utf16 = bytes
                    .chunks(2)
                    .map(|c| (c[0] as u16) * 256 + c[1] as u16)
                    .collect::<Vec<_>>();

                Ok(String::from_utf16_lossy(&utf16))
            }),

            // Some unknown string type...
            _ => Err(ASN1Error::new(ASN1ErrorKind::Invalid)),
        }
    })
}

fn read_seq_of<T: BERDecodable + ::core::fmt::Debug>(der: &[u8]) -> ASN1Result<Vec<T>> {
    let mut result = Vec::new();

    yasna::parse_der(der, |reader| {
        reader.read_sequence_of(|reader| {
            if let Ok(data) = reader.read_der() {
                let v: T = yasna::decode_der(&data)?;
                result.push(v);
                return Ok(());
            } else {
                return Err(ASN1Error::new(ASN1ErrorKind::Eof));
            }
        })?;
        return Ok(());
    })?;

    Ok(result)
}

fn read_set_of<T: BERDecodable + ::core::fmt::Debug>(der: &[u8]) -> ASN1Result<Vec<T>> {
    let mut result = Vec::new();

    yasna::parse_der(der, |reader| {
        reader.read_set_of(|reader| {
            if let Ok(data) = reader.read_der() {
                let v: T = yasna::decode_der(&data)?;
                result.push(v);
                return Ok(());
            } else {
                return Err(ASN1Error::new(ASN1ErrorKind::Eof));
            }
        })?;
        return Ok(());
    })?;

    Ok(result)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Pkcs12Error {
    ASN1(ASN1Error),
    Crypto(MbedtlsError),
    Custom(String),
}

impl fmt::Display for Pkcs12Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Pkcs12Error::ASN1(ref e) => f.write_fmt(format_args!("Error parsing ASN.1: {}", e)),
            &Pkcs12Error::Crypto(ref e) => f.write_fmt(format_args!("Cryptographic error {}", e)),
            &Pkcs12Error::Custom(ref s) => f.write_fmt(format_args!("{}", s)),
        }
    }
}

#[cfg(feature = "std")]
impl StdError for Pkcs12Error {
    fn description(&self) -> &str {
        match self {
            &Pkcs12Error::ASN1(_) => "Error parsing ASN.1",
            &Pkcs12Error::Crypto(_) => "Cryptographic error",
            &Pkcs12Error::Custom(_) => "Format problem",
        }
    }
}

impl From<ASN1Error> for Pkcs12Error {
    fn from(error: ASN1Error) -> Pkcs12Error {
        Pkcs12Error::ASN1(error)
    }
}

impl From<MbedtlsError> for Pkcs12Error {
    fn from(error: MbedtlsError) -> Pkcs12Error {
        Pkcs12Error::Crypto(error)
    }
}

pub type Pkcs12Result<T> = StdResult<T, Pkcs12Error>;

fn map_oid_to_mbedtls_digest(oid: &ObjectIdentifier) -> Pkcs12Result<MdType> {
    match &**oid.components() {
        OID_SHA1 => Ok(MdType::Sha1),
        OID_SHA256 => Ok(MdType::Sha256),
        OID_SHA384 => Ok(MdType::Sha384),
        OID_SHA512 => Ok(MdType::Sha512),
        _ => Err(Pkcs12Error::Custom("Unknown MAC digest OID".to_owned())),
    }
}

// AlgorithmIdentifier of X.509 fame, see RFC 5280
#[derive(Debug, Clone)]
struct AlgorithmIdentifier {
    algo: ObjectIdentifier,
    params: Vec<u8>,
}

impl BERDecodable for AlgorithmIdentifier {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let algo = reader.next().read_oid()?;
            let params = reader.next().read_der().ok().unwrap_or(Vec::new());

            Ok(AlgorithmIdentifier { algo, params })
        })
    }
}

// Attribute of X.509 fame, see RFC 5280
#[derive(Debug, Clone)]
struct Attribute {
    id: ObjectIdentifier,
    values: Vec<Vec<u8>>, // SET of opaque blob
}

impl BERDecodable for Attribute {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let id = reader.next().read_oid()?;
            let values = reader.next().collect_set_of(|reader| reader.read_der())?;

            Ok(Attribute { id, values })
        })
    }
}

// DigestInfo from PKCS7, see RFC 2315 section 9.4
#[derive(Debug, Clone)]
struct DigestInfo {
    algo: AlgorithmIdentifier,
    digest: Vec<u8>,
}

impl BERDecodable for DigestInfo {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let algo = read_struct::<AlgorithmIdentifier>(reader)?;
            let digest = reader.next().read_bytes()?;

            Ok(DigestInfo { algo, digest })
        })
    }
}

// MacData is from RFC 7292 section 4
#[derive(Debug, Clone)]
struct MacData {
    digest: DigestInfo,
    salt: Vec<u8>,
    iterations: Option<u32>,
}

impl BERDecodable for MacData {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let digest = read_struct::<DigestInfo>(reader)?;
            let salt = reader.next().read_bytes()?;
            let iterations = reader.read_optional(|reader| reader.read_u32())?;

            Ok(MacData {
                digest,
                salt,
                iterations,
            })
        })
    }
}

// ContentInfo from PKCS7 see RFC 2315 section 7
#[derive(Debug, Clone)]
struct ContentInfo {
    oid: ObjectIdentifier,
    contents: Vec<AuthenticatedSafe>,
}

impl BERDecodable for ContentInfo {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let oid = reader.next().read_oid()?;
            let contents = reader
                .next()
                .read_tagged(Tag::context(0), |reader| reader.read_bytes())?;
            let contents = read_seq_of::<AuthenticatedSafe>(&contents)?;
            Ok(ContentInfo { oid, contents })
        })
    }
}

// AuthenticatedSafe from PKCS12 see RFC 7292 section 4.1
#[derive(Debug, Clone)]
enum AuthenticatedSafe {
    Data(SafeContents),
    EncryptedData(EncryptedData),
}

impl BERDecodable for AuthenticatedSafe {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        let r = reader.read_sequence(|reader| {
            let oid = reader.next().read_oid()?;
            let blob = reader
                .next()
                .read_tagged(Tag::context(0), |reader| reader.read_der())?;
            Ok((oid, blob))
        })?;

        if r.0 == ObjectIdentifier::from_slice(PKCS7_DATA) {
            // Wrapped in an OCTET STRING
            let blob = yasna::parse_der(&r.1, |reader| reader.read_bytes())?;
            let sc = read_struct_from_bytes::<SafeContents>(&blob)?;
            Ok(AuthenticatedSafe::Data(sc))
        } else if r.0 == ObjectIdentifier::from_slice(PKCS7_ENCRYPTED_DATA) {
            let ed = read_struct_from_bytes::<EncryptedData>(&r.1)?;
            Ok(AuthenticatedSafe::EncryptedData(ed))
        } else {
            Err(ASN1Error::new(ASN1ErrorKind::Invalid))
        }
    }
}

// EncryptedData from PKCS7 see RFC 2315 section 13
#[derive(Debug, Clone)]
struct EncryptedData {
    version: u32,
    content_info: EncryptedContentInfo,
}

impl BERDecodable for EncryptedData {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let version = reader.next().read_u32()?;
            let content_info = read_struct::<EncryptedContentInfo>(reader)?;
            Ok(EncryptedData {
                version,
                content_info,
            })
        })
    }
}

// EncryptedContentInfo from PKCS7 see RFC 2315 section 10.1
#[derive(Debug, Clone)]
struct EncryptedContentInfo {
    content_type: ObjectIdentifier,
    encryption_algo: AlgorithmIdentifier,
    encrypted_content: Vec<u8>,
}

impl BERDecodable for EncryptedContentInfo {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let content_type = reader.next().read_oid()?;
            let encryption_algo = read_struct::<AlgorithmIdentifier>(reader)?;
            let encrypted_content = reader
                .next()
                .read_tagged_implicit(Tag::context(0), |reader| reader.read_bytes())?;
            Ok(EncryptedContentInfo {
                content_type,
                encryption_algo,
                encrypted_content,
            })
        })
    }
}

// CertTypes from PKCS12, see RFC 7292 section 4.2.3
#[derive(Debug, Clone)]
struct CertTypes {
    cert_type: ObjectIdentifier,
    cert_blob: Vec<u8>,
}

impl BERDecodable for CertTypes {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let cert_type = reader.next().read_oid()?;
            let cert_blob = reader
                .next()
                .read_tagged(Tag::context(0), |reader| reader.read_bytes())?;
            Ok(CertTypes {
                cert_type,
                cert_blob,
            })
        })
    }
}

// CertBag from PKCS12, see RFC 7292 section 4.2.3
#[derive(Debug, Clone)]
struct CertBag(Option<Vec<u8>>);

impl BERDecodable for CertBag {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        let blob = reader.read_der()?;

        let pkcs12cert = read_struct_from_bytes::<CertTypes>(&blob)?;

        if pkcs12cert.cert_type == ObjectIdentifier::from_slice(PKCS9_X509_CERT) {
            return Ok(CertBag(Some(pkcs12cert.cert_blob.to_vec())));
        } else {
            return Ok(CertBag(None));
        }
    }
}

// KeyBag from PKCS12, see RFC 7292 section 4.2.1
#[derive(Debug, Clone)]
struct KeyBag {
    pkcs8: Vec<u8>,
}

impl BERDecodable for KeyBag {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        let key = reader.read_der()?;
        Ok(KeyBag { pkcs8: key })
    }
}

// SafeContents from PKCS12, see RFC 7292 section 4.2
#[derive(Debug, Clone)]
struct SafeContents(Vec<SafeBag>);

impl BERDecodable for SafeContents {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        Ok(SafeContents(read_seq_of::<SafeBag>(&reader.read_der()?)?))
    }
}

// Pkcs12BagSet from PKCS12, see RFC 7292 section 4.2
#[derive(Debug, Clone)]
enum Pkcs12BagSet {
    Key(KeyBag),
    EncryptedPkcs8(Vec<u8>),
    Pkcs8(Vec<u8>),
    Cert(CertBag),
    UnknownBlob(Vec<u8>),
    // XXX CRL and Secret bags not supported
    //Crl(CrlBag),
    //Secret(SecretBag),
    // XXX Recursively encoded SafeContents not supported
    //SafeContents(SafeContents),
}

#[derive(Debug, Clone)]
struct SafeBag {
    bag_id: ObjectIdentifier,
    bag_value: Pkcs12BagSet,
    bag_attributes: Vec<Attribute>,
}

// SafeBag does not mean "safe" in the Rust sense of safety but
// instead refers to as if you put a bag (with some stuff in it)
// into a physical safe.
// Yeah, it doesn't make much sense to me either.
impl SafeBag {
    fn friendly_name(&self) -> Vec<String> {
        let friendly_name = ObjectIdentifier::from_slice(PKCS9_FRIENDLY_NAME);

        self.bag_attributes
            .iter()
            .filter(|attr| attr.id == friendly_name)
            .flat_map(|attr| attr.values.iter())
            .filter_map(|val| read_string_type(val).ok())
            .collect()
    }
}

impl BERDecodable for SafeBag {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let bag_id = reader.next().read_oid()?;
            let bag_blob = reader
                .next()
                .read_tagged(Tag::context(0), |reader| reader.read_der())?;

            let mut bag_attributes = Vec::new();
            if let Ok(attr) = reader.next().read_der() {
                bag_attributes = read_set_of::<Attribute>(&attr)?;
            }

            let bag_value = match &**bag_id.components() {
                PKCS12_BAG_KEY => Pkcs12BagSet::Key(read_struct_from_bytes(&bag_blob)?),
                PKCS12_BAG_PKCS8_KEY => Pkcs12BagSet::EncryptedPkcs8(bag_blob),
                PKCS12_BAG_CERT => Pkcs12BagSet::Cert(read_struct_from_bytes(&bag_blob)?),
                _ => Pkcs12BagSet::UnknownBlob(bag_blob),
            };

            Ok(SafeBag {
                bag_id,
                bag_value,
                bag_attributes,
            })
        })
    }
}

/// Represents a PKCS12 (aka PFX) data structure, which can hold arbitrary
/// quantities of private keys, certificates, and other data.
///
/// See RFC 7292 for details on the format.
#[derive(Debug, Clone)]
pub struct Pfx {
    version: u32,
    authsafe: ContentInfo,
    macdata: Option<MacData>,
    raw_data: Vec<u8>,
}

// See RFC 7292 Appendix C
#[derive(Debug, Clone)]
struct Pkcs12PbeParams {
    salt: Vec<u8>,
    iterations: u32,
}

impl BERDecodable for Pkcs12PbeParams {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let salt = reader.next().read_bytes()?;
            let iterations = reader.next().read_u32()?;
            Ok(Pkcs12PbeParams { salt, iterations })
        })
    }
}

// PKCS12 formats PBKDF input as BMP (UCS-16) with trailing NULL
// See RFC 7292 Appendix B.1
fn format_passphrase_for_pkcs12(passphrase: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity((passphrase.len() + 1) * 2);

    for c in passphrase.encode_utf16().chain(core::iter::once(0)) {
        v.extend_from_slice(&c.to_be_bytes())
    }

    v
}

fn decrypt_contents(data: &EncryptedData, passphrase: &[u8]) -> Pkcs12Result<SafeContents> {
    if data.version != 0 {
        return Err(Pkcs12Error::Custom(format!(
            "Unknown EncryptedData version {}",
            data.version
        )));
    }

    let encryption_algo = &data.content_info.encryption_algo.algo;
    let pbe_params: Pkcs12PbeParams = yasna::decode_der(&data.content_info.encryption_algo.params)?;

    let pt = decrypt_data(
        &data.content_info.encrypted_content,
        &pbe_params,
        encryption_algo,
        passphrase,
    )?;

    let sc = read_struct_from_bytes::<SafeContents>(&pt)?;
    return Ok(sc);
}

fn decrypt_pkcs8(pkcs8: &[u8], passphrase: &[u8]) -> Pkcs12Result<Vec<u8>> {
    let p8 = yasna::parse_der(pkcs8, |reader| {
        reader.read_sequence(|reader| {
            let alg_id = read_struct_from_bytes::<AlgorithmIdentifier>(&reader.next().read_der()?)?;
            let pbe_params = read_struct_from_bytes::<Pkcs12PbeParams>(&alg_id.params)?;
            let enc_p8 = reader.next().read_bytes()?;

            decrypt_data(&enc_p8, &pbe_params, &alg_id.algo, passphrase)
                .map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))
        })
    })?;

    Ok(p8)
}

fn decrypt_3des(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Pkcs12Result<Vec<u8>> {
    let cipher = Cipher::<Decryption, Traditional, Fresh>::new(
        CipherId::Des3,
        CipherMode::CBC,
        (key.len() * 8) as u32,
    )?;
    let cipher = cipher.set_key_iv(&key, &iv)?;
    let mut plaintext = vec![0; ciphertext.len() + 8];
    let len = cipher.decrypt(&ciphertext, &mut plaintext)?;
    plaintext.truncate(len.0);
    return Ok(plaintext);
}

#[cfg(feature = "pkcs12_rc2")]
fn decrypt_rc2(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Pkcs12Result<Vec<u8>> {
    use block_modes::BlockMode;

    let cipher =
        block_modes::Cbc::<rc2::Rc2, block_modes::block_padding::Pkcs7>::new_var(&key, &iv)
            .map_err(|e| Pkcs12Error::Custom(format!("{:?}", e)))?;

    let mut pt = ciphertext.to_vec();
    let pt = cipher
        .decrypt(&mut pt)
        .map_err(|e| Pkcs12Error::Custom(format!("{:?}", e)))?;
    return Ok(pt.to_owned());
}

#[cfg(not(feature = "pkcs12_rc2"))]
fn decrypt_rc2(_ciphertext: &[u8], _key: &[u8], _iv: &[u8]) -> Pkcs12Result<Vec<u8>> {
    return Err(Pkcs12Error::Custom(
        "RC2 not supported in this build".to_owned(),
    ));
}

#[derive(Debug, Clone, Copy)]
#[allow(non_camel_case_types)]
enum Pkcs12EncryptionAlgo {
    TDES_168_SHA,
    TDES_112_SHA,
    RC2_128_SHA,
    RC2_40_SHA,
}

fn key_length(algo: Pkcs12EncryptionAlgo) -> usize {
    match algo {
        Pkcs12EncryptionAlgo::TDES_168_SHA => 192 / 8,
        Pkcs12EncryptionAlgo::TDES_112_SHA => 128 / 8,
        Pkcs12EncryptionAlgo::RC2_128_SHA => 128 / 8,
        Pkcs12EncryptionAlgo::RC2_40_SHA => 40 / 8,
    }
}

fn decrypt_data(
    ciphertext: &[u8],
    pbe_params: &Pkcs12PbeParams,
    encryption_algo: &ObjectIdentifier,
    passphrase: &[u8],
) -> Pkcs12Result<Vec<u8>> {
    fn parse_encryption_algo(oid: &ObjectIdentifier) -> Pkcs12Result<Pkcs12EncryptionAlgo> {
        match &**oid.components() {
            PKCS12_PBE_SHA_3DES_168 => Ok(Pkcs12EncryptionAlgo::TDES_168_SHA),
            PKCS12_PBE_SHA_3DES_112 => Ok(Pkcs12EncryptionAlgo::TDES_112_SHA),
            PKCS12_PBE_SHA_RC2_128 => Ok(Pkcs12EncryptionAlgo::RC2_128_SHA),
            PKCS12_PBE_SHA_RC2_40 => Ok(Pkcs12EncryptionAlgo::RC2_40_SHA),
            _ => Err(Pkcs12Error::Custom(format!(
                "Unknown encryption algo {}",
                oid
            ))),
        }
    }

    let cipher_algo = parse_encryption_algo(encryption_algo)?;

    let mut cipher_key = vec![0; key_length(cipher_algo)];
    let mut cipher_iv = vec![0; 8]; // Either 3DES or RC2

    // All defined PKCS12 encryption methods use SHA-1 for the PBKDF
    pbkdf_pkcs12(
        MdType::Sha1,
        passphrase,
        &pbe_params.salt,
        1,
        pbe_params.iterations,
        &mut cipher_key,
    )?;
    pbkdf_pkcs12(
        MdType::Sha1,
        passphrase,
        &pbe_params.salt,
        2,
        pbe_params.iterations,
        &mut cipher_iv,
    )?;

    return match cipher_algo {
        Pkcs12EncryptionAlgo::TDES_168_SHA | Pkcs12EncryptionAlgo::TDES_112_SHA => {
            decrypt_3des(ciphertext, &cipher_key, &cipher_iv)
        }

        Pkcs12EncryptionAlgo::RC2_128_SHA | Pkcs12EncryptionAlgo::RC2_40_SHA => {
            decrypt_rc2(ciphertext, &cipher_key, &cipher_iv)
        }
    };
}

impl Pfx {
    /// Create a Pfx data structure by parsing the binary data
    ///
    /// Once created, the stored certificates and keys can be accessed Pfx
    /// allows encrypting the keys and/or certificates with a password.
    /// Initially (after parsing) the data remains encrypted, but unencrypted
    /// keys can be accessed immediately by calling private_keys and
    /// certificates functions.
    ///
    /// After a successful call to decrypt, any encrypted keys and certificates
    /// can also be accessed. In addition, PKCS12 includes an (optional)
    /// authentication code, which is checked during decryption.
    pub fn parse(data: &[u8]) -> Pkcs12Result<Pfx> {
        let pfx: Pfx = yasna::decode_der(data)?;

        if pfx.version != 3 {
            return Err(Pkcs12Error::Custom(format!(
                "Unknown PKCS12 version {}",
                pfx.version
            )));
        }

        Ok(pfx)
    }

    fn authenticate(&self, passphrase: &[u8]) -> Pkcs12Result<()> {
        if let Some(mac) = &self.macdata {
            let md = map_oid_to_mbedtls_digest(&mac.digest.algo.algo)?;
            let stored_mac = &mac.digest.digest;
            let salt = &mac.salt;
            let iterations = mac.iterations.clone().unwrap_or(1);

            let md_info: MdInfo = match md.into() {
                Some(md) => md,
                None => return Err(Pkcs12Error::from(MbedtlsError::MdBadInputData)),
            };

            if stored_mac.len() != md_info.size() {
                return Err(Pkcs12Error::Custom(
                    "The MAC was truncated which is not allowed by PKCS12".to_owned(),
                ));
            }

            // See section B.4 of RFC 7292 for details
            let mut hmac_key = vec![0u8; md_info.size()];

            pbkdf_pkcs12(md, passphrase, salt, 3, iterations, &mut hmac_key)?;

            let mut computed_hmac = vec![0u8; md_info.size()];

            let hmac_len = Md::hmac(md, &hmac_key, &self.raw_data, &mut computed_hmac)?;

            // FIXME const time compare
            if computed_hmac[0..hmac_len] != stored_mac[..] {
                return Err(Pkcs12Error::Custom("Invalid MAC".to_owned()));
            }
        }

        return Ok(());
    }

    /// Decrypt an encrypted Pfx If mac_passphrase is None, it is assumed to be
    /// identical to the encryption passphrase Dual password PKCS12 files (using
    /// distinct passwords for encryption and authentication) can be created
    /// using openssl with the -twopass option.
    pub fn decrypt(&self, passphrase: &str, mac_passphrase: Option<&str>) -> Pkcs12Result<Pfx> {
        // Test if this object is already decrypted
        if self.raw_data.len() == 0 {
            return Ok(self.clone());
        }

        let passphrase = format_passphrase_for_pkcs12(passphrase);

        if let Some(mac_pass) = mac_passphrase {
            let mac_passphrase = format_passphrase_for_pkcs12(mac_pass);
            self.authenticate(&mac_passphrase)?;
        } else {
            self.authenticate(&passphrase)?;
        }

        fn decrypt_pkcs8_sb(sb: &SafeBag, passphrase: &[u8]) -> Pkcs12Result<SafeBag> {
            if let &Pkcs12BagSet::EncryptedPkcs8(ref p8) = &sb.bag_value {
                let decrypted_p8 = decrypt_pkcs8(&p8, passphrase)?;
                return Ok(SafeBag {
                    bag_id: ObjectIdentifier::from_slice(PKCS12_BAG_KEY),
                    bag_value: Pkcs12BagSet::Pkcs8(decrypted_p8),
                    bag_attributes: sb.bag_attributes.clone(),
                });
            } else {
                return Ok(sb.clone());
            }
        }

        fn decrypt_data(
            data: &AuthenticatedSafe,
            passphrase: &[u8],
        ) -> Pkcs12Result<AuthenticatedSafe> {
            match data {
                &AuthenticatedSafe::Data(ref sc) => {
                    let mut contents = Vec::new();

                    for item in &sc.0 {
                        contents.push(decrypt_pkcs8_sb(&item, passphrase)?);
                    }

                    Ok(AuthenticatedSafe::Data(SafeContents(contents)))
                }
                &AuthenticatedSafe::EncryptedData(ref ed) => {
                    let decrypted = decrypt_contents(&ed, &passphrase)?;
                    Ok(AuthenticatedSafe::Data(decrypted))
                }
            }
        }

        let mut new_authsafe = Vec::new();

        for c in &self.authsafe.contents {
            let d = decrypt_data(&c, &passphrase)?;
            new_authsafe.push(d);
        }

        let decrypted = Pfx {
            version: self.version,
            authsafe: ContentInfo {
                oid: self.authsafe.oid.clone(),
                contents: new_authsafe,
            },
            raw_data: Vec::new(),
            macdata: None,
        };
        Ok(decrypted)
    }

    fn authsafe_decrypted_contents(&self) -> impl Iterator<Item=&SafeBag> {
        self.authsafe.contents.iter()
            .flat_map(|d| if let AuthenticatedSafe::Data(ref d) = d { d.0.as_slice() } else { &[] })
    }

    /// Return the certificates stored in this Pfx along with a possibly empty list
    /// of "friendly names" which are associated with said certificate.
    /// Some or all of the certificates stored in a Pfx may be encrypted in which case
    /// decrypt must be called to access them.
    pub fn certificates<'a>(&'a self) -> impl Iterator<Item=(Result<Certificate, crate::Error>, Vec<String>)> + 'a {
        self.authsafe_decrypted_contents()
            .filter_map(|sb| if let Pkcs12BagSet::Cert(CertBag(Some(cert))) = &sb.bag_value {
                Some((Certificate::from_der(cert), sb.friendly_name()))
            } else { None })
    }

    /// Return the private keys stored in this Pfx along with a possibly empty list
    /// of "friendly names" which are associated with said private key.
    pub fn private_keys<'a>(&'a self) -> impl Iterator<Item=(Result<Pk, crate::Error>, Vec<String>)> + 'a {
        self.authsafe_decrypted_contents()
            .filter_map(|sb|
                match &sb.bag_value {
                    Pkcs12BagSet::Pkcs8(pkcs8) | Pkcs12BagSet::Key(KeyBag { pkcs8 }) =>
                        Some((Pk::from_private_key(pkcs8, None), sb.friendly_name())),
                    _ => /* not a private key */ None
                }
            )
    }
}

impl BERDecodable for Pfx {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let version = reader.next().read_u32()?;
            let raw_safe = reader.next().read_der()?;
            let safe = read_struct_from_bytes::<ContentInfo>(&raw_safe)?;
            let mac = read_struct::<MacData>(reader);

            // mac is optional
            if let Err(e) = mac {
                if e.kind() != ASN1ErrorKind::Eof {
                    return Err(e);
                }
            }

            // need to dig down a few layers to get the bytes that are MACed
            let raw_data = yasna::parse_der(&raw_safe, |reader| {
                reader.read_sequence(|reader| {
                    let _oid = reader.next().read_oid()?;
                    let contents = reader
                        .next()
                        .read_tagged(Tag::context(0), |reader| reader.read_bytes())?;
                    Ok(contents)
                })
            })?;

            Ok(Pfx {
                raw_data: raw_data,
                version: version,
                authsafe: safe,
                macdata: mac.ok(),
            })
        })
    }
}

#[cfg(test)]
mod tests {

    use crate::mbedtls::pkcs12::{ASN1Error, ASN1ErrorKind, Pfx, Pkcs12Error};

    #[test]
    fn parse_shibboleth() {
        // Test from OpenSSL
        let pfx_bits = include_bytes!("../../tests/data/shibboleth.pfx");
        let password = "σύνθημα γνώρισμα";

        let parsed_pfx = Pfx::parse(pfx_bits).unwrap();

        // Certs are not encrypted in this Pfx
        let certs = parsed_pfx.certificates().collect::<Vec<_>>();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].1.len(), 0); // no friendly name set

        let keys = parsed_pfx.private_keys().collect::<Vec<_>>();
        assert_eq!(keys.len(), 0);

        let pfx = parsed_pfx.decrypt(&password, None).unwrap();

        let certs = pfx.certificates().collect::<Vec<_>>();
        assert_eq!(certs.len(), 1);
        for cert in certs {
            assert!(cert.0.is_ok());
        }

        let keys = pfx.private_keys().collect::<Vec<_>>();
        assert_eq!(keys.len(), 1);

        assert_eq!(keys[0].1.len(), 1); // has friendly name
        assert_eq!(keys[0].1[0], "3f71af65-1687-444a-9f46-c8be194c3e8e"); // which is this uuid

        let pk = keys[0].0.as_ref().unwrap();
        assert_eq!(pk.name().unwrap(), "RSA");
        assert_eq!(pk.len(), 2048);
    }

    #[test]
    #[cfg(feature = "pkcs12_rc2")]
    fn parse_identity_p12() {
        // Used in rust-native-tls examples

        let pfx_bits = include_bytes!("../../tests/data/identity.p12");
        let password = "mypass";
        let not_the_password = "bunny hops";

        let parsed_pfx = Pfx::parse(pfx_bits).unwrap();

        let certs = parsed_pfx.certificates().collect::<Vec<_>>();
        assert_eq!(certs.len(), 0);

        let keys = parsed_pfx.private_keys().collect::<Vec<_>>();
        assert_eq!(keys.len(), 0);

        assert!(parsed_pfx.decrypt(&not_the_password, None).is_err());

        let pfx = parsed_pfx.decrypt(&password, None).unwrap();

        let certs = pfx.certificates().collect::<Vec<_>>();
        assert_eq!(certs.len(), 2);
        for cert in certs {
            assert!(cert.0.is_ok());
        }

        let keys = pfx.private_keys().collect::<Vec<_>>();
        assert_eq!(keys.len(), 1);

        assert_eq!(keys[0].1.len(), 1); // has friendly name
        assert_eq!(keys[0].1[0], "foobar.com");
        let pk = keys[0].0.as_ref().unwrap();
        assert_eq!(pk.name().unwrap(), "RSA");
        assert_eq!(pk.len(), 2048);
    }

    #[test]
    fn parse_pkijs_p12() {
        // This one is not encrypted at all

        let pfx_bits = include_bytes!("../../tests/data/pkijs_pkcs12.p12");

        let parsed_pfx = Pfx::parse(pfx_bits).unwrap();

        let certs = parsed_pfx.certificates().collect::<Vec<_>>();
        assert_eq!(certs.len(), 1);
        for cert in certs {
            assert!(cert.0.is_ok());
        }

        let keys = parsed_pfx.private_keys().collect::<Vec<_>>();
        assert_eq!(keys.len(), 1);

        assert_eq!(keys[0].1.len(), 0); // no name
        let pk = keys[0].0.as_ref().unwrap();
        assert_eq!(pk.name().unwrap(), "RSA");
        assert_eq!(pk.len(), 2048);
    }

    #[test]
    #[cfg(feature = "pkcs12_rc2")]
    fn parse_windows_p12() {
        // Generated by Windows CryptoAPI with empty password
        let pfx_bits = include_bytes!("../../tests/data/MetroTestCertificate.pfx");
        let password = "";

        let parsed_pfx = Pfx::parse(pfx_bits).unwrap();

        let pfx = parsed_pfx.decrypt(&password, None).unwrap();

        let certs = pfx.certificates().collect::<Vec<_>>();
        assert_eq!(certs.len(), 1);
        for cert in certs {
            assert!(cert.0.is_ok());
        }

        let keys = pfx.private_keys().collect::<Vec<_>>();
        assert_eq!(keys.len(), 1);

        assert_eq!(keys[0].1.len(), 1); // no name
        assert_eq!(keys[0].1[0], "Unity");
        let pk = keys[0].0.as_ref().unwrap();
        assert_eq!(pk.name().unwrap(), "RSA");
        assert_eq!(pk.len(), 2048);
    }

    #[test]
    #[cfg(feature = "pkcs12_rc2")]
    fn parse_openssl_nomac() {
        let pfx_bits = include_bytes!("../../tests/data/nomac.pfx");
        let password = "xyzzy";

        let parsed_pfx = Pfx::parse(pfx_bits).unwrap();

        let pfx = parsed_pfx.decrypt(&password, None).unwrap();

        let certs = pfx.certificates().collect::<Vec<_>>();
        assert_eq!(certs.len(), 1);
        for cert in certs {
            assert!(cert.0.is_ok());
        }

        let keys = pfx.private_keys().collect::<Vec<_>>();
        assert_eq!(keys.len(), 1);

        assert_eq!(keys[0].1.len(), 1);
        assert_eq!(keys[0].1[0], "Bongo");
        let pk = keys[0].0.as_ref().unwrap();
        assert_eq!(pk.name().unwrap(), "RSA");
        assert_eq!(pk.len(), 1536);
    }

    #[test]
    fn test_bad_password() {
        let pfx_bits = include_bytes!("../../tests/data/nomac_pass.pfx");
        let correct_password = "xyzzy";
        let wrong_password = "unicorn";
        // This password happens to produce a correct CBC padding so causes a different error
        let wrong_password_correct_padding = "zork#364";

        let parsed_pfx = Pfx::parse(pfx_bits).unwrap();

        let pfx = parsed_pfx.decrypt(&wrong_password, None);
        assert!(pfx.is_err());
        assert_eq!(
            pfx.unwrap_err(),
            Pkcs12Error::Crypto(crate::Error::CipherInvalidPadding)
        );

        let pfx = parsed_pfx.decrypt(&wrong_password_correct_padding, None);
        assert!(pfx.is_err());
        assert_eq!(
            pfx.unwrap_err(),
            Pkcs12Error::ASN1(ASN1Error::new(ASN1ErrorKind::Eof))
        );

        let pfx = parsed_pfx.decrypt(&correct_password, None).unwrap();

        let certs = pfx.certificates().collect::<Vec<_>>();
        assert_eq!(certs.len(), 1);
        for cert in certs {
            assert!(cert.0.is_ok());
        }

        let keys = pfx.private_keys().collect::<Vec<_>>();
        assert_eq!(keys.len(), 1);

        assert_eq!(keys[0].1.len(), 1);
        assert_eq!(keys[0].1[0], "Bogus");
        let pk = keys[0].0.as_ref().unwrap();
        assert_eq!(pk.name().unwrap(), "RSA");
        assert_eq!(pk.len(), 1536);
    }

    #[test]
    #[cfg(feature = "pkcs12_rc2")]
    fn parse_openssl_nomaciter() {
        let pfx_bits = include_bytes!("../../tests/data/nomaciter.pfx");
        let password = "xyzzy";

        let parsed_pfx = Pfx::parse(pfx_bits).unwrap();

        let pfx = parsed_pfx.decrypt(&password, None).unwrap();

        let certs = pfx.certificates().collect::<Vec<_>>();
        assert_eq!(certs.len(), 1);
        for cert in certs {
            assert!(cert.0.is_ok());
        }

        let keys = pfx.private_keys().collect::<Vec<_>>();
        assert_eq!(keys.len(), 1);

        assert_eq!(keys[0].1.len(), 1);
        assert_eq!(keys[0].1[0], "Bongo");
        let pk = keys[0].0.as_ref().unwrap();
        assert_eq!(pk.name().unwrap(), "RSA");
        assert_eq!(pk.len(), 1536);
    }

    #[test]
    fn parse_openssl_sha2() {
        let pfx_bits = include_bytes!("../../tests/data/sha2.pfx");
        let password = "xyzzy";

        let parsed_pfx = Pfx::parse(pfx_bits).unwrap();

        let pfx = parsed_pfx.decrypt(&password, None).unwrap();

        let certs = pfx.certificates().collect::<Vec<_>>();
        assert_eq!(certs.len(), 1);
        for cert in certs {
            assert!(cert.0.is_ok());
        }

        let keys = pfx.private_keys().collect::<Vec<_>>();
        assert_eq!(keys.len(), 1);

        assert_eq!(keys[0].1.len(), 1);
        assert_eq!(keys[0].1[0], "Bongo");
        let pk = keys[0].0.as_ref().unwrap();
        assert_eq!(pk.name().unwrap(), "RSA");
        assert_eq!(pk.len(), 1536);
    }

    #[test]
    fn parse_openssl_3certs() {
        let pfx_bits = include_bytes!("../../tests/data/3certs.pfx");
        let password = "xyzzy";

        let parsed_pfx = Pfx::parse(pfx_bits).unwrap();

        let pfx = parsed_pfx.decrypt(&password, None).unwrap();

        let certs = pfx.certificates().collect::<Vec<_>>();
        assert_eq!(certs.len(), 3);
        for cert in certs {
            assert!(cert.0.is_ok());
        }

        let keys = pfx.private_keys().collect::<Vec<_>>();
        assert_eq!(keys.len(), 1);

        let pk = keys[0].0.as_ref().unwrap();
        assert_eq!(pk.name().unwrap(), "RSA");
        assert_eq!(pk.len(), 1536);
    }

    #[test]
    fn parse_openssl_twopass() {
        let pfx_bits = include_bytes!("../../tests/data/twopass.pfx");
        let enc_password = "enc";
        let mac_password = "mac";

        let parsed_pfx = Pfx::parse(pfx_bits).unwrap();

        // Test that decrypting an already decrypted Pfx works:
        let pfx = parsed_pfx
            .decrypt(&enc_password, Some(&mac_password))
            .unwrap();
        let pfx = pfx.decrypt(&enc_password, Some(&mac_password)).unwrap();

        let certs = pfx.certificates().collect::<Vec<_>>();
        assert_eq!(certs.len(), 1);
        for cert in certs {
            assert!(cert.0.is_ok());
        }

        let keys = pfx.private_keys().collect::<Vec<_>>();
        assert_eq!(keys.len(), 1);

        assert_eq!(keys[0].1.len(), 1);
        assert_eq!(keys[0].1[0], "Deus");

        let pk = keys[0].0.as_ref().unwrap();
        assert_eq!(pk.name().unwrap(), "RSA");
        assert_eq!(pk.len(), 1536);
    }

    #[test]
    fn parse_windows_p12_2() {
        // Generated by Windows CryptoAPI
        let pfx_bits = include_bytes!("../../tests/data/Windows_TemporaryKey.pfx");
        let password = "";

        let pfx = Pfx::parse(pfx_bits).unwrap();

        // Cert is not encrypted
        let certs = pfx.certificates().collect::<Vec<_>>();
        assert_eq!(certs.len(), 1);
        for cert in certs {
            assert!(cert.0.is_ok());
        }

        let keys = pfx.private_keys().collect::<Vec<_>>();
        assert_eq!(keys.len(), 0);

        let pfx = pfx.decrypt(&password, None).unwrap();

        let keys = pfx.private_keys().collect::<Vec<_>>();
        assert_eq!(keys.len(), 1);

        assert_eq!(keys[0].1.len(), 1); // no name
        assert_eq!(keys[0].1[0], "PvkTmp:7708e756-dd3f-4399-bb07-f0b5b4f41c1b");
        let pk = keys[0].0.as_ref().unwrap();
        assert_eq!(pk.name().unwrap(), "RSA");
        assert_eq!(pk.len(), 2048);
    }

}
