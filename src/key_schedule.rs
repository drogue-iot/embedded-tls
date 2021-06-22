use crate::handshake::finished::Finished;
use core::marker::PhantomData;
use digest::generic_array::ArrayLength;
use digest::{BlockInput, FixedOutput, Reset, Update};
use heapless::{consts::*, Vec};
use hkdf::Hkdf;
use hmac::crypto_mac::NewMac;
use hmac::{Hmac, Mac};
use sha2::digest::generic_array::{typenum::Unsigned, GenericArray};
use sha2::Digest;

pub struct KeySchedule<D, KeyLen, IvLen>
where
    D: Update + BlockInput + FixedOutput + Reset + Default + Clone,
    D::BlockSize: ArrayLength<u8>,
    D::OutputSize: ArrayLength<u8>,
    //D: Digest,
    KeyLen: ArrayLength<u8>,
    IvLen: ArrayLength<u8>,
{
    secret: GenericArray<u8, D::OutputSize>,
    transcript_hash: Option<D>,
    hkdf: Option<Hkdf<D>>,
    client_traffic_secret: Option<Hkdf<D>>,
    server_traffic_secret: Option<Hkdf<D>>,
    read_counter: u64,
    write_counter: u64,
    _key_len: PhantomData<KeyLen>,
    _iv_len: PhantomData<IvLen>,
}

enum ContextType {
    None,
    TranscriptHash,
    EmptyHash,
}

impl<D, KeyLen, IvLen> KeySchedule<D, KeyLen, IvLen>
where
    D: Update + BlockInput + FixedOutput + Reset + Default + Clone,
    D::BlockSize: ArrayLength<u8>,
    D::OutputSize: ArrayLength<u8>,
    KeyLen: ArrayLength<u8>,
    IvLen: ArrayLength<u8>,
{
    pub fn new() -> Self {
        Self {
            secret: Self::zero(),
            transcript_hash: Some(D::new()),
            hkdf: None,
            client_traffic_secret: None,
            server_traffic_secret: None,
            read_counter: 0,
            write_counter: 0,
            _key_len: PhantomData,
            _iv_len: PhantomData,
        }
    }

    pub(crate) fn transcript_hash(&mut self) -> &mut D {
        self.transcript_hash.as_mut().unwrap()
    }

    pub(crate) fn replace_transcript_hash(&mut self, digest: D) {
        self.transcript_hash.replace(digest);
    }

    pub(crate) fn increment_read_counter(&mut self) {
        self.read_counter += 1;
    }

    pub(crate) fn increment_write_counter(&mut self) {
        self.write_counter += 1;
    }

    pub(crate) fn reset_write_counter(&mut self) {
        self.write_counter = 0;
    }

    pub(crate) fn get_server_nonce(&self) -> GenericArray<u8, IvLen> {
        self.get_nonce(self.read_counter, &self.get_server_iv())
    }

    pub(crate) fn get_client_nonce(&self) -> GenericArray<u8, IvLen> {
        self.get_nonce(self.write_counter, &self.get_client_iv())
    }

    pub(crate) fn get_server_key(&self) -> GenericArray<u8, KeyLen> {
        self.hkdf_expand_label(
            &self.server_traffic_secret.as_ref().unwrap(),
            &self.make_hkdf_label(b"key", ContextType::None, KeyLen::to_u16()),
        )
    }

    pub(crate) fn get_client_key(&self) -> GenericArray<u8, KeyLen> {
        self.hkdf_expand_label(
            &self.client_traffic_secret.as_ref().unwrap(),
            &self.make_hkdf_label(b"key", ContextType::None, KeyLen::to_u16()),
        )
    }

    fn get_server_iv(&self) -> GenericArray<u8, IvLen> {
        self.hkdf_expand_label(
            &self.server_traffic_secret.as_ref().unwrap(),
            &self.make_hkdf_label(b"iv", ContextType::None, IvLen::to_u16()),
        )
    }

    fn get_client_iv(&self) -> GenericArray<u8, IvLen> {
        self.hkdf_expand_label(
            &self.client_traffic_secret.as_ref().unwrap(),
            &self.make_hkdf_label(b"iv", ContextType::None, IvLen::to_u16()),
        )
    }

    pub fn create_client_finished(&self) -> Result<Finished<D::OutputSize>, ()> {
        let key: GenericArray<u8, D::OutputSize> = self.hkdf_expand_label(
            self.client_traffic_secret.as_ref().unwrap(),
            &self.make_hkdf_label(b"finished", ContextType::None, D::OutputSize::to_u16()),
        );

        let mut hmac = Hmac::<D>::new_varkey(&key).map_err(|_| ())?;
        hmac.update(&self.transcript_hash.as_ref().unwrap().clone().finalize());
        let verify = hmac.finalize().into_bytes();

        Ok(Finished { verify, hash: None })
    }

    pub fn verify_server_finished(&self, finished: &Finished<D::OutputSize>) -> bool {
        //info!("verify server finished: {:x?}", finished.verify);
        //self.client_traffic_secret.as_ref().unwrap().expand()
        //info!("size ===> {}", D::OutputSize::to_u16());
        let key: GenericArray<u8, D::OutputSize> = self.hkdf_expand_label(
            self.server_traffic_secret.as_ref().unwrap(),
            &self.make_hkdf_label(b"finished", ContextType::None, D::OutputSize::to_u16()),
        );
        info!("hmac sign key {:x?}", key);
        let mut hmac = Hmac::<D>::new_varkey(&key).unwrap();
        info!("CHECK HASH {:x?}", &finished.hash.as_ref().unwrap());
        hmac.update(finished.hash.as_ref().unwrap());
        //let code = hmac.clone().finalize().into_bytes();
        hmac.verify(&finished.verify).is_ok()
        //info!("verified {:?}", verified);
        //unimplemented!()
    }

    fn get_nonce(&self, counter: u64, iv: &GenericArray<u8, IvLen>) -> GenericArray<u8, IvLen> {
        //info!("counter = {} {:x?}", counter, &counter.to_be_bytes(),);
        let counter = Self::pad::<IvLen>(&counter.to_be_bytes());

        //info!("counter = {:x?}", counter);
        info!("iv = {:x?}", iv);

        let mut nonce = GenericArray::default();

        for (index, (l, r)) in iv[0..IvLen::to_usize()]
            .iter()
            .zip(counter.iter())
            .enumerate()
        {
            nonce[index] = l ^ r
        }

        //debug!("nonce {:x?}", nonce);

        nonce
    }

    fn pad<N: ArrayLength<u8>>(input: &[u8]) -> GenericArray<u8, N> {
        info!("padding input = {:x?}", input);
        let mut padded = GenericArray::default();
        for (index, byte) in input.iter().rev().enumerate() {
            info!(
                "{} pad {}={:x?}",
                index,
                ((N::to_usize() - index) - 1),
                *byte
            );
            padded[(N::to_usize() - index) - 1] = *byte;
        }
        padded
    }

    fn zero() -> GenericArray<u8, D::OutputSize> {
        GenericArray::default()
    }

    fn derived(&mut self) {
        self.secret = self.derive_secret(b"derived", ContextType::EmptyHash);
    }

    pub fn initialize_early_secret(&mut self) {
        let (secret, hkdf) =
            Hkdf::<D>::extract(Some(self.secret.as_ref()), Self::zero().as_slice());
        self.hkdf.replace(hkdf);
        self.secret = secret;
        // no right-hand jaunts (yet)
        self.derived();
    }

    pub fn initialize_handshake_secret(&mut self, ikm: &[u8]) {
        let (secret, hkdf) = Hkdf::<D>::extract(Some(self.secret.as_ref()), ikm);
        self.secret = secret;
        self.hkdf.replace(hkdf);
        self.calculate_traffic_secrets();
        self.derived();
    }

    pub fn initialize_master_secret(&mut self) {
        let (secret, hkdf) =
            Hkdf::<D>::extract(Some(self.secret.as_ref()), Self::zero().as_slice());
        self.secret = secret;
        self.hkdf.replace(hkdf);

        let context = self.transcript_hash.as_ref().unwrap().clone().finalize();
        info!("Derive keys, hash: {:x?}", context);

        let client_secret = self.derive_secret(b"c ap traffic", ContextType::TranscriptHash);
        self.client_traffic_secret
            .replace(Hkdf::from_prk(&client_secret).unwrap());
        info!("c traffic secret {:x?}", client_secret);
        let server_secret = self.derive_secret(b"s ap traffic", ContextType::TranscriptHash);
        self.server_traffic_secret
            .replace(Hkdf::from_prk(&server_secret).unwrap());
        info!("s traffic secret {:x?}", server_secret);
        self.read_counter = 0;
        self.write_counter = 0;

        self.derived();
    }

    fn calculate_traffic_secrets(&mut self) {
        let client_secret = self.derive_secret(b"c hs traffic", ContextType::TranscriptHash);
        self.client_traffic_secret
            .replace(Hkdf::from_prk(&client_secret).unwrap());
        info!("c traffic secret {:x?}", client_secret);
        let server_secret = self.derive_secret(b"s hs traffic", ContextType::TranscriptHash);
        self.server_traffic_secret
            .replace(Hkdf::from_prk(&server_secret).unwrap());
        info!("s traffic secret {:x?}", server_secret);
        self.read_counter = 0;
        self.write_counter = 0;
    }

    fn derive_secret(
        &mut self,
        label: &[u8],
        context_type: ContextType,
    ) -> GenericArray<u8, D::OutputSize> {
        let label = self.make_hkdf_label(label, context_type, D::OutputSize::to_u16());
        self.hkdf_expand_label(self.hkdf.as_ref().unwrap(), &label)
    }

    pub fn hkdf_expand_label<N: ArrayLength<u8>>(
        &self,
        hkdf: &Hkdf<D>,
        label: &[u8],
    ) -> GenericArray<u8, N> {
        let mut okm: GenericArray<u8, N> = Default::default();
        //info!("label {:x?}", label);
        hkdf.expand(label, &mut okm);
        //info!("expand {:x?}", okm);
        okm
    }

    fn make_hkdf_label(&self, label: &[u8], context_type: ContextType, len: u16) -> Vec<u8, U512> {
        //info!("make label {:?} {}", label, len);
        let mut hkdf_label = Vec::new();
        hkdf_label.extend_from_slice(&len.to_be_bytes());

        let label_len = 6 + label.len() as u8;
        hkdf_label.extend_from_slice(&(label_len as u8).to_be_bytes());
        hkdf_label.extend_from_slice(b"tls13 ");
        hkdf_label.extend_from_slice(label);

        match context_type {
            ContextType::None => {
                hkdf_label.push(0);
            }
            ContextType::TranscriptHash => {
                let context = self.transcript_hash.as_ref().unwrap().clone().finalize();
                hkdf_label.extend_from_slice(&(context.len() as u8).to_be_bytes());
                hkdf_label.extend_from_slice(&context);
            }
            ContextType::EmptyHash => {
                let context = D::new().chain(&[]).finalize();
                hkdf_label.extend_from_slice(&(context.len() as u8).to_be_bytes());
                hkdf_label.extend_from_slice(&context);
            }
        }
        hkdf_label
    }
}
