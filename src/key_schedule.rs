use crate::handshake::finished::Finished;
use crate::TlsError;
use core::marker::PhantomData;
use digest::generic_array::ArrayLength;
use digest::{BlockInput, FixedOutput, Reset, Update};
use heapless::Vec;
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

    pub(crate) fn replace_transcript_hash(&mut self, hash: D) {
        self.transcript_hash.replace(hash);
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

    pub(crate) fn get_server_nonce(&self) -> Result<GenericArray<u8, IvLen>, TlsError> {
        Ok(self.get_nonce(self.read_counter, &self.get_server_iv()?))
    }

    pub(crate) fn get_client_nonce(&self) -> Result<GenericArray<u8, IvLen>, TlsError> {
        Ok(self.get_nonce(self.write_counter, &self.get_client_iv()?))
    }

    pub(crate) fn get_server_key(&self) -> Result<GenericArray<u8, KeyLen>, TlsError> {
        self.hkdf_expand_label(
            &self.server_traffic_secret.as_ref().unwrap(),
            &self.make_hkdf_label(b"key", ContextType::None, KeyLen::to_u16())?,
        )
    }

    pub(crate) fn get_client_key(&self) -> Result<GenericArray<u8, KeyLen>, TlsError> {
        self.hkdf_expand_label(
            &self.client_traffic_secret.as_ref().unwrap(),
            &self.make_hkdf_label(b"key", ContextType::None, KeyLen::to_u16())?,
        )
    }

    fn get_server_iv(&self) -> Result<GenericArray<u8, IvLen>, TlsError> {
        self.hkdf_expand_label(
            &self.server_traffic_secret.as_ref().unwrap(),
            &self.make_hkdf_label(b"iv", ContextType::None, IvLen::to_u16())?,
        )
    }

    fn get_client_iv(&self) -> Result<GenericArray<u8, IvLen>, TlsError> {
        self.hkdf_expand_label(
            &self.client_traffic_secret.as_ref().unwrap(),
            &self.make_hkdf_label(b"iv", ContextType::None, IvLen::to_u16())?,
        )
    }

    pub fn create_client_finished(&self) -> Result<Finished<D::OutputSize>, TlsError> {
        let key: GenericArray<u8, D::OutputSize> = self.hkdf_expand_label(
            self.client_traffic_secret.as_ref().unwrap(),
            &self.make_hkdf_label(b"finished", ContextType::None, D::OutputSize::to_u16())?,
        )?;

        let mut hmac = Hmac::<D>::new_varkey(&key).map_err(|_| TlsError::CryptoError)?;
        hmac.update(&self.transcript_hash.as_ref().unwrap().clone().finalize());
        let verify = hmac.finalize().into_bytes();

        Ok(Finished { verify, hash: None })
    }

    pub fn verify_server_finished(
        &self,
        finished: &Finished<D::OutputSize>,
    ) -> Result<bool, TlsError> {
        //info!("verify server finished: {:x?}", finished.verify);
        //self.client_traffic_secret.as_ref().unwrap().expand()
        //info!("size ===> {}", D::OutputSize::to_u16());
        let key: GenericArray<u8, D::OutputSize> = self.hkdf_expand_label(
            self.server_traffic_secret.as_ref().unwrap(),
            &self.make_hkdf_label(b"finished", ContextType::None, D::OutputSize::to_u16())?,
        )?;
        // info!("hmac sign key {:x?}", key);
        let mut hmac = Hmac::<D>::new_varkey(&key).unwrap();
        hmac.update(finished.hash.as_ref().unwrap());
        //let code = hmac.clone().finalize().into_bytes();
        Ok(hmac.verify(&finished.verify).is_ok())
        //info!("verified {:?}", verified);
        //unimplemented!()
    }

    fn get_nonce(&self, counter: u64, iv: &GenericArray<u8, IvLen>) -> GenericArray<u8, IvLen> {
        //info!("counter = {} {:x?}", counter, &counter.to_be_bytes(),);
        let counter = Self::pad::<IvLen>(&counter.to_be_bytes());

        //info!("counter = {:x?}", counter);
        // info!("iv = {:x?}", iv);

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
        // info!("padding input = {:x?}", input);
        let mut padded = GenericArray::default();
        for (index, byte) in input.iter().rev().enumerate() {
            /*info!(
                "{} pad {}={:x?}",
                index,
                ((N::to_usize() - index) - 1),
                *byte
            );*/
            padded[(N::to_usize() - index) - 1] = *byte;
        }
        padded
    }

    fn zero() -> GenericArray<u8, D::OutputSize> {
        GenericArray::default()
    }

    fn derived(&mut self) -> Result<(), TlsError> {
        self.secret = self.derive_secret(b"derived", ContextType::EmptyHash)?;
        Ok(())
    }

    pub fn initialize_early_secret(&mut self) -> Result<(), TlsError> {
        let (secret, hkdf) =
            Hkdf::<D>::extract(Some(self.secret.as_ref()), Self::zero().as_slice());
        self.hkdf.replace(hkdf);
        self.secret = secret;
        // no right-hand jaunts (yet)
        self.derived()
    }

    pub fn initialize_handshake_secret(&mut self, ikm: &[u8]) -> Result<(), TlsError> {
        let (secret, hkdf) = Hkdf::<D>::extract(Some(self.secret.as_ref()), ikm);
        self.secret = secret;
        self.hkdf.replace(hkdf);
        self.calculate_traffic_secrets(b"c hs traffic", b"s hs traffic")?;
        self.derived()
    }

    pub fn initialize_master_secret(&mut self) -> Result<(), TlsError> {
        let (secret, hkdf) =
            Hkdf::<D>::extract(Some(self.secret.as_ref()), Self::zero().as_slice());
        self.secret = secret;
        self.hkdf.replace(hkdf);

        //let context = self.transcript_hash.as_ref().unwrap().clone().finalize();
        //info!("Derive keys, hash: {:x?}", context);

        self.calculate_traffic_secrets(b"c ap traffic", b"s ap traffic")?;
        self.derived()
    }

    fn calculate_traffic_secrets(
        &mut self,
        client_label: &[u8],
        server_label: &[u8],
    ) -> Result<(), TlsError> {
        let client_secret = self.derive_secret(client_label, ContextType::TranscriptHash)?;
        self.client_traffic_secret
            .replace(Hkdf::from_prk(&client_secret).unwrap());
        /*info!(
            "\n\nTRAFFIC {} secret {:x?}",
            core::str::from_utf8(client_label).unwrap(),
            client_secret
        );*/
        let server_secret = self.derive_secret(server_label, ContextType::TranscriptHash)?;
        self.server_traffic_secret
            .replace(Hkdf::from_prk(&server_secret).unwrap());
        /*info!(
            "TRAFFIC {} secret {:x?}\n\n",
            core::str::from_utf8(server_label).unwrap(),
            server_secret
        );*/
        self.read_counter = 0;
        self.write_counter = 0;
        Ok(())
    }

    fn derive_secret(
        &mut self,
        label: &[u8],
        context_type: ContextType,
    ) -> Result<GenericArray<u8, D::OutputSize>, TlsError> {
        let label = self.make_hkdf_label(label, context_type, D::OutputSize::to_u16())?;
        self.hkdf_expand_label(self.hkdf.as_ref().unwrap(), &label)
    }

    pub fn hkdf_expand_label<N: ArrayLength<u8>>(
        &self,
        hkdf: &Hkdf<D>,
        label: &[u8],
    ) -> Result<GenericArray<u8, N>, TlsError> {
        let mut okm: GenericArray<u8, N> = Default::default();
        //info!("label {:x?}", label);
        hkdf.expand(label, &mut okm)
            .map_err(|_| TlsError::CryptoError)?;
        //info!("expand {:x?}", okm);
        Ok(okm)
    }

    fn make_hkdf_label(
        &self,
        label: &[u8],
        context_type: ContextType,
        len: u16,
    ) -> Result<Vec<u8, 512>, TlsError> {
        //info!("make label {:?} {}", label, len);
        let mut hkdf_label = Vec::new();
        hkdf_label
            .extend_from_slice(&len.to_be_bytes())
            .map_err(|_| TlsError::InternalError)?;

        let label_len = 6 + label.len() as u8;
        hkdf_label
            .extend_from_slice(&(label_len as u8).to_be_bytes())
            .map_err(|_| TlsError::InternalError)?;
        hkdf_label
            .extend_from_slice(b"tls13 ")
            .map_err(|_| TlsError::InternalError)?;
        hkdf_label
            .extend_from_slice(label)
            .map_err(|_| TlsError::InternalError)?;

        match context_type {
            ContextType::None => {
                hkdf_label.push(0).map_err(|_| TlsError::InternalError)?;
            }
            ContextType::TranscriptHash => {
                let context = self.transcript_hash.as_ref().unwrap().clone().finalize();
                hkdf_label
                    .extend_from_slice(&(context.len() as u8).to_be_bytes())
                    .map_err(|_| TlsError::InternalError)?;
                hkdf_label
                    .extend_from_slice(&context)
                    .map_err(|_| TlsError::InternalError)?;
            }
            ContextType::EmptyHash => {
                let context = D::new().chain(&[]).finalize();
                hkdf_label
                    .extend_from_slice(&(context.len() as u8).to_be_bytes())
                    .map_err(|_| TlsError::InternalError)?;
                hkdf_label
                    .extend_from_slice(&context)
                    .map_err(|_| TlsError::InternalError)?;
            }
        }
        Ok(hkdf_label)
    }
}

impl<D, KeyLen, IvLen> Default for KeySchedule<D, KeyLen, IvLen>
where
    D: Update + BlockInput + FixedOutput + Reset + Default + Clone,
    D::BlockSize: ArrayLength<u8>,
    D::OutputSize: ArrayLength<u8>,
    KeyLen: ArrayLength<u8>,
    IvLen: ArrayLength<u8>,
{
    fn default() -> Self {
        KeySchedule::new()
    }
}
