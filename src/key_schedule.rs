use crate::handshake::binder::PskBinder;
use crate::handshake::finished::Finished;
use crate::{config::TlsCipherSuite, TlsError};
use digest::generic_array::ArrayLength;
use heapless::Vec;
use hmac::digest::OutputSizeUser;
use hmac::{Mac, SimpleHmac};
use sha2::digest::generic_array::{typenum::Unsigned, GenericArray};
use sha2::Digest;

pub type HashOutputSize<CipherSuite> =
    <<CipherSuite as TlsCipherSuite>::Hash as OutputSizeUser>::OutputSize;

pub type IvArray<CipherSuite> = GenericArray<u8, <CipherSuite as TlsCipherSuite>::IvLen>;
pub type KeyArray<CipherSuite> = GenericArray<u8, <CipherSuite as TlsCipherSuite>::KeyLen>;
pub type HashArray<CipherSuite> = GenericArray<u8, HashOutputSize<CipherSuite>>;

type Hkdf<CipherSuite> = hkdf::Hkdf<
    <CipherSuite as TlsCipherSuite>::Hash,
    SimpleHmac<<CipherSuite as TlsCipherSuite>::Hash>,
>;

pub struct KeySchedule<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    secret: HashArray<CipherSuite>,
    transcript_hash: CipherSuite::Hash,
    hkdf: Option<Hkdf<CipherSuite>>,
    client_traffic_secret: Option<Hkdf<CipherSuite>>,
    server_traffic_secret: Option<Hkdf<CipherSuite>>,
    binder_key: Option<Hkdf<CipherSuite>>,
    read_counter: u64,
    write_counter: u64,
}

enum ContextType {
    None,
    TranscriptHash,
    EmptyHash,
}

impl<CipherSuite> KeySchedule<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub fn new() -> Self {
        Self {
            secret: Self::zero(),
            transcript_hash: CipherSuite::Hash::new(),
            hkdf: None,
            client_traffic_secret: None,
            server_traffic_secret: None,
            binder_key: None,
            read_counter: 0,
            write_counter: 0,
        }
    }

    pub(crate) fn transcript_hash(&mut self) -> &mut CipherSuite::Hash {
        &mut self.transcript_hash
    }

    pub(crate) fn replace_transcript_hash(&mut self, hash: CipherSuite::Hash) {
        self.transcript_hash = hash;
    }

    pub(crate) fn increment_read_counter(&mut self) {
        self.read_counter = self.read_counter.checked_add(1).unwrap()
    }

    pub(crate) fn increment_write_counter(&mut self) {
        self.write_counter = self.write_counter.checked_add(1).unwrap()
    }

    pub(crate) fn reset_write_counter(&mut self) {
        self.write_counter = 0;
    }

    pub(crate) fn get_server_nonce(&self) -> Result<IvArray<CipherSuite>, TlsError> {
        Ok(self.get_nonce(self.read_counter, &self.get_server_iv()?))
    }

    pub(crate) fn get_client_nonce(&self) -> Result<IvArray<CipherSuite>, TlsError> {
        Ok(self.get_nonce(self.write_counter, &self.get_client_iv()?))
    }

    pub(crate) fn get_server_key(&self) -> Result<KeyArray<CipherSuite>, TlsError> {
        self.hkdf_expand_label(
            self.server_traffic_secret.as_ref().unwrap(),
            &self.make_hkdf_label(b"key", ContextType::None, CipherSuite::KeyLen::to_u16())?,
        )
    }

    pub(crate) fn get_client_key(&self) -> Result<KeyArray<CipherSuite>, TlsError> {
        self.hkdf_expand_label(
            self.client_traffic_secret.as_ref().unwrap(),
            &self.make_hkdf_label(b"key", ContextType::None, CipherSuite::KeyLen::to_u16())?,
        )
    }

    fn get_server_iv(&self) -> Result<IvArray<CipherSuite>, TlsError> {
        self.hkdf_expand_label(
            self.server_traffic_secret.as_ref().unwrap(),
            &self.make_hkdf_label(b"iv", ContextType::None, CipherSuite::IvLen::to_u16())?,
        )
    }

    fn get_client_iv(&self) -> Result<IvArray<CipherSuite>, TlsError> {
        self.hkdf_expand_label(
            self.client_traffic_secret.as_ref().unwrap(),
            &self.make_hkdf_label(b"iv", ContextType::None, CipherSuite::IvLen::to_u16())?,
        )
    }

    pub fn create_client_finished(
        &self,
    ) -> Result<Finished<HashOutputSize<CipherSuite>>, TlsError> {
        let key = self.hkdf_expand_label::<HashOutputSize<CipherSuite>>(
            self.client_traffic_secret.as_ref().unwrap(),
            &self.make_hkdf_label(
                b"finished",
                ContextType::None,
                HashOutputSize::<CipherSuite>::to_u16(),
            )?,
        )?;

        let mut hmac = SimpleHmac::<CipherSuite::Hash>::new_from_slice(&key)
            .map_err(|_| TlsError::CryptoError)?;
        Mac::update(&mut hmac, &self.transcript_hash.clone().finalize());
        let verify = hmac.finalize().into_bytes();

        Ok(Finished { verify, hash: None })
    }

    pub fn create_psk_binder(&self) -> Result<PskBinder<HashOutputSize<CipherSuite>>, TlsError> {
        let key = self.hkdf_expand_label::<HashOutputSize<CipherSuite>>(
            self.binder_key.as_ref().unwrap(),
            &self.make_hkdf_label(
                b"finished",
                ContextType::None,
                HashOutputSize::<CipherSuite>::to_u16(),
            )?,
        )?;

        let mut hmac = SimpleHmac::<CipherSuite::Hash>::new_from_slice(&key)
            .map_err(|_| TlsError::CryptoError)?;
        Mac::update(&mut hmac, &self.transcript_hash.clone().finalize());
        let verify = hmac.finalize().into_bytes();
        Ok(PskBinder { verify })
    }

    pub fn verify_server_finished(
        &self,
        finished: &Finished<HashOutputSize<CipherSuite>>,
    ) -> Result<bool, TlsError> {
        //info!("verify server finished: {:x?}", finished.verify);
        //self.client_traffic_secret.as_ref().unwrap().expand()
        //info!("size ===> {}", D::OutputSize::to_u16());
        let key = self.hkdf_expand_label::<HashOutputSize<CipherSuite>>(
            self.server_traffic_secret.as_ref().unwrap(),
            &self.make_hkdf_label(
                b"finished",
                ContextType::None,
                HashOutputSize::<CipherSuite>::to_u16(),
            )?,
        )?;
        // info!("hmac sign key {:x?}", key);
        let mut hmac = SimpleHmac::<CipherSuite::Hash>::new_from_slice(&key).unwrap();
        Mac::update(&mut hmac, finished.hash.as_ref().unwrap());
        //let code = hmac.clone().finalize().into_bytes();
        Ok(hmac.verify(&finished.verify).is_ok())
        //info!("verified {:?}", verified);
        //unimplemented!()
    }

    fn get_nonce(&self, counter: u64, iv: &IvArray<CipherSuite>) -> IvArray<CipherSuite> {
        //info!("counter = {} {:x?}", counter, &counter.to_be_bytes(),);
        let counter = Self::pad::<CipherSuite::IvLen>(&counter.to_be_bytes());

        //info!("counter = {:x?}", counter);
        // info!("iv = {:x?}", iv);

        let mut nonce = GenericArray::default();

        for (index, (l, r)) in iv[0..CipherSuite::IvLen::to_usize()]
            .iter()
            .zip(counter.iter())
            .enumerate()
        {
            nonce[index] = l ^ r;
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

    fn zero() -> HashArray<CipherSuite> {
        GenericArray::default()
    }

    fn derived(&mut self) -> Result<(), TlsError> {
        self.secret = self.derive_secret(b"derived", ContextType::EmptyHash)?;
        Ok(())
    }

    fn initialize(&mut self, ikm: &[u8]) {
        let (secret, hkdf) = Hkdf::<CipherSuite>::extract(Some(self.secret.as_ref()), ikm);
        self.hkdf = Some(hkdf);
        self.secret = secret;
    }

    // Initializes the early secrets with a callback for any PSK binders
    pub fn initialize_early_secret(&mut self, psk: Option<&[u8]>) -> Result<(), TlsError> {
        self.initialize(
            #[allow(clippy::or_fun_call)]
            psk.unwrap_or(Self::zero().as_slice()),
        );

        let binder_key = self.derive_secret(b"ext binder", ContextType::EmptyHash)?;
        self.binder_key
            .replace(Hkdf::<CipherSuite>::from_prk(&binder_key).unwrap());
        self.derived()
    }

    pub fn initialize_handshake_secret(&mut self, ikm: &[u8]) -> Result<(), TlsError> {
        self.initialize(ikm);

        self.calculate_traffic_secrets(b"c hs traffic", b"s hs traffic")?;
        self.derived()
    }

    pub fn initialize_master_secret(&mut self) -> Result<(), TlsError> {
        self.initialize(Self::zero().as_slice());

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
            .replace(Hkdf::<CipherSuite>::from_prk(&client_secret).unwrap());
        /*info!(
            "\n\nTRAFFIC {} secret {:x?}",
            core::str::from_utf8(client_label).unwrap(),
            client_secret
        );*/
        let server_secret = self.derive_secret(server_label, ContextType::TranscriptHash)?;
        self.server_traffic_secret
            .replace(Hkdf::<CipherSuite>::from_prk(&server_secret).unwrap());
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
    ) -> Result<HashArray<CipherSuite>, TlsError> {
        self.hkdf_expand_label(
            self.hkdf.as_ref().unwrap(),
            &self.make_hkdf_label(label, context_type, HashOutputSize::<CipherSuite>::to_u16())?,
        )
    }

    fn hkdf_expand_label<N: ArrayLength<u8>>(
        &self,
        hkdf: &Hkdf<CipherSuite>,
        label: &[u8],
    ) -> Result<GenericArray<u8, N>, TlsError> {
        let mut okm = GenericArray::default();
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
            .extend_from_slice(&label_len.to_be_bytes())
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
                let context = self.transcript_hash.clone().finalize();
                hkdf_label
                    .extend_from_slice(&(context.len() as u8).to_be_bytes())
                    .map_err(|_| TlsError::InternalError)?;
                hkdf_label
                    .extend_from_slice(&context)
                    .map_err(|_| TlsError::InternalError)?;
            }
            ContextType::EmptyHash => {
                let context = CipherSuite::Hash::new().chain_update([]).finalize();
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

impl<CipherSuite> Default for KeySchedule<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    fn default() -> Self {
        KeySchedule::new()
    }
}
