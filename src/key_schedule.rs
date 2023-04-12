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

enum Secret<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    Uninitialized,
    Initialized(Hkdf<CipherSuite>),
}

impl<CipherSuite> Secret<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    fn replace(&mut self, secret: Hkdf<CipherSuite>) {
        *self = Self::Initialized(secret);
    }

    fn as_ref(&self) -> &Hkdf<CipherSuite> {
        match self {
            Secret::Initialized(ref secret) => secret,
            Secret::Uninitialized => panic!(),
        }
    }

    fn make_expanded_hkdf_label<N: ArrayLength<u8>>(
        &self,
        label: &[u8],
        context_type: ContextType<CipherSuite>,
    ) -> Result<GenericArray<u8, N>, TlsError> {
        //info!("make label {:?} {}", label, len);
        let mut hkdf_label = Vec::<u8, 512>::new();
        hkdf_label
            .extend_from_slice(&N::to_u16().to_be_bytes())
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
            ContextType::Hash(context) => {
                hkdf_label
                    .extend_from_slice(&(context.len() as u8).to_be_bytes())
                    .map_err(|_| TlsError::InternalError)?;
                hkdf_label
                    .extend_from_slice(&context)
                    .map_err(|_| TlsError::InternalError)?;
            }
        }

        let mut okm = GenericArray::default();
        //info!("label {:x?}", label);
        self.as_ref()
            .expand(&hkdf_label, &mut okm)
            .map_err(|_| TlsError::CryptoError)?;
        //info!("expand {:x?}", okm);
        Ok(okm)
    }
}

pub struct KeySchedule<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    shared: SharedState<CipherSuite>,
    client_state: KeyScheduleState<CipherSuite>, // used for writes
    server_state: KeyScheduleState<CipherSuite>, // used for reads
    transcript_hash: CipherSuite::Hash,          // server state
    binder_key: Secret<CipherSuite>,             // client state
}

struct SharedState<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    secret: HashArray<CipherSuite>,
    hkdf: Secret<CipherSuite>,
}

impl<CipherSuite> SharedState<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    fn new() -> Self {
        Self {
            secret: GenericArray::default(),
            hkdf: Secret::Uninitialized,
        }
    }

    fn initialize(&mut self, ikm: &[u8]) {
        let (secret, hkdf) = Hkdf::<CipherSuite>::extract(Some(self.secret.as_ref()), ikm);
        self.hkdf.replace(hkdf);
        self.secret = secret;
    }

    fn derive_secret(
        &mut self,
        label: &[u8],
        context_type: ContextType<CipherSuite>,
    ) -> Result<HashArray<CipherSuite>, TlsError> {
        self.hkdf
            .make_expanded_hkdf_label::<HashOutputSize<CipherSuite>>(label, context_type)
    }

    fn derived(&mut self) -> Result<(), TlsError> {
        self.secret = self.derive_secret(b"derived", ContextType::empty_hash())?;
        Ok(())
    }
}

pub(crate) struct KeyScheduleState<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    traffic_secret: Secret<CipherSuite>,
    counter: u64,
}

impl<CipherSuite> KeyScheduleState<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    fn new() -> Self {
        Self {
            traffic_secret: Secret::Uninitialized,
            counter: 0,
        }
    }

    pub fn get_key(&self) -> Result<KeyArray<CipherSuite>, TlsError> {
        self.traffic_secret
            .make_expanded_hkdf_label(b"key", ContextType::None)
    }

    pub fn get_iv(&self) -> Result<IvArray<CipherSuite>, TlsError> {
        self.traffic_secret
            .make_expanded_hkdf_label(b"iv", ContextType::None)
    }

    pub fn get_nonce(&self) -> Result<IvArray<CipherSuite>, TlsError> {
        Ok(KeySchedule::<CipherSuite>::get_nonce(
            self.counter,
            &self.get_iv()?,
        ))
    }

    fn calculate_traffic_secret(
        &mut self,
        label: &[u8],
        shared: &mut SharedState<CipherSuite>,
        transcript_hash: &CipherSuite::Hash,
    ) -> Result<(), TlsError> {
        let secret = shared.derive_secret(label, ContextType::transcript_hash(transcript_hash))?;
        let traffic_secret =
            Hkdf::<CipherSuite>::from_prk(&secret).map_err(|_| TlsError::InternalError)?;

        self.traffic_secret.replace(traffic_secret);
        self.counter = 0;
        Ok(())
    }

    pub fn increment_counter(&mut self) {
        self.counter = self.counter.checked_add(1).unwrap();
    }
}

enum ContextType<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    None,
    Hash(HashArray<CipherSuite>),
}

impl<CipherSuite> ContextType<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    fn transcript_hash(hash: &CipherSuite::Hash) -> Self {
        Self::Hash(hash.clone().finalize())
    }

    fn empty_hash() -> Self {
        Self::Hash(CipherSuite::Hash::new().chain_update([]).finalize())
    }
}

impl<CipherSuite> KeySchedule<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub fn new() -> Self {
        Self {
            shared: SharedState::new(),
            client_state: KeyScheduleState::new(),
            server_state: KeyScheduleState::new(),
            binder_key: Secret::Uninitialized,
            transcript_hash: CipherSuite::Hash::new(),
        }
    }

    pub(crate) fn transcript_hash(&mut self) -> &mut CipherSuite::Hash {
        &mut self.transcript_hash
    }

    pub(crate) fn replace_transcript_hash(&mut self, hash: CipherSuite::Hash) {
        self.transcript_hash = hash;
    }

    pub(crate) fn write_state(&mut self) -> &mut KeyScheduleState<CipherSuite> {
        &mut self.client_state
    }

    pub(crate) fn read_state(&mut self) -> &mut KeyScheduleState<CipherSuite> {
        &mut self.server_state
    }

    pub fn create_client_finished(
        &self,
    ) -> Result<Finished<HashOutputSize<CipherSuite>>, TlsError> {
        let key = self
            .client_state
            .traffic_secret
            .make_expanded_hkdf_label::<HashOutputSize<CipherSuite>>(
                b"finished",
                ContextType::None,
            )?;

        let mut hmac = SimpleHmac::<CipherSuite::Hash>::new_from_slice(&key)
            .map_err(|_| TlsError::CryptoError)?;
        Mac::update(&mut hmac, &self.transcript_hash.clone().finalize());
        let verify = hmac.finalize().into_bytes();

        Ok(Finished { verify, hash: None })
    }

    pub fn create_psk_binder(&self) -> Result<PskBinder<HashOutputSize<CipherSuite>>, TlsError> {
        let key = self
            .binder_key
            .make_expanded_hkdf_label::<HashOutputSize<CipherSuite>>(
                b"finished",
                ContextType::None,
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
        let key = self
            .server_state
            .traffic_secret
            .make_expanded_hkdf_label::<HashOutputSize<CipherSuite>>(
                b"finished",
                ContextType::None,
            )?;
        // info!("hmac sign key {:x?}", key);
        let mut hmac = SimpleHmac::<CipherSuite::Hash>::new_from_slice(&key)
            .map_err(|_| TlsError::InternalError)?;
        Mac::update(
            &mut hmac,
            finished.hash.as_ref().ok_or(TlsError::InternalError)?,
        );
        //let code = hmac.clone().finalize().into_bytes();
        Ok(hmac.verify(&finished.verify).is_ok())
        //info!("verified {:?}", verified);
        //unimplemented!()
    }

    fn get_nonce(counter: u64, iv: &IvArray<CipherSuite>) -> IvArray<CipherSuite> {
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

    // Initializes the early secrets with a callback for any PSK binders
    pub fn initialize_early_secret(&mut self, psk: Option<&[u8]>) -> Result<(), TlsError> {
        self.shared.initialize(
            #[allow(clippy::or_fun_call)]
            psk.unwrap_or(Self::zero().as_slice()),
        );

        let binder_key = self
            .shared
            .derive_secret(b"ext binder", ContextType::empty_hash())?;
        self.binder_key.replace(
            Hkdf::<CipherSuite>::from_prk(&binder_key).map_err(|_| TlsError::InternalError)?,
        );
        self.shared.derived()
    }

    pub fn initialize_handshake_secret(&mut self, ikm: &[u8]) -> Result<(), TlsError> {
        self.shared.initialize(ikm);

        self.calculate_traffic_secrets(b"c hs traffic", b"s hs traffic")?;
        self.shared.derived()
    }

    pub fn initialize_master_secret(&mut self) -> Result<(), TlsError> {
        self.shared.initialize(Self::zero().as_slice());

        //let context = self.transcript_hash.as_ref().unwrap().clone().finalize();
        //info!("Derive keys, hash: {:x?}", context);

        self.calculate_traffic_secrets(b"c ap traffic", b"s ap traffic")?;
        self.shared.derived()
    }

    fn calculate_traffic_secrets(
        &mut self,
        client_label: &[u8],
        server_label: &[u8],
    ) -> Result<(), TlsError> {
        self.client_state.calculate_traffic_secret(
            client_label,
            &mut self.shared,
            &self.transcript_hash,
        )?;

        self.server_state.calculate_traffic_secret(
            server_label,
            &mut self.shared,
            &self.transcript_hash,
        )?;

        Ok(())
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
