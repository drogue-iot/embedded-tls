use crate::crypto_traits::{TlsHash, TlsHmac};
use crate::handshake::binder::PskBinder;
use crate::handshake::finished::Finished;
use crate::hkdf;
use crate::{CryptoProvider, TlsError, config::TlsCipherSuite};
use digest::OutputSizeUser;
use digest::generic_array::ArrayLength;
use sha2::digest::generic_array::{GenericArray, typenum::Unsigned};
use subtle::ConstantTimeEq;

// Backward-compatible alias (still used by handshake/finished, handshake/binder)
#[allow(dead_code)]
pub type HashOutputSize<CipherSuite> =
    <<CipherSuite as TlsCipherSuite>::Hash as OutputSizeUser>::OutputSize;

pub type IvArray<CipherSuite> = GenericArray<u8, <CipherSuite as TlsCipherSuite>::IvLen>;
pub type KeyArray<CipherSuite> = GenericArray<u8, <CipherSuite as TlsCipherSuite>::KeyLen>;
#[allow(dead_code)]
pub type HashArray<CipherSuite> = GenericArray<u8, HashOutputSize<CipherSuite>>;

// Provider-based aliases
pub type ProviderHashOutputSize<Provider> =
    <<Provider as CryptoProvider>::Hash as TlsHash>::OutputSize;
pub type ProviderHashArray<Provider> = GenericArray<u8, ProviderHashOutputSize<Provider>>;

enum Secret<Provider>
where
    Provider: CryptoProvider,
{
    Uninitialized,
    Initialized(ProviderHashArray<Provider>),
}

impl<Provider> Secret<Provider>
where
    Provider: CryptoProvider,
{
    fn replace(&mut self, secret: ProviderHashArray<Provider>) {
        *self = Self::Initialized(secret);
    }

    fn as_ref(&self) -> Result<&ProviderHashArray<Provider>, TlsError> {
        match self {
            Secret::Initialized(secret) => Ok(secret),
            Secret::Uninitialized => Err(TlsError::InternalError),
        }
    }

    fn make_expanded_hkdf_label<N: ArrayLength<u8>>(
        &self,
        label: &[u8],
        context_type: ContextType<Provider>,
    ) -> Result<GenericArray<u8, N>, TlsError> {
        //info!("make label {:?} {}", label, len);
        // Max label buffer: hash_output (up to 48 for SHA-384) + 12 (longest label) + 10 (overhead) = 70
        let mut hkdf_label = heapless::Vec::<u8, 70>::new();
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
        hkdf::hkdf_expand::<Provider::Hmac>(
            self.as_ref()?.as_slice(),
            &hkdf_label,
            N::USIZE,
            &mut okm,
        )?;
        //info!("expand {:x?}", okm);
        Ok(okm)
    }
}

pub struct SharedState<Provider>
where
    Provider: CryptoProvider,
{
    secret: ProviderHashArray<Provider>,
    hkdf: Secret<Provider>,
}

impl<Provider> SharedState<Provider>
where
    Provider: CryptoProvider,
{
    fn new() -> Self {
        Self {
            secret: GenericArray::default(),
            hkdf: Secret::Uninitialized,
        }
    }

    fn initialize(&mut self, ikm: &[u8]) {
        let prk = hkdf::hkdf_extract::<Provider::Hmac>(self.secret.as_slice(), ikm);
        self.secret = prk.clone();
        self.hkdf.replace(prk);
    }

    fn derive_secret(
        &mut self,
        label: &[u8],
        context_type: ContextType<Provider>,
    ) -> Result<ProviderHashArray<Provider>, TlsError> {
        self.hkdf
            .make_expanded_hkdf_label::<ProviderHashOutputSize<Provider>>(label, context_type)
    }

    fn derived(&mut self) -> Result<(), TlsError> {
        self.secret = self.derive_secret(b"derived", ContextType::empty_hash())?;
        Ok(())
    }
}

pub(crate) struct KeyScheduleState<Provider>
where
    Provider: CryptoProvider,
{
    traffic_secret: Secret<Provider>,
    counter: u64,
    key: KeyArray<Provider::CipherSuite>,
    iv: IvArray<Provider::CipherSuite>,
    aead: Option<Provider::Aead>,
}

impl<Provider> KeyScheduleState<Provider>
where
    Provider: CryptoProvider,
{
    fn new() -> Self {
        Self {
            traffic_secret: Secret::Uninitialized,
            counter: 0,
            key: KeyArray::<Provider::CipherSuite>::default(),
            iv: IvArray::<Provider::CipherSuite>::default(),
            aead: None,
        }
    }

    #[inline]
    #[allow(dead_code)]
    pub fn get_key(&self) -> Result<&KeyArray<Provider::CipherSuite>, TlsError> {
        Ok(&self.key)
    }

    #[inline]
    pub fn get_iv(&self) -> Result<&IvArray<Provider::CipherSuite>, TlsError> {
        Ok(&self.iv)
    }

    pub fn get_nonce(&self) -> Result<IvArray<Provider::CipherSuite>, TlsError> {
        let iv = self.get_iv()?;
        Ok(KeySchedule::<Provider>::get_nonce(self.counter, iv))
    }

    pub fn get_aead(&mut self) -> Result<&mut Provider::Aead, TlsError> {
        self.aead.as_mut().ok_or(TlsError::InternalError)
    }

    fn calculate_traffic_secret(
        &mut self,
        label: &[u8],
        shared: &mut SharedState<Provider>,
        transcript_hash: &Provider::Hash,
        provider: &mut Provider,
    ) -> Result<(), TlsError> {
        let mut context = GenericArray::default();
        let cloned = transcript_hash.clone();
        cloned.finalize_into(&mut context);

        let secret = shared.derive_secret(label, ContextType::Hash(context))?;
        self.traffic_secret.replace(secret);

        self.key = self
            .traffic_secret
            .make_expanded_hkdf_label(b"key", ContextType::None)?;
        self.iv = self
            .traffic_secret
            .make_expanded_hkdf_label(b"iv", ContextType::None)?;
        self.aead = Some(
            provider
                .aead(&self.key)
                .map_err(|_| TlsError::CryptoError)?,
        );
        self.counter = 0;
        Ok(())
    }

    pub fn increment_counter(&mut self) {
        self.counter = unwrap!(self.counter.checked_add(1));
    }
}

enum ContextType<Provider>
where
    Provider: CryptoProvider,
{
    None,
    Hash(ProviderHashArray<Provider>),
}

impl<Provider> ContextType<Provider>
where
    Provider: CryptoProvider,
{
    #[allow(dead_code)]
    fn transcript_hash(hash: &Provider::Hash) -> Self {
        let mut out = GenericArray::default();
        let cloned = hash.clone();
        cloned.finalize_into(&mut out);
        Self::Hash(out)
    }

    fn empty_hash() -> Self {
        let mut hash = Provider::Hash::new();
        hash.update(&[]);
        let mut out = GenericArray::default();
        hash.finalize_into(&mut out);
        Self::Hash(out)
    }
}

pub struct KeySchedule<Provider>
where
    Provider: CryptoProvider,
{
    shared: SharedState<Provider>,
    client_state: WriteKeySchedule<Provider>,
    server_state: ReadKeySchedule<Provider>,
}

impl<Provider> KeySchedule<Provider>
where
    Provider: CryptoProvider,
{
    pub fn new() -> Self {
        Self {
            shared: SharedState::new(),
            client_state: WriteKeySchedule {
                state: KeyScheduleState::new(),
                binder_key: Secret::Uninitialized,
            },
            server_state: ReadKeySchedule {
                state: KeyScheduleState::new(),
                transcript_hash: Provider::Hash::new(),
            },
        }
    }

    pub(crate) fn transcript_hash(&mut self) -> &mut Provider::Hash {
        &mut self.server_state.transcript_hash
    }

    pub(crate) fn replace_transcript_hash(&mut self, hash: Provider::Hash) {
        self.server_state.transcript_hash = hash;
    }

    pub fn as_split(
        &mut self,
    ) -> (
        &mut WriteKeySchedule<Provider>,
        &mut ReadKeySchedule<Provider>,
    ) {
        (&mut self.client_state, &mut self.server_state)
    }

    pub(crate) fn write_state(&mut self) -> &mut WriteKeySchedule<Provider> {
        &mut self.client_state
    }

    pub(crate) fn read_state(&mut self) -> &mut ReadKeySchedule<Provider> {
        &mut self.server_state
    }

    pub fn create_client_finished(
        &self,
    ) -> Result<Finished<ProviderHashOutputSize<Provider>>, TlsError> {
        let key = self
            .client_state
            .state
            .traffic_secret
            .make_expanded_hkdf_label::<ProviderHashOutputSize<Provider>>(
                b"finished",
                ContextType::None,
            )?;

        let mut hmac = Provider::Hmac::new(&key).map_err(|_| TlsError::CryptoError)?;
        let mut transcript = GenericArray::default();
        let cloned = self.server_state.transcript_hash.clone();
        cloned.finalize_into(&mut transcript);
        hmac.update(&transcript);
        let mut verify = GenericArray::default();
        hmac.finalize_into(&mut verify);

        Ok(Finished { verify, hash: None })
    }

    fn get_nonce(
        counter: u64,
        iv: &IvArray<Provider::CipherSuite>,
    ) -> IvArray<Provider::CipherSuite> {
        //info!("counter = {} {:x?}", counter, &counter.to_be_bytes(),);
        let counter =
            Self::pad::<<Provider::CipherSuite as TlsCipherSuite>::IvLen>(&counter.to_be_bytes());

        //info!("counter = {:x?}", counter);
        // info!("iv = {:x?}", iv);

        let mut nonce = GenericArray::default();
        for (index, (l, r)) in iv
            [0..<<Provider::CipherSuite as TlsCipherSuite>::IvLen as Unsigned>::to_usize()]
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

    fn zero() -> ProviderHashArray<Provider> {
        GenericArray::default()
    }

    pub fn initialize_early_secret(&mut self, psk: Option<&[u8]>) -> Result<(), TlsError> {
        self.shared.initialize(
            #[allow(clippy::or_fun_call)]
            psk.unwrap_or(Self::zero().as_slice()),
        );

        let binder_key = self
            .shared
            .derive_secret(b"ext binder", ContextType::empty_hash())?;
        self.client_state.binder_key.replace(binder_key);
        self.shared.derived()
    }

    pub fn initialize_handshake_secret(
        &mut self,
        ikm: &[u8],
        provider: &mut Provider,
    ) -> Result<(), TlsError> {
        self.shared.initialize(ikm);
        self.calculate_traffic_secrets(b"c hs traffic", b"s hs traffic", provider)?;
        self.shared.derived()
    }

    pub fn initialize_master_secret(&mut self, provider: &mut Provider) -> Result<(), TlsError> {
        self.shared.initialize(Self::zero().as_slice());

        //let context = self.transcript_hash.as_ref().unwrap().clone().finalize();
        //info!("Derive keys, hash: {:x?}", context);
        self.calculate_traffic_secrets(b"c ap traffic", b"s ap traffic", provider)?;
        self.shared.derived()
    }

    fn calculate_traffic_secrets(
        &mut self,
        client_label: &[u8],
        server_label: &[u8],
        provider: &mut Provider,
    ) -> Result<(), TlsError> {
        self.client_state.state.calculate_traffic_secret(
            client_label,
            &mut self.shared,
            &self.server_state.transcript_hash,
            provider,
        )?;

        self.server_state.state.calculate_traffic_secret(
            server_label,
            &mut self.shared,
            &self.server_state.transcript_hash,
            provider,
        )?;

        Ok(())
    }
}

pub struct WriteKeySchedule<Provider>
where
    Provider: CryptoProvider,
{
    state: KeyScheduleState<Provider>,
    binder_key: Secret<Provider>,
}

impl<Provider> WriteKeySchedule<Provider>
where
    Provider: CryptoProvider,
{
    pub(crate) fn increment_counter(&mut self) {
        self.state.increment_counter();
    }

    #[allow(dead_code)]
    pub(crate) fn get_key(&self) -> Result<&KeyArray<Provider::CipherSuite>, TlsError> {
        self.state.get_key()
    }

    pub(crate) fn get_nonce(&self) -> Result<IvArray<Provider::CipherSuite>, TlsError> {
        self.state.get_nonce()
    }

    pub(crate) fn get_aead(&mut self) -> Result<&mut Provider::Aead, TlsError> {
        self.state.get_aead()
    }

    pub fn create_psk_binder(
        &self,
        transcript_hash: &Provider::Hash,
    ) -> Result<PskBinder<ProviderHashOutputSize<Provider>>, TlsError> {
        let key = self
            .binder_key
            .make_expanded_hkdf_label::<ProviderHashOutputSize<Provider>>(
                b"finished",
                ContextType::None,
            )?;

        let mut hmac = Provider::Hmac::new(&key).map_err(|_| TlsError::CryptoError)?;
        let mut transcript = GenericArray::default();
        let cloned = transcript_hash.clone();
        cloned.finalize_into(&mut transcript);
        hmac.update(&transcript);
        let mut verify = GenericArray::default();
        hmac.finalize_into(&mut verify);
        Ok(PskBinder { verify })
    }
}

pub struct ReadKeySchedule<Provider>
where
    Provider: CryptoProvider,
{
    state: KeyScheduleState<Provider>,
    transcript_hash: Provider::Hash,
}

impl<Provider> ReadKeySchedule<Provider>
where
    Provider: CryptoProvider,
{
    pub(crate) fn increment_counter(&mut self) {
        self.state.increment_counter();
    }

    pub(crate) fn transcript_hash(&mut self) -> &mut Provider::Hash {
        &mut self.transcript_hash
    }

    #[allow(dead_code)]
    pub(crate) fn get_key(&self) -> Result<&KeyArray<Provider::CipherSuite>, TlsError> {
        self.state.get_key()
    }

    pub(crate) fn get_nonce(&self) -> Result<IvArray<Provider::CipherSuite>, TlsError> {
        self.state.get_nonce()
    }

    pub(crate) fn get_aead(&mut self) -> Result<&mut Provider::Aead, TlsError> {
        self.state.get_aead()
    }

    pub fn verify_server_finished(
        &self,
        finished: &Finished<ProviderHashOutputSize<Provider>>,
    ) -> Result<bool, TlsError> {
        let key = self
            .state
            .traffic_secret
            .make_expanded_hkdf_label::<ProviderHashOutputSize<Provider>>(
                b"finished",
                ContextType::None,
            )?;

        let mut hmac = Provider::Hmac::new(&key).map_err(|_| TlsError::InternalError)?;
        let hash = finished.hash.as_ref().ok_or_else(|| {
            warn!("No hash in Finished");
            TlsError::InternalError
        })?;
        hmac.update(hash);
        let mut verify = GenericArray::default();
        hmac.finalize_into(&mut verify);

        Ok(verify.as_slice().ct_eq(finished.verify.as_slice()).into())
    }
}
