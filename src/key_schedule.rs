use crate::handshake::binder::PskBinder;
use crate::handshake::finished::Finished;
use crate::hkdf;
use crate::{CryptoProvider, TlsError, config::TlsCipherSuite};
use digest::{Digest, KeyInit, Mac, Output};
use subtle::ConstantTimeEq;

pub type ProviderHashArray<Provider> = Output<<Provider as CryptoProvider>::Hash>;

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

    fn make_expanded_hkdf_label(
        &self,
        label: &[u8],
        context_type: ContextType<Provider>,
        out: &mut [u8],
    ) -> Result<(), TlsError> {
        let mut hkdf_label = heapless::Vec::<u8, 70>::new();
        hkdf_label
            .extend_from_slice(&(out.len() as u16).to_be_bytes())
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

        hkdf::hkdf_expand::<Provider::Hmac>(
            self.as_ref()?.as_slice(),
            &hkdf_label,
            out.len(),
            out,
        )?;
        Ok(())
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
            secret: ProviderHashArray::<Provider>::default(),
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
        let mut out: ProviderHashArray<Provider> = Default::default();
        self.hkdf
            .make_expanded_hkdf_label(label, context_type, out.as_mut())?;
        Ok(out)
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
    key: <Provider::CipherSuite as TlsCipherSuite>::KeyArray,
    iv: <Provider::CipherSuite as TlsCipherSuite>::IvArray,
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
            key: Default::default(),
            iv: Default::default(),
            aead: None,
        }
    }

    #[inline]
    #[allow(dead_code)]
    pub fn get_key(
        &self,
    ) -> Result<&<Provider::CipherSuite as TlsCipherSuite>::KeyArray, TlsError> {
        Ok(&self.key)
    }

    #[inline]
    pub fn get_iv(&self) -> Result<&<Provider::CipherSuite as TlsCipherSuite>::IvArray, TlsError> {
        Ok(&self.iv)
    }

    pub fn get_nonce(
        &self,
    ) -> Result<<Provider::CipherSuite as TlsCipherSuite>::IvArray, TlsError> {
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
        let mut context: ProviderHashArray<Provider> = Default::default();
        let cloned = transcript_hash.clone();
        Digest::finalize_into(cloned, context.as_mut());

        let secret = shared.derive_secret(label, ContextType::Hash(context))?;
        self.traffic_secret.replace(secret);

        let mut key: <Provider::CipherSuite as TlsCipherSuite>::KeyArray = Default::default();
        self.traffic_secret
            .make_expanded_hkdf_label(b"key", ContextType::None, key.as_mut())?;
        self.key = key;

        let mut iv: <Provider::CipherSuite as TlsCipherSuite>::IvArray = Default::default();
        self.traffic_secret
            .make_expanded_hkdf_label(b"iv", ContextType::None, iv.as_mut())?;
        self.iv = iv;

        error!(
            "[DIAG] calculate_traffic_secret: key_len={}, iv_len={}",
            self.key.as_ref().len(),
            self.iv.as_ref().len()
        );
        self.aead = Some(provider.aead(self.key.as_ref()).map_err(|e| {
            error!(
                "[DIAG] provider.aead() failed: key_len={}, err={:?}",
                self.key.as_ref().len(),
                e
            );
            TlsError::CryptoError
        })?);
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
        let mut out: ProviderHashArray<Provider> = Default::default();
        let cloned = hash.clone();
        Digest::finalize_into(cloned, out.as_mut());
        Self::Hash(out)
    }

    fn empty_hash() -> Self {
        let mut hash = Provider::Hash::new();
        Digest::update(&mut hash, &[]);
        let mut out: ProviderHashArray<Provider> = Default::default();
        Digest::finalize_into(hash, out.as_mut());
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

    pub fn create_client_finished(&self) -> Result<Finished<Provider::Hash>, TlsError> {
        let mut key: ProviderHashArray<Provider> = Default::default();
        self.client_state
            .state
            .traffic_secret
            .make_expanded_hkdf_label(b"finished", ContextType::None, key.as_mut())?;

        error!("[DIAG] create_client_finished: key_len={}", key.len());
        let mut hmac = Provider::Hmac::new_from_slice(&key).map_err(|e| {
            error!("[DIAG] Hmac::new_from_slice failed in create_client_finished: key_len={}, err={:?}", key.len(), e);
            TlsError::CryptoError
        })?;
        let mut transcript: ProviderHashArray<Provider> = Default::default();
        let cloned = self.server_state.transcript_hash.clone();
        Digest::finalize_into(cloned, transcript.as_mut());
        Mac::update(&mut hmac, &transcript);
        let verify = hmac.finalize().into_bytes();

        Ok(Finished { verify, hash: None })
    }

    fn get_nonce(
        counter: u64,
        iv: &<Provider::CipherSuite as TlsCipherSuite>::IvArray,
    ) -> <Provider::CipherSuite as TlsCipherSuite>::IvArray {
        let iv_len = iv.as_ref().len();
        let mut counter_bytes = [0u8; 12];
        let counter_slice = &counter.to_be_bytes();
        let start = counter_bytes.len() - counter_slice.len();
        counter_bytes[start..].copy_from_slice(counter_slice);

        let mut nonce: <Provider::CipherSuite as TlsCipherSuite>::IvArray = Default::default();
        let nonce_ref: &mut [u8] = nonce.as_mut();
        for (index, (l, r)) in iv.as_ref()[0..iv_len]
            .iter()
            .zip(counter_bytes[counter_bytes.len() - iv_len..].iter())
            .enumerate()
        {
            nonce_ref[index] = l ^ r;
        }

        nonce
    }

    fn zero() -> ProviderHashArray<Provider> {
        Default::default()
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
    pub(crate) fn get_key(
        &self,
    ) -> Result<&<Provider::CipherSuite as TlsCipherSuite>::KeyArray, TlsError> {
        self.state.get_key()
    }

    pub(crate) fn get_nonce(
        &self,
    ) -> Result<<Provider::CipherSuite as TlsCipherSuite>::IvArray, TlsError> {
        self.state.get_nonce()
    }

    pub(crate) fn get_aead(&mut self) -> Result<&mut Provider::Aead, TlsError> {
        self.state.get_aead()
    }

    pub fn create_psk_binder(
        &self,
        transcript_hash: &Provider::Hash,
    ) -> Result<PskBinder<Provider::Hash>, TlsError> {
        let mut key: ProviderHashArray<Provider> = Default::default();
        self.binder_key
            .make_expanded_hkdf_label(b"finished", ContextType::None, key.as_mut())?;

        error!("[DIAG] create_client_finished: key_len={}", key.len());
        let mut hmac = Provider::Hmac::new_from_slice(&key).map_err(|e| {
            error!("[DIAG] Hmac::new_from_slice failed in create_client_finished: key_len={}, err={:?}", key.len(), e);
            TlsError::CryptoError
        })?;
        let mut transcript: ProviderHashArray<Provider> = Default::default();
        let cloned = transcript_hash.clone();
        Digest::finalize_into(cloned, transcript.as_mut());
        Mac::update(&mut hmac, &transcript);
        let verify = hmac.finalize().into_bytes();
        Ok(PskBinder::new(verify))
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
    pub(crate) fn get_key(
        &self,
    ) -> Result<&<Provider::CipherSuite as TlsCipherSuite>::KeyArray, TlsError> {
        self.state.get_key()
    }

    pub(crate) fn get_nonce(
        &self,
    ) -> Result<<Provider::CipherSuite as TlsCipherSuite>::IvArray, TlsError> {
        self.state.get_nonce()
    }

    pub(crate) fn get_aead(&mut self) -> Result<&mut Provider::Aead, TlsError> {
        self.state.get_aead()
    }

    pub fn verify_server_finished(
        &self,
        finished: &Finished<Provider::Hash>,
    ) -> Result<bool, TlsError> {
        let mut key: ProviderHashArray<Provider> = Default::default();
        self.state.traffic_secret.make_expanded_hkdf_label(
            b"finished",
            ContextType::None,
            key.as_mut(),
        )?;

        let mut hmac = Provider::Hmac::new_from_slice(&key).map_err(|_| TlsError::InternalError)?;
        let hash = finished.hash.as_ref().ok_or_else(|| {
            warn!("No hash in Finished");
            TlsError::InternalError
        })?;
        Mac::update(&mut hmac, hash);
        let verify = hmac.finalize().into_bytes();

        Ok(verify.as_slice().ct_eq(finished.verify.as_slice()).into())
    }
}
