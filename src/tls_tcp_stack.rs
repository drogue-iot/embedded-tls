use crate::config::{Config, TlsCipherSuite};
use crate::crypto_engine::CryptoEngine;
use crate::handshake::client_hello::ClientHello;
use crate::handshake::server_hello::ServerHello;
use crate::handshake::ServerHandshake;
use crate::record::{ClientRecord, ServerRecord};
use crate::tls_connection::TlsConnection;
use crate::TlsError;
use crate::traits::ip::{IpProtocol, SocketAddress};
use crate::traits::tcp::{TcpError, TcpSocket, TcpStack};
use core::future::Future;
use digest::{BlockInput, Digest, FixedOutput, Reset, Update};
use heapless::{consts::*, ArrayLength, Vec};
use rand_core::{CryptoRng, RngCore};

pub struct TlsTcpStack<Tcp, RNG, CipherSuite, TxBufLen, RxBufLen>
where
    Tcp: TcpStack + 'static,
    RNG: CryptoRng + RngCore + Copy + 'static,
    CipherSuite: TlsCipherSuite + 'static,
    TxBufLen: ArrayLength<u8>,
    RxBufLen: ArrayLength<u8>,
{
    delegate: Tcp,
    pub(crate) config: Option<&'static Config<RNG, CipherSuite>>,
    connections: [Option<TlsConnection<RNG, Tcp, CipherSuite, TxBufLen, RxBufLen>>; 1],
}

/*
impl<Tcp, RNG, CipherSuite, TxBufLen, RxBufLen> Actor
    for TlsTcpStack<Tcp, RNG, CipherSuite, TxBufLen, RxBufLen>
where
    Tcp: TcpStack + 'static,
    RNG: CryptoRng + RngCore + Copy + 'static,
    CipherSuite: TlsCipherSuite + 'static,
    TxBufLen: ArrayLength<u8>,
    RxBufLen: ArrayLength<u8>,
{
    type Configuration = (&'static Config<RNG, CipherSuite>, Tcp);

    fn on_mount(&mut self, config: Self::Configuration)
    where
        Self: Sized,
    {
        self.config.replace(config.0);
        self.delegate.replace(config.1);
    }
}
*/

impl<Tcp, RNG, CipherSuite, TxBufLen, RxBufLen>
    TlsTcpStack<Tcp, RNG, CipherSuite, TxBufLen, RxBufLen>
where
    Tcp: TcpStack + 'static,
    RNG: CryptoRng + RngCore + Copy,
    CipherSuite: TlsCipherSuite,
    TxBufLen: ArrayLength<u8>,
    RxBufLen: ArrayLength<u8>,
{
    pub fn new(delegate: Tcp) -> Self {
        Self {
            delegate,
            config: None,
            connections: Default::default(),
        }
    }
}

impl<Tcp, RNG, CipherSuite, TxBufLen, RxBufLen> TcpStack
    for TlsTcpStack<Tcp, RNG, CipherSuite, TxBufLen, RxBufLen>
where
    Tcp: TcpStack + 'static,
    RNG: CryptoRng + RngCore + Copy,
    CipherSuite: TlsCipherSuite,
    TxBufLen: ArrayLength<u8>,
    RxBufLen: ArrayLength<u8>,
{
    type SocketHandle = u8;

    #[rustfmt::skip]
    type OpenFuture<'m> = impl Future<Output = Self::SocketHandle> + 'm;
    fn open<'m>(&'m mut self) -> Self::OpenFuture<'m> {
        async move {
            let delegate = self.delegate.open().await;
            //let handle = TlsConnection::new(self.delegate.unwrap(), delegate);
            let result = self
                .connections
                .iter_mut()
                .enumerate()
                .find(|(index, slot)| matches!(slot, None));

            match result {
                None => (self, u8::max_value()),
                Some((index, slot)) => {
                    slot.replace(TlsConnection::new(self.config.unwrap(), delegate));
                    (self, index as u8)
                }
            }
        }
    }

    #[rustfmt::skip]
    type ConnectFuture<'m> = impl Future<Output = Result<(), TcpError>> + 'm;
    fn connect<'m>(
        &'m mut self,
        handle: Self::SocketHandle,
        proto: IpProtocol,
        dst: SocketAddress,
    ) -> Self::ConnectFuture<'m> {
        async move {
            let mut connection = &mut self.connections[handle as usize];

            match connection {
                None => (self, Err(TcpError::ConnectError)),
                Some(connection) => {
                    let result = connection.connect(proto, dst).await.map_err(|e| match e {
                        TlsError::TcpError(tcp_error) => tcp_error,
                        _ => TcpError::ConnectError,
                    });
                    (self, result)
                }
            }
        }
    }

    #[rustfmt::skip]
    type WriteFuture<'m> = impl Future<Output = Result<usize, TcpError>> + 'm;
    fn write<'m>(&'m mut self, handle: Self::SocketHandle, buf: &'m [u8]) -> Self::WriteFuture<'m> {
        unimplemented!()
    }

    #[rustfmt::skip]
    type ReadFuture<'m> = impl Future<Output = Result<usize, TcpError>> + 'm;
    fn read<'m>(
        &'m mut self,
        handle: Self::SocketHandle,
        buf: &'m mut [u8],
    ) -> Self::ReadFuture<'m> {
        unimplemented!()
    }

    #[rustfmt::skip]
    type CloseFuture<'m> = impl Future<Output = ()> + 'm;
    fn close<'m>(&'m mut self, handle: Self::SocketHandle) -> Self::CloseFuture<'m> {
        unimplemented!()
    }
}
