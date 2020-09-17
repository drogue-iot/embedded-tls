use drogue_network::{TcpStack, SocketAddr, Mode};
use crate::ssl::config::SslConfig;
use crate::ssl::context::SslContext;
use core::cell::{RefCell, Cell};

use heapless::{
    Vec,
    consts::U16,
};

#[derive(Debug)]
pub enum TcpStackError<E> {
    UnableToCreateContext,
    NoAvailableSockets,
    SocketNotOpen,
    WantRead,
    WantWrite,
    AsyncInProgress,
    CryptoInProgress,
    Unknown(i32),
    Other(E),
}

impl<E> From<E> for TcpStackError<E> {
    fn from(error: E) -> Self {
        TcpStackError::Other(error)
    }
}

pub struct SslTcpStack<'stack, DelegateStack: TcpStack> {
    config: RefCell<SslConfig>,
    delegate: &'stack DelegateStack,
    sockets: RefCell<[SslTcpSocketState<DelegateStack>; 16]>,
}

impl<'stack, DelegateStack: TcpStack> SslTcpStack<'stack, DelegateStack> {
    pub fn new(mut config: SslConfig, delegate: &'stack DelegateStack) -> Self {
        Self {
            config: RefCell::new(config),
            delegate,
            sockets: RefCell::new(Default::default()),
        }
    }

    fn write_through(&self, socket: usize, delegate_socket: &mut DelegateStack::TcpSocket, buf: &[u8]) -> nb::Result<usize, TcpStackError<DelegateStack::Error>> {
        match self.delegate.write(delegate_socket, buf) {
            Ok(len) => {
                Ok(len)
            },
            Err(e) => {
                match e {
                    Error::Other(o) => {
                        Err(nb::Error::Other(TcpStackError::Other(o)))
                    },
                    Error::WouldBlock => {
                        Err(nb::Error::WouldBlock)
                    },
                }
            },
        }
    }

    fn read_through(&self, socket: usize, delegate_socket: &mut DelegateStack::TcpSocket, buf: &mut [u8]) -> nb::Result<usize, TcpStackError<DelegateStack::Error>> {
        match self.delegate.read(delegate_socket, buf) {
            Ok(len) => {
                Ok(len)
            },
            Err(e) => {
                match e {
                    Error::Other(o) => {
                        Err(nb::Error::Other(TcpStackError::Other(o)))
                    },
                    Error::WouldBlock => {
                        Err(nb::Error::WouldBlock)
                    },
                }
            },
        }
    }

    fn callback_context<'a>(&self, socket: &SslTcpSocket, delegate_socket: &'a mut DelegateStack::TcpSocket) -> CallbackContext<'a, DelegateStack> {
        CallbackContext {
            stack: &*self as *const _ as *const c_void,
            delegate_socket,
            socket: socket.0,
        }
    }
}

impl<'stack, DelegateStack: TcpStack> Drop for SslTcpStack<'stack, DelegateStack> {
    fn drop(&mut self) {
        unimplemented!()
    }
}

#[repr(C)]
struct CallbackContext<'a, DelegateStack: TcpStack> {
    socket: usize,
    delegate_socket: &'a mut DelegateStack::TcpSocket,
    stack: *const c_void,
}

struct SslTcpSocketState<DelegateStack: TcpStack> {
    ssl_context: RefCell<Option<SslContext>>,
    delegate_socket: Option<DelegateStack::TcpSocket>,
}

impl<DelegateStack: TcpStack> Default for SslTcpSocketState<DelegateStack> {
    fn default() -> Self {
        SslTcpSocketState {
            ssl_context: RefCell::new(None),
            delegate_socket: None,
        }
    }
}

#[derive(Debug)]
pub struct SslTcpSocket(usize);

use drogue_tls_sys::{ssl_write, ssl_read, ERR_SSL_WANT_READ, ERR_SSL_WANT_WRITE, ERR_SSL_CRYPTO_IN_PROGRESS, ERR_SSL_ASYNC_IN_PROGRESS, ssl_free, ssl_set_bio};

use drogue_tls_sys::types::c_uchar;

impl<'stack, DelegateStack> TcpStack for SslTcpStack<'stack, DelegateStack>
    where
        DelegateStack: TcpStack,
{
    type TcpSocket = SslTcpSocket;
    type Error = TcpStackError<DelegateStack::Error>;

    fn open(&self, mode: Mode) -> Result<Self::TcpSocket, Self::Error> {
        let mut ssl_context = self.config.borrow_mut().new_context().map_err(|_| TcpStackError::UnableToCreateContext)?;
        ssl_context.set_hostname("rsa2048.badssl.com");

        if let Some((index, socket)) = self.sockets
            .borrow_mut()
            .iter_mut()
            .enumerate()
            .find(|(_, e)| matches!( *e.ssl_context.borrow(), None)) {
            let ssl_socket = SslTcpSocket(index);
            let delegate_socket = self.delegate.open(mode).map_err(|e| TcpStackError::Other(e))?;

            socket.delegate_socket.replace(delegate_socket);
            socket.ssl_context.borrow_mut().replace(ssl_context);
            Ok(ssl_socket)
        } else {
            Err(TcpStackError::NoAvailableSockets)
        }
    }

    fn connect(&self, socket: Self::TcpSocket, remote: SocketAddr) -> Result<Self::TcpSocket, Self::Error> {
        let socket_state = &mut self.sockets.borrow_mut()[socket.0];
        let result = if let Some(ref mut ssl_context) = *socket_state.ssl_context.borrow_mut() {
            let delegate_socket = self.delegate.connect(
                socket_state
                    .delegate_socket
                    .take()
                    .unwrap(),
                remote)?;

            socket_state.delegate_socket.replace(delegate_socket);
            //let bio_ptr = &socket as *const _ as *mut c_void;

            unsafe {
                ssl_set_bio(
                    ssl_context.inner_mut(),
                    //&socket_state.callback_context.as_ref().unwrap().socket as *const _ as *mut _,
                    core::ptr::null_mut(),
                    Some(send_f::<DelegateStack>),
                    Some(recv_f::<DelegateStack>),
                    Option::None,
                );
            }

            Ok(socket)
        } else {
            Err(TcpStackError::SocketNotOpen)
        };

        result
    }

    fn is_connected(&self, socket: &Self::TcpSocket) -> Result<bool, Self::Error> {
        let socket_state = &self.sockets.borrow()[socket.0];
        self.delegate.is_connected(&
            socket_state
                .delegate_socket
                .as_ref()
                .unwrap()
        ).map_err(|e| TcpStackError::Other(e))
    }

    fn write(&self, socket: &mut Self::TcpSocket, buffer: &[u8]) -> nb::Result<usize, Self::Error> {
        let mut sockets = self.sockets.borrow_mut();
        let mut socket_state = &mut sockets[socket.0];
        let result = if let Some(ref mut ssl_context) = *socket_state.ssl_context.borrow_mut() {
            let inner_ssl_context = ssl_context.inner_mut();
            let result = unsafe {
                let mut delegate_socket = socket_state.delegate_socket.as_mut().unwrap();
                let cb =
                    self.callback_context(socket,
                                          &mut delegate_socket);
                (*inner_ssl_context).p_bio = &cb as *const _ as *mut _;
                ssl_write(
                    inner_ssl_context,
                    buffer.as_ptr(),
                    buffer.len(),
                )
            };
            if result >= 0 {
                return Ok(result as usize);
            }

            match result {
                ERR_SSL_WANT_READ => Err(nb::Error::from(TcpStackError::WantRead)),
                ERR_SSL_WANT_WRITE => Err(nb::Error::from(TcpStackError::WantWrite)),
                ERR_SSL_ASYNC_IN_PROGRESS => Err(nb::Error::from(TcpStackError::AsyncInProgress)),
                ERR_SSL_CRYPTO_IN_PROGRESS => Err(nb::Error::from(TcpStackError::CryptoInProgress)),
                _ => {
                    log::error!("error from ssl_write {}", result);
                    Err(nb::Error::from(TcpStackError::Unknown(result)))
                }
            }
        } else {
            Err(nb::Error::from(TcpStackError::SocketNotOpen))
        };

        result
    }

    fn read(&self, socket: &mut Self::TcpSocket, buffer: &mut [u8]) -> nb::Result<usize, Self::Error> {
        let mut sockets = self.sockets.borrow_mut();
        let socket_state = &mut sockets[socket.0];
        let result = if let Some(ref mut ssl_context) = *socket_state.ssl_context.borrow_mut() {
            let inner_ssl_context = ssl_context.inner_mut();
            let result = unsafe {
                let mut delegate_socket = socket_state.delegate_socket.as_mut().unwrap();
                let cb =
                    self.callback_context(socket,
                                          &mut delegate_socket);
                (*inner_ssl_context).p_bio = &cb as *const _ as *mut _;
                log::info!("about to ssl_read");
                ssl_read(ssl_context.inner_mut(),
                         buffer.as_mut_ptr(),
                         buffer.len(),
                )
            };
            log::info!("ssl read ret {}", result);

            if result >= 0 {
                return Ok(result as usize);
            }

            match result {
                ERR_SSL_WANT_READ => Err(nb::Error::Other(TcpStackError::WantRead)),
                ERR_SSL_WANT_WRITE => Err(nb::Error::Other(TcpStackError::WantWrite)),
                ERR_SSL_ASYNC_IN_PROGRESS => Err(nb::Error::Other(TcpStackError::AsyncInProgress)),
                ERR_SSL_CRYPTO_IN_PROGRESS => Err(nb::Error::Other(TcpStackError::CryptoInProgress)),
                _ => Err(nb::Error::Other(TcpStackError::Unknown(result)))
            }
        } else {
            Err(nb::Error::from(TcpStackError::SocketNotOpen))
        };

        result
    }

    fn close(&self, socket: Self::TcpSocket) -> Result<(), Self::Error> {
        let mut sockets = self.sockets.borrow_mut();
        let socket_state = &mut sockets[socket.0];

        let result = self.delegate.close(
            socket_state
                .delegate_socket
                .take()
                .unwrap()
        ).map_err(|e| TcpStackError::Other(e));

        let mut opt = socket_state.ssl_context.borrow_mut();
        match *opt {
            None => {}
            Some(ref mut ssl_context) => {
                unsafe {
                    ssl_free(ssl_context.inner_mut())
                };
                opt.take();
            }
        }
        result
    }
}

use drogue_tls_sys::types::{
    c_void,
    c_int,
};
use core::{slice, fmt};
use nb::Error;
use core::intrinsics::transmute;
use core::fmt::{Debug, Formatter};
use core::borrow::BorrowMut;


struct Bio<'a, DelegateStack: TcpStack> {
    stack: &'a DelegateStack,
    socket: &'a mut DelegateStack::TcpSocket,
}

extern "C" fn send_f<DelegateStack: TcpStack>(ctx: *mut c_void, buf: *const c_uchar, len: usize) -> c_int {
    unsafe {
        let mut ctx = &mut *(ctx as *mut CallbackContext<DelegateStack>);
        let stack = &*(ctx.stack as *const _ as *const SslTcpStack<DelegateStack>);

        let slice = slice::from_raw_parts(buf, len);

        let result = stack.write_through(
            ctx.socket,
            &mut ctx.delegate_socket,
            slice,
        );

        match result {
            Ok(len) => {
                len as c_int
            }
            Err(e) => {
                match e {
                    Error::Other(_) => {
                        -1 as c_int
                    }
                    Error::WouldBlock => {
                        ERR_SSL_WANT_WRITE
                    }
                }
            }
        }
    }
}

extern "C" fn recv_f<DelegateStack: TcpStack>(ctx: *mut c_void, buf: *mut c_uchar, len: usize) -> c_int {
    log::info!("recv_f {}", len);
    unsafe {
        let mut ctx = &mut *(ctx as *mut CallbackContext<DelegateStack>);
        let mut actual_len = len;
        if actual_len > 500 {
            actual_len = 500;
        }
        let stack = &*(ctx.stack as *const _ as *const SslTcpStack<DelegateStack>);

        let slice = slice::from_raw_parts_mut(buf, actual_len);

        let result = stack.read_through(
            ctx.socket,
            &mut ctx.delegate_socket,
            slice,
        );

        match result {
            Ok(len) => {
                len as c_int
            }
            Err(e) => {
                match e {
                    Error::Other(_) => {
                        -1 as c_int
                    }
                    Error::WouldBlock => {
                        ERR_SSL_WANT_READ
                    }
                }
            }
        }
    }
}