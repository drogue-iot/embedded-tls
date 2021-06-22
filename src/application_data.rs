use crate::parse_buffer::ParseBuffer;
use crate::{AsyncRead, AsyncWrite, TlsError};
use core::fmt::{Debug, Formatter};
use heapless::{consts::*, Vec};

pub struct ApplicationData {
    pub(crate) header: Vec<u8, U16>,
    pub(crate) data: Vec<u8, U4096>,
}

impl Debug for ApplicationData {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "ApplicationData {:x?}", self.data)
    }
}

impl ApplicationData {
    pub async fn read<T: AsyncRead>(
        socket: &mut T,
        len: u16,
        header: &[u8],
    ) -> Result<Self, TlsError> {
        info!("application data of len={}", len);
        //let mut buf: [u8; 8192] = [0; 8192];
        let mut buf = Vec::<u8, U4096>::new();
        buf.resize(len as usize, 0);

        let mut num_read = 0;

        loop {
            info!(
                "Reading {} bytes of app data from socket",
                len as usize - num_read
            );
            num_read += socket
                .read(&mut buf[num_read..len as usize])
                .await
                .map_err(|e| {
                    error!("Read socket error: {:?}", e);
                    TlsError::InvalidApplicationData
                })?;

            info!("READ app data");

            if num_read == len as usize {
                info!("read application data fully");
                break;
            }
        }
        Ok(Self {
            header: Vec::from_slice(header).unwrap(),
            data: buf,
            //data: Vec::from_slice(&buf[0..len as usize])
            //.map_err(|_| TlsError::InvalidApplicationData)?,
        })
    }

    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, TlsError> {
        let mut app = ApplicationData {
            header: Vec::new(),
            data: Vec::new(),
        };
        app.data.resize(buf.remaining(), 0);
        buf.fill(&mut app.data[..])
            .map_err(|_| TlsError::InvalidApplicationData)?;
        Ok(app)
    }
}
