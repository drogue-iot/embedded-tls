use generic_array::ArrayLength;

use crate::{
    alert::AlertDescription, common::decrypted_buffer_info::DecryptedBufferInfo,
    handshake::ServerHandshake, record::ServerRecord, TlsError,
};

pub struct DecryptedReadHandler<'a> {
    pub source_buffer_ptr: *const u8,
    pub source_buffer_len: usize,
    pub buffer_info: &'a mut DecryptedBufferInfo,
    pub is_open: &'a mut bool,
}

impl DecryptedReadHandler<'_> {
    pub fn handle<N: ArrayLength<u8>>(
        &mut self,
        record: ServerRecord<'_, N>,
    ) -> Result<(), TlsError> {
        match record {
            ServerRecord::ApplicationData(data) => {
                // SAFETY: Assume `decrypt_record()` to decrypt in-place
                // We have assertions to ensure this is valid.
                let slice = data.data.as_slice();
                let slice_ptr = slice.as_ptr();
                let offset = unsafe { slice_ptr.offset_from(self.source_buffer_ptr) };
                debug_assert!(offset >= 0);
                let offset = offset as usize;
                debug_assert!(offset + slice.len() <= self.source_buffer_len);

                self.buffer_info.offset = offset;
                self.buffer_info.len = slice.len();
                self.buffer_info.consumed = 0;
                Ok(())
            }
            ServerRecord::Alert(alert) => {
                if let AlertDescription::CloseNotify = alert.description {
                    *self.is_open = false;
                    Err(TlsError::ConnectionClosed)
                } else {
                    Err(TlsError::InternalError)
                }
            }
            ServerRecord::ChangeCipherSpec(_) => Err(TlsError::InternalError),
            ServerRecord::Handshake(ServerHandshake::NewSessionTicket(_)) => {
                // Ignore
                Ok(())
            }
            _ => {
                unimplemented!()
            }
        }
    }
}
