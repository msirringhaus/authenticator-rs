use super::{Error, RequestCtap1, Retryable};
use crate::consts::U2F_VERSION;
use crate::transport::{ApduErrorStatus, Error as TransportError, FidoDevice};
use crate::u2ftypes::U2FAPDUHeader;
use std::ffi::CString;
use std::io;

pub enum U2FInfo {
    U2F_V2,
}

#[derive(Debug)]
// TODO(baloo): if one does not issue U2F_VERSION before makecredentials or getassertion, token
//              will return error (ConditionsNotSatified), test this in unit tests
pub struct GetVersion {}

impl Default for GetVersion {
    fn default() -> GetVersion {
        GetVersion {}
    }
}

impl RequestCtap1 for GetVersion {
    type Output = U2FInfo;

    fn handle_response_ctap1(
        &self,
        _status: Result<(), ApduErrorStatus>,
        input: &[u8],
    ) -> Result<Self::Output, Retryable<TransportError>> {
        if input.is_empty() {
            return Err(Error::InputTooSmall)
                .map_err(TransportError::Command)
                .map_err(Retryable::Error);
        }

        let expected = CString::new("U2F_V2")
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "null data in version"))
            .map_err(|e| TransportError::IO(None, e))
            .map_err(Retryable::Error)?;

        match CString::new(input)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "null data in version"))
            .map_err(|e| TransportError::IO(None, e))
            .map_err(Retryable::Error)?
        {
            ref data if data == &expected => Ok(U2FInfo::U2F_V2),
            _ => Err(io::Error::new(io::ErrorKind::Other, "unexpected version"))
                .map_err(|e| TransportError::IO(None, e))
                .map_err(Retryable::Error),
        }
    }

    fn apdu_format<Dev>(&self, _dev: &mut Dev) -> Result<Vec<u8>, TransportError>
    where
        Dev: FidoDevice,
    {
        let flags = 0;

        let cmd = U2F_VERSION;
        let apdu = U2FAPDUHeader::serialize(cmd, flags, &[])?;

        Ok(apdu)
    }
}
