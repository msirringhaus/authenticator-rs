use super::{Command, RequestCtap2, Error, StatusCode};
use crate::transport::{Error as TransportError, FidoDevice};
use serde_cbor::{Value, de::from_slice};
use crate::ctap2::commands::get_assertion::GetAssertionResponse;

#[derive(Debug)]
pub(crate) struct GetNextAssertion;

impl RequestCtap2 for GetNextAssertion {
    type Output = GetAssertionResponse;

    fn command() -> Command {
        Command::GetNextAssertion
    }

    fn wire_format<Dev>(&self, dev: &mut Dev) -> Result<Vec<u8>, TransportError>
    where
        Dev: FidoDevice,
    {
        Ok(Vec::new())
    }

    fn handle_response_ctap2<Dev>(
        &self,
        _dev: &mut Dev,
        input: &[u8],
    ) -> Result<Self::Output, TransportError>
    where
        Dev: FidoDevice,
    {
        if input.is_empty() {
            return Err(Error::InputTooSmall).map_err(TransportError::Command);
        }

        let status: StatusCode = input[0].into();
        debug!("response status code: {:?}", status);
        if input.len() > 1 {
            if status.is_ok() {
                let assertion = from_slice(&input[1..]).map_err(Error::Parsing)?;
                // TODO(baloo): check assertion response does not have numberOfCredentials
                Ok(assertion)
            } else {
                let data: Value = from_slice(&input[1..]).map_err(Error::Parsing)?;
                Err(Error::StatusCode(status, Some(data))).map_err(TransportError::Command)
            }
        } else if status.is_ok() {
            Err(Error::InputTooSmall).map_err(TransportError::Command)
        } else {
            Err(Error::StatusCode(status, None)).map_err(TransportError::Command)
        }
    }
}
