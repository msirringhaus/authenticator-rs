use serde_cbor::{error, Value};
use serde_json::{self as json};
use std::error::Error as StdErrorT;
use std::fmt;

use crate::ctap::{ClientDataHash, Version};
use crate::transport::{ApduErrorStatus, Error as TransportError, FidoDevice};

pub mod get_info;
use get_info::GetInfo;

pub mod client_pin;
use client_pin::{GetKeyAgreement, GetPinToken, Pin, PinAuth, PinError};

pub mod get_assertion;
pub mod get_next_assertion;
pub mod get_version;
pub mod make_credentials;

#[derive(Debug)]
pub enum NSSError {
    ImportCertError,
    DecodingPKCS8Failed,
    InputTooLarge,
    LibraryFailure,
    SignatureVerificationFailed,
    SigningFailed,
    ExtractPublicKeyFailed,
}

pub(crate) trait Request<T>
where
    Self: fmt::Debug,
    Self: RequestCtap1<Output = T>,
    Self: RequestCtap2<Output = T>,
{
    fn maximum_version(&self) -> Version;
    fn minimum_version(&self) -> Version;
}

/// Retryable wraps an error type and may ask manager to retry sending a
/// command, this is useful for ctap1 where token will reply with "condition not
/// sufficient" because user needs to press the button.
pub(crate) enum Retryable<T> {
    Retry,
    Error(T),
}

impl<T> Retryable<T> {
    pub fn is_retry(&self) -> bool {
        match *self {
            Retryable::Retry => true,
            _ => false,
        }
    }

    pub fn is_error(&self) -> bool {
        !self.is_retry()
    }
}

impl<T> From<T> for Retryable<T> {
    fn from(e: T) -> Self {
        Retryable::Error(e)
    }
}

pub(crate) trait RequestCtap1: fmt::Debug {
    type Output;

    fn apdu_format<Dev>(&self, dev: &mut Dev) -> Result<Vec<u8>, TransportError>
    where
        Dev: FidoDevice;

    fn handle_response_ctap1(
        &self,
        status: Result<(), ApduErrorStatus>,
        input: &[u8],
    ) -> Result<Self::Output, Retryable<TransportError>>;
}

pub(crate) trait RequestCtap2: fmt::Debug {
    type Output;

    fn command() -> Command;

    fn wire_format<Dev>(&self, dev: &mut Dev) -> Result<Vec<u8>, TransportError>
    where
        Dev: FidoDevice;

    fn handle_response_ctap2<Dev>(
        &self,
        dev: &mut Dev,
        input: &[u8],
    ) -> Result<Self::Output, TransportError>
    where
        Dev: FidoDevice;
}

trait RequestWithPin: RequestCtap2 {
    fn pin(&self) -> Option<&Pin>;
    fn client_data_hash(&self) -> Result<ClientDataHash, Error>;
}

// Spec: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticator-api
#[repr(u8)]
#[derive(Debug)]
pub enum Command {
    MakeCredentials = 0x01,
    GetAssertion = 0x02,
    GetInfo = 0x04,
    ClientPin = 0x06,
    Reset = 0x07,
    GetNextAssertion = 0x08,
}

impl Command {
    #[cfg(test)]
    pub fn from_u8(v: u8) -> Option<Command> {
        match v {
            0x01 => Some(Command::MakeCredentials),
            0x02 => Some(Command::GetAssertion),
            0x04 => Some(Command::GetInfo),
            0x06 => Some(Command::ClientPin),
            0x07 => Some(Command::Reset),
            0x08 => Some(Command::GetNextAssertion),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum StatusCode {
    /// Indicates successful response.
    OK,
    /// The command is not a valid CTAP command.
    InvalidCommand,
    /// The command included an invalid parameter.
    InvalidParameter,
    /// Invalid message or item length.
    InvalidLength,
    /// Invalid message sequencing.
    InvalidSeq,
    /// Message timed out.
    Timeout,
    /// Channel busy.
    ChannelBusy,
    /// Command requires channel lock.
    LockRequired,
    /// Command not allowed on this cid.
    InvalidChannel,
    /// Invalid/unexpected CBOR error.
    CBORUnexpectedType,
    /// Error when parsing CBOR.
    InvalidCBOR,
    /// Missing non-optional parameter.
    MissingParameter,
    /// Limit for number of items exceeded.
    LimitExceeded,
    /// Unsupported extension.
    UnsupportedExtension,
    /// Valid credential found in the exclude list.
    CredentialExcluded,
    /// Processing (Lengthy operation is in progress).
    Processing,
    /// Credential not valid for the authenticator.
    InvalidCredential,
    /// Authentication is waiting for user interaction.
    UserActionPending,
    /// Processing, lengthy operation is in progress.
    OperationPending,
    /// No request is pending.
    NoOperations,
    /// Authenticator does not support requested algorithm.
    UnsupportedAlgorithm,
    /// Not authorized for requested operation.
    OperationDenied,
    /// Internal key storage is full.
    KeyStoreFull,
    /// No outstanding operations.
    NoOperationPending,
    /// Unsupported option.
    UnsupportedOption,
    /// Not a valid option for current operation.
    InvalidOption,
    /// Pending keep alive was cancelled.
    KeepaliveCancel,
    /// No valid credentials provided.
    NoCredentials,
    /// Timeout waiting for user interaction.
    UserActionTimeout,
    /// Continuation command, such as, authenticatorGetNextAssertion not
    /// allowed.
    NotAllowed,
    /// PIN Invalid.
    PinInvalid,
    /// PIN Blocked.
    PinBlocked,
    /// PIN authentication,pinAuth, verification failed.
    PinAuthInvalid,
    /// PIN authentication,pinAuth, blocked. Requires power recycle to reset.
    PinAuthBlocked,
    /// No PIN has been set.
    PinNotSet,
    /// PIN is required for the selected operation.
    PinRequired,
    /// PIN policy violation. Currently only enforces minimum length.
    PinPolicyViolation,
    /// pinToken expired on authenticator.
    PinTokenExpired,
    /// Authenticator cannot handle this request due to memory constraints.
    RequestTooLarge,
    /// The current operation has timed out.
    ActionTimeout,
    /// User presence is required for the requested operation.
    UpRequired,

    /// Unknown status.
    Unknown(u8),
}

impl StatusCode {
    fn is_ok(&self) -> bool {
        match *self {
            StatusCode::OK => true,
            _ => false,
        }
    }

    fn device_busy(&self) -> bool {
        match *self {
            StatusCode::ChannelBusy => true,
            _ => false,
        }
    }
}

impl From<u8> for StatusCode {
    fn from(value: u8) -> StatusCode {
        match value {
            0x00 => StatusCode::OK,
            0x01 => StatusCode::InvalidCommand,
            0x02 => StatusCode::InvalidParameter,
            0x03 => StatusCode::InvalidLength,
            0x04 => StatusCode::InvalidSeq,
            0x05 => StatusCode::Timeout,
            0x06 => StatusCode::ChannelBusy,
            0x0A => StatusCode::LockRequired,
            0x0B => StatusCode::InvalidChannel,
            0x11 => StatusCode::CBORUnexpectedType,
            0x12 => StatusCode::InvalidCBOR,
            0x14 => StatusCode::MissingParameter,
            0x15 => StatusCode::LimitExceeded,
            0x16 => StatusCode::UnsupportedExtension,
            0x19 => StatusCode::CredentialExcluded,
            0x21 => StatusCode::Processing,
            0x22 => StatusCode::InvalidCredential,
            0x23 => StatusCode::UserActionPending,
            0x24 => StatusCode::OperationPending,
            0x25 => StatusCode::NoOperations,
            0x26 => StatusCode::UnsupportedAlgorithm,
            0x27 => StatusCode::OperationDenied,
            0x28 => StatusCode::KeyStoreFull,
            0x2A => StatusCode::NoOperationPending,
            0x2B => StatusCode::UnsupportedOption,
            0x2C => StatusCode::InvalidOption,
            0x2D => StatusCode::KeepaliveCancel,
            0x2E => StatusCode::NoCredentials,
            0x2f => StatusCode::UserActionTimeout,
            0x30 => StatusCode::NotAllowed,
            0x31 => StatusCode::PinInvalid,
            0x32 => StatusCode::PinBlocked,
            0x33 => StatusCode::PinAuthInvalid,
            0x34 => StatusCode::PinAuthBlocked,
            0x35 => StatusCode::PinNotSet,
            0x36 => StatusCode::PinRequired,
            0x37 => StatusCode::PinPolicyViolation,
            0x38 => StatusCode::PinTokenExpired,
            0x39 => StatusCode::RequestTooLarge,
            0x3A => StatusCode::ActionTimeout,
            0x3B => StatusCode::UpRequired,

            othr => StatusCode::Unknown(othr),
        }
    }
}

#[cfg(test)]
impl Into<u8> for StatusCode {
    fn into(self) -> u8 {
        match self {
            StatusCode::OK => 0x00,
            StatusCode::InvalidCommand => 0x01,
            StatusCode::InvalidParameter => 0x02,
            StatusCode::InvalidLength => 0x03,
            StatusCode::InvalidSeq => 0x04,
            StatusCode::Timeout => 0x05,
            StatusCode::ChannelBusy => 0x06,
            StatusCode::LockRequired => 0x0A,
            StatusCode::InvalidChannel => 0x0B,
            StatusCode::CBORUnexpectedType => 0x11,
            StatusCode::InvalidCBOR => 0x12,
            StatusCode::MissingParameter => 0x14,
            StatusCode::LimitExceeded => 0x15,
            StatusCode::UnsupportedExtension => 0x16,
            StatusCode::CredentialExcluded => 0x19,
            StatusCode::Processing => 0x21,
            StatusCode::InvalidCredential => 0x22,
            StatusCode::UserActionPending => 0x23,
            StatusCode::OperationPending => 0x24,
            StatusCode::NoOperations => 0x25,
            StatusCode::UnsupportedAlgorithm => 0x26,
            StatusCode::OperationDenied => 0x27,
            StatusCode::KeyStoreFull => 0x28,
            StatusCode::NoOperationPending => 0x2A,
            StatusCode::UnsupportedOption => 0x2B,
            StatusCode::InvalidOption => 0x2C,
            StatusCode::KeepaliveCancel => 0x2D,
            StatusCode::NoCredentials => 0x2E,
            StatusCode::UserActionTimeout => 0x2f,
            StatusCode::NotAllowed => 0x30,
            StatusCode::PinInvalid => 0x31,
            StatusCode::PinBlocked => 0x32,
            StatusCode::PinAuthInvalid => 0x33,
            StatusCode::PinAuthBlocked => 0x34,
            StatusCode::PinNotSet => 0x35,
            StatusCode::PinRequired => 0x36,
            StatusCode::PinPolicyViolation => 0x37,
            StatusCode::PinTokenExpired => 0x38,
            StatusCode::RequestTooLarge => 0x39,
            StatusCode::ActionTimeout => 0x3A,
            StatusCode::UpRequired => 0x3B,

            StatusCode::Unknown(othr) => othr,
        }
    }
}

/// Internal struct to serialize command that may need to serialize differently
/// depending on the device (pin_token, ...)
struct CommandDevice<'command, Command> {
    command: &'command Command,
    pin_auth: Option<PinAuth>,
}

impl<'command, Command> CommandDevice<'command, Command>
where
    Command: RequestWithPin,
{
    fn new<Dev>(dev: &mut Dev, command: &'command Command) -> Result<Self, TransportError>
    where
        Dev: FidoDevice,
    {
        let info = if let Some(authenticator_info) = dev.authenticator_info().cloned() {
            authenticator_info
        } else {
            let info_command = GetInfo::default();
            let info = dev.send_cbor(&info_command)?;
            debug!("infos: {:?}", info);

            dev.set_authenticator_info(info.clone());
            info
        };

        let pin_auth = if info.client_pin_set() {
            let pin = if let Some(pin) = command.pin() {
                pin
            } else {
                return Err(Error::StatusCode(StatusCode::PinRequired, None).into());
            };

            let shared_secret = if let Some(shared_secret) = dev.shared_secret().cloned() {
                shared_secret
            } else {
                let pin_command = GetKeyAgreement::new(&info)?;
                let device_key_agreement = dev.send_cbor(&pin_command)?;
                let shared_secret = device_key_agreement.shared_secret()?;
                dev.set_shared_secret(shared_secret.clone());
                shared_secret
            };

            let pin_command = GetPinToken::new(&info, &shared_secret, &pin)?;
            let pin_token = dev.send_cbor(&pin_command)?;

            Some(
                pin_token
                    .auth(&command.client_data_hash()?)
                    .map_err(Error::Pin)?,
            )
        } else {
            None
        };

        Ok(Self { command, pin_auth })
    }
}

#[derive(Debug)]
pub enum Error {
    InputTooSmall,
    UnsupportedPinProtocol,
    ECDH,
    MissingRequiredField(&'static str),
    Parsing(error::Error),
    Serialization(error::Error),
    Cose(cose::CoseError),
    StatusCode(StatusCode, Option<Value>),
    NSS(NSSError),
    Pin(PinError),
    Json(json::Error),
}

impl Error {
    pub fn device_busy(&self) -> bool {
        match *self {
            Error::StatusCode(ref s, _) => s.device_busy(),
            _ => false,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InputTooSmall => write!(f, "CommandError: Input is too small"),
            Error::ECDH => write!(f, "CommandError: ecdh error"),
            Error::UnsupportedPinProtocol => {
                write!(f, "CommandError: Pin protocol is not supported")
            }
            Error::MissingRequiredField(field) => {
                write!(f, "CommandError: Missing required field {}", field)
            }
            Error::Parsing(ref e) => write!(f, "CommandError: Error while parsing: {}", e),
            Error::Serialization(ref e) => {
                write!(f, "CommandError: Error while serializing: {}", e)
            }
            Error::Cose(ref e) => write!(f, "CommandError: COSE: {:?}", e),
            Error::NSS(ref e) => write!(f, "CommandError: NSS: {:?}", e),
            Error::StatusCode(ref code, ref value) => {
                write!(f, "CommandError: Unexpected code: {:?} ({:?})", code, value)
            }
            Error::Pin(ref p) => write!(f, "CommandError: Pin error: {}", p),
            Error::Json(ref e) => write!(f, "CommandError: Json serializing error: {}", e),
        }
    }
}

impl StdErrorT for Error {}

impl From<error::Error> for Error {
    fn from(e: error::Error) -> Error {
        Error::Parsing(e)
    }
}

impl From<cose::CoseError> for Error {
    fn from(e: cose::CoseError) -> Error {
        Error::Cose(e)
    }
}

impl From<NSSError> for Error {
    fn from(e: NSSError) -> Error {
        Error::NSS(e)
    }
}

#[cfg(test)]
pub mod test {
    use serde_cbor::de::from_slice;

    use super::{get_info::AuthenticatorInfo};
    use crate::ctap::{CollectedClientData, Origin, WebauthnType};
    use crate::ctap2::commands::make_credentials::MakeCredentials;
    use crate::ctap2::server::{
        Alg, PublicKeyCredentialParameters, RelyingParty, RelyingPartyData, User,
    };
    //     use crate::transport::hid::HIDDevice;
    //     use crate::transport::platform::device::Device;
    use crate::platform::device::Device;
    //     use crate::transport::platform::TestCase;

    pub const MAKE_CREDENTIALS_SAMPLE_RESPONSE: [u8; 666] =
        include!("tests/MAKE_CREDENTIALS_SAMPLE_RESPONSE,in");

    #[test]
    fn parse_response() {
        let challenge = vec![0, 1, 2, 3];
        let req = MakeCredentials::new(
            CollectedClientData {
                type_: WebauthnType::Create,
                challenge: challenge.clone().into(),
                origin: Origin::Some(String::from("https://www.example.com")),
                token_binding: None,
            },
            RelyingParty::Data(RelyingPartyData {
                id: String::from("example.com"),
            }),
            Some(User {
                id: vec![0],
                icon: None,
                name: String::from("j.doe"),
                display_name: None,
            }),
            vec![PublicKeyCredentialParameters { alg: Alg::ES256 }],
            Vec::new(),
            None,
            None,
        );
        let mut device = Device::new(TestCase::WriteError).unwrap();
        let reply = req.handle_response(&mut device, &MAKE_CREDENTIALS_SAMPLE_RESPONSE[..]);

        assert!(reply.is_ok());
        let (reply, _) = reply.unwrap();

        assert_eq!(
            &reply.auth_data.rp_id_hash.0,
            &[
                0xc2, 0x89, 0xc5, 0xca, 0x9b, 0x04, 0x60, 0xf9, 0x34, 0x6a, 0xb4, 0xe4, 0x2d, 0x84,
                0x27, 0x43, 0x40, 0x4d, 0x31, 0xf4, 0x84, 0x68, 0x25, 0xa6, 0xd0, 0x65, 0xbe, 0x59,
                0x7a, 0x87, 0x5, 0x1d
            ]
        );
    }

    pub const AUTHENTICATOR_INFO_PAYLOAD: [u8; 85] =
        include!("tests/AUTHENTICATOR_INFO_PAYLOAD.in");

    #[test]
    fn parse_authenticator_info() {
        let authenticator_info: AuthenticatorInfo =
            from_slice(&AUTHENTICATOR_INFO_PAYLOAD[..]).unwrap();

        println!("authenticator_info {:?}", authenticator_info);
        //assert_eq!(true, false);
    }
}
