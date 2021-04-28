use crate::consts::{SW_CONDITIONS_NOT_SATISFIED, SW_NO_ERROR, SW_WRONG_DATA, SW_WRONG_LENGTH};
use crate::ctap2::commands::Error as CommandError;
use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::path;

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "netbsd"))]
pub mod hidproto;

#[cfg(all(not(test), target_os = "linux"))]
#[path = "linux/mod.rs"]
pub mod platform;

#[cfg(all(not(test), target_os = "freebsd"))]
#[path = "freebsd/mod.rs"]
pub mod platform;

#[cfg(all(not(test), target_os = "netbsd"))]
#[path = "netbsd/mod.rs"]
pub mod platform;

#[cfg(all(not(test), target_os = "openbsd"))]
#[path = "openbsd/mod.rs"]
pub mod platform;

#[cfg(all(not(test), target_os = "macos"))]
#[path = "macos/mod.rs"]
pub mod platform;

#[cfg(all(not(test), target_os = "windows"))]
#[path = "windows/mod.rs"]
pub mod platform;

#[cfg(test)]
#[path = "test/mod.rs"]
pub mod platform;

#[cfg(not(any(
    test,
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos",
    target_os = "windows"
)))]
#[path = "stub/mod.rs"]
pub mod platform;

#[derive(Debug, PartialEq, Eq)]
pub enum ApduErrorStatus {
    ConditionsNotSatisfied,
    WrongData,
    WrongLength,
    Unknown([u8; 2]),
}

impl ApduErrorStatus {
    pub fn from(status: [u8; 2]) -> Result<(), ApduErrorStatus> {
        match status {
            s if s == SW_NO_ERROR => Ok(()),
            s if s == SW_CONDITIONS_NOT_SATISFIED => Err(ApduErrorStatus::ConditionsNotSatisfied),
            s if s == SW_WRONG_DATA => Err(ApduErrorStatus::WrongData),
            s if s == SW_WRONG_LENGTH => Err(ApduErrorStatus::WrongLength),
            other => Err(ApduErrorStatus::Unknown(other)),
        }
    }

    pub fn is_conditions_not_satisfied(&self) -> bool {
        match *self {
            ApduErrorStatus::ConditionsNotSatisfied => true,
            _ => false,
        }
    }
}
impl fmt::Display for ApduErrorStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ApduErrorStatus::ConditionsNotSatisfied => write!(f, "Apdu: condition not satisfied"),
            ApduErrorStatus::WrongData => write!(f, "Apdu: wrong data"),
            ApduErrorStatus::WrongLength => write!(f, "Apdu: wrong length"),
            ApduErrorStatus::Unknown(ref u) => write!(f, "Apdu: unknown error: {:?}", u),
        }
    }
}

impl StdError for ApduErrorStatus {
    fn description(&self) -> &str {
        match *self {
            ApduErrorStatus::ConditionsNotSatisfied => "Apdu: condition not satisfied",
            ApduErrorStatus::WrongData => "Apdu: wrong data",
            ApduErrorStatus::WrongLength => "Apdu: wrong length",
            ApduErrorStatus::Unknown(_) => "Apdu: unknown error",
        }
    }
}

#[derive(Debug)]
pub enum Error {
    /// Transport replied with a status not expected
    DeviceError,
    UnexpectedInitReplyLen,
    NonceMismatch,
    DeviceNotInitialized,
    DeviceNotSupported,
    UnsupportedCommand,
    IO(Option<path::PathBuf>, io::Error),
    UnexpectedCmd(u8),
    Command(CommandError),
    ApduStatus(ApduErrorStatus),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::IO(None, e)
    }
}

impl From<CommandError> for Error {
    fn from(e: CommandError) -> Error {
        Error::Command(e)
    }
}

impl From<ApduErrorStatus> for Error {
    fn from(e: ApduErrorStatus) -> Error {
        Error::ApduStatus(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::UnexpectedInitReplyLen => {
                write!(f, "Error: Unexpected reply len when initilizaling")
            }
            Error::NonceMismatch => write!(f, "Error: Nonce mismatch"),
            Error::DeviceError => write!(f, "Error: device returned error"),
            Error::DeviceNotInitialized => write!(f, "Error: using not initiliazed device"),
            Error::DeviceNotSupported => {
                write!(f, "Error: requested operation is not available on device")
            }
            Error::UnsupportedCommand => {
                write!(f, "Error: command is not supported on this device")
            }
            Error::IO(ref p, ref e) => write!(f, "Error: Ioerror({:?}): {}", p, e),
            Error::Command(ref e) => write!(f, "Error: Error issuing command: {}", e),
            Error::UnexpectedCmd(s) => write!(f, "Error: Unexpected status: {}", s),
            Error::ApduStatus(ref status) => {
                write!(f, "Error: Unexpected apdu status: {:?}", status)
            }
        }
    }
}
