/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![cfg_attr(feature = "cargo-clippy", allow(clippy::needless_lifetimes))]

extern crate std;

use crate::consts::*;
use crate::ctap2::send_apdu;
use crate::u2ftypes::*;
use crate::util::io_err;
use std::io;
use std::io::{Read, Write};

////////////////////////////////////////////////////////////////////////
// Device Commands
////////////////////////////////////////////////////////////////////////

pub fn u2f_register<T>(dev: &mut T, challenge: &[u8], application: &[u8]) -> io::Result<Vec<u8>>
where
    T: U2FDevice + Read + Write,
{
    if challenge.len() != PARAMETER_SIZE || application.len() != PARAMETER_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid parameter sizes",
        ));
    }

    let mut register_data = Vec::with_capacity(2 * PARAMETER_SIZE);
    register_data.extend(challenge);
    register_data.extend(application);

    let flags = U2F_REQUEST_USER_PRESENCE;
    let (resp, status) = send_apdu(dev, U2F_REGISTER, flags, &register_data)?;
    status_word_to_result(status, resp)
}

pub fn u2f_sign<T>(
    dev: &mut T,
    challenge: &[u8],
    application: &[u8],
    key_handle: &[u8],
) -> io::Result<Vec<u8>>
where
    T: U2FDevice + Read + Write,
{
    if challenge.len() != PARAMETER_SIZE || application.len() != PARAMETER_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid parameter sizes",
        ));
    }

    if key_handle.len() > 256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Key handle too large",
        ));
    }

    let mut sign_data = Vec::with_capacity(2 * PARAMETER_SIZE + 1 + key_handle.len());
    sign_data.extend(challenge);
    sign_data.extend(application);
    sign_data.push(key_handle.len() as u8);
    sign_data.extend(key_handle);

    let flags = U2F_REQUEST_USER_PRESENCE;
    let (resp, status) = send_apdu(dev, U2F_AUTHENTICATE, flags, &sign_data)?;
    status_word_to_result(status, resp)
}

pub fn u2f_is_keyhandle_valid<T>(
    dev: &mut T,
    challenge: &[u8],
    application: &[u8],
    key_handle: &[u8],
) -> io::Result<bool>
where
    T: U2FDevice + Read + Write,
{
    if challenge.len() != PARAMETER_SIZE || application.len() != PARAMETER_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid parameter sizes",
        ));
    }

    if key_handle.len() > 256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Key handle too large",
        ));
    }

    let mut sign_data = Vec::with_capacity(2 * PARAMETER_SIZE + 1 + key_handle.len());
    sign_data.extend(challenge);
    sign_data.extend(application);
    sign_data.push(key_handle.len() as u8);
    sign_data.extend(key_handle);

    let flags = U2F_CHECK_IS_REGISTERED;
    let (_, status) = send_apdu(dev, U2F_AUTHENTICATE, flags, &sign_data)?;
    Ok(status == SW_CONDITIONS_NOT_SATISFIED)
}

////////////////////////////////////////////////////////////////////////
// Error Handling
////////////////////////////////////////////////////////////////////////

pub(crate) fn status_word_to_result<T>(status: [u8; 2], val: T) -> io::Result<T> {
    use self::io::ErrorKind::{InvalidData, InvalidInput};

    match status {
        SW_NO_ERROR => Ok(val),
        SW_WRONG_DATA => Err(io::Error::new(InvalidData, "wrong data")),
        SW_WRONG_LENGTH => Err(io::Error::new(InvalidInput, "wrong length")),
        SW_CONDITIONS_NOT_SATISFIED => Err(io_err("conditions not satisfied")),
        _ => Err(io_err(&format!("failed with status {:?}", status))),
    }
}
