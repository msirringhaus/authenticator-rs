use super::{
    ApduFormat, Command, CommandDevice, Error, Request, RequestCtap1, RequestCtap2, RequestWithPin,
    Retryable, StatusCode,
};
use crate::consts::{
    PARAMETER_SIZE, U2F_AUTHENTICATE, U2F_CHECK_IS_REGISTERED, U2F_REQUEST_USER_PRESENCE,
};
use crate::ctap::CollectedClientData;
use crate::ctap::{ClientDataHash, Version};
use crate::ctap2::attestation::{AuthenticatorData, AuthenticatorDataFlags};
use crate::ctap2::commands::client_pin::Pin;
use crate::ctap2::commands::get_next_assertion::GetNextAssertion;
use crate::ctap2::commands::make_credentials::{MakeCredentialsOptions, UserValidation};
use crate::ctap2::server::{PublicKeyCredentialDescriptor, RelyingParty, User};
use crate::transport::{ApduErrorStatus, Error as TransportError};
use crate::u2fprotocol::{send_apdu, send_cbor};
use crate::u2ftypes::U2FDevice;
use nom::{
    do_parse, named,
    number::complete::{be_u32, be_u8},
};
use serde::{
    de::{Error as DesError, MapAccess, Visitor},
    ser::{Error as SerError, SerializeMap},
    Deserialize, Deserializer, Serialize, Serializer,
};
use serde_bytes::ByteBuf;
use serde_cbor::{de::from_slice, ser, Value};
use serde_json::{value as json_value, Map};
use std::fmt;
use std::io;

#[derive(Debug)]
pub struct GetAssertion {
    client_data: CollectedClientData,
    rp: RelyingParty,
    allow_list: Vec<PublicKeyCredentialDescriptor>,

    // https://www.w3.org/TR/webauthn/#client-extension-input
    // The client extension input, which is a value that can be encoded in JSON,
    // is passed from the WebAuthn Relying Party to the client in the get() or
    // create() call, while the CBOR authenticator extension input is passed
    // from the client to the authenticator for authenticator extensions during
    // the processing of these calls.
    extensions: Map<String, json_value::Value>,
    options: Option<MakeCredentialsOptions>,

    pin: Option<Pin>,
}

impl GetAssertion {
    pub fn new(
        client_data: CollectedClientData,
        rp: RelyingParty,
        allow_list: Vec<PublicKeyCredentialDescriptor>,
        options: Option<MakeCredentialsOptions>,
        pin: Option<Pin>,
    ) -> Self {
        Self {
            client_data,
            rp,
            allow_list,
            // TODO(baloo): need to sort those out once final api is in
            extensions: Map::new(),
            options,
            pin,
        }
    }
}

impl<'command> Serialize for CommandDevice<'command, GetAssertion> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let command = &self.command;
        let pin_auth = &self.pin_auth;

        // Need to define how many elements are going to be in the map
        // beforehand
        let mut map_len = 2;
        if !command.allow_list.is_empty() {
            map_len += 1;
        }
        if !command.extensions.is_empty() {
            map_len += 1;
        }
        if command.options.is_some() {
            map_len += 1;
        }
        if pin_auth.is_some() {
            map_len += 2;
        }

        let mut map = serializer.serialize_map(Some(map_len))?;
        match command.rp {
            RelyingParty::Data(ref d) => {
                map.serialize_entry(&1, &d)?;
            }
            _ => {
                return Err(S::Error::custom(
                    "Can't serialize a RelyingParty::Hash for ctap2",
                ));
            }
        }

        let client_data_hash = command
            .client_data
            .hash()
            .map_err(|e| S::Error::custom(format!("error while hashing client data: {}", e)))?;
        map.serialize_entry(&2, &client_data_hash)?;
        if !command.allow_list.is_empty() {
            map.serialize_entry(&3, &command.allow_list)?;
        }
        if !command.extensions.is_empty() {
            map.serialize_entry(&4, &command.extensions)?;
        }
        if command.options.is_some() {
            map.serialize_entry(&5, &command.options)?;
        }
        if let Some(pin_auth) = pin_auth {
            map.serialize_entry(&6, &pin_auth)?;
            map.serialize_entry(&7, &1)?;
        }
        map.end()
    }
}

impl Request<AssertionObject> for GetAssertion {
    fn maximum_version(&self) -> Version {
        if self.rp.is_hash() {
            return Version::CTAP1;
        }

        Version::CTAP2
    }

    fn minimum_version(&self) -> Version {
        Version::CTAP1
    }
}

impl RequestCtap1 for GetAssertion {
    type Output = AssertionObject;

    fn apdu_format<Dev>(&self, dev: &mut Dev) -> Result<ApduFormat, TransportError>
    where
        Dev: U2FDevice + io::Read + io::Write + fmt::Debug,
    {
        /// This command is used to check which key_handle is valid for this
        /// token this is sent before a GetAssertion command, to determine which
        /// is valid for a specific token and which key_handle GetAssertion
        /// should send to the token.
        #[derive(Debug)]
        struct GetAssertionCheck<'assertion> {
            key_handle: &'assertion [u8],
            client_data: &'assertion CollectedClientData,
            rp: &'assertion RelyingParty,
        }

        impl<'assertion> RequestCtap1 for GetAssertionCheck<'assertion> {
            type Output = ();

            fn apdu_format<Dev>(&self, _dev: &mut Dev) -> Result<ApduFormat, TransportError>
            where
                Dev: U2FDevice + io::Read + io::Write + fmt::Debug,
            {
                let flags = U2F_CHECK_IS_REGISTERED;
                let mut auth_data = Vec::with_capacity(
                    2 * PARAMETER_SIZE + 1 /* key_handle_len */ + self.key_handle.len(),
                );

                auth_data.extend_from_slice(self.client_data.challenge.as_ref());
                auth_data.extend_from_slice(self.rp.hash().as_ref());
                auth_data.extend_from_slice(&[self.key_handle.len() as u8]);
                auth_data.extend_from_slice(self.key_handle);

                let cmd = U2F_AUTHENTICATE;
                // let apdu = U2FAPDUHeader::serialize(cmd, flags, &auth_data)?;

                Ok(ApduFormat {
                    cmd,
                    flags,
                    data: auth_data,
                })
            }

            fn handle_response_ctap1(
                &self,
                status: Result<(), ApduErrorStatus>,
                _input: &[u8],
            ) -> Result<Self::Output, Retryable<TransportError>> {
                match status {
                    Err(ref status) if status.is_conditions_not_satisfied() => Ok(()),
                    _ => Err(Retryable::Error(TransportError::DeviceError)),
                }
            }
        }

        let key_handle = self
            .allow_list
            .iter()
            .find_map(|allowed_handle| {
                let check_command = GetAssertionCheck {
                    key_handle: allowed_handle.id.as_ref(),
                    client_data: &self.client_data,
                    rp: &self.rp,
                };
                let af = check_command.apdu_format(dev).ok()?;
                match send_apdu(dev, af.cmd, af.flags, &af.data) {
                    Ok(_) => Some(allowed_handle.id.clone()),
                    _ => None,
                }
            })
            .ok_or(TransportError::DeviceNotSupported)?;

        debug!("sending key_handle = {:?}", key_handle);

        let flags = if self.options.ask_user_validation() {
            U2F_REQUEST_USER_PRESENCE
        } else {
            0
        };
        let mut auth_data =
            Vec::with_capacity(2 * PARAMETER_SIZE + 1 /* key_handle_len */ + key_handle.len());

        auth_data.extend_from_slice(self.client_data.challenge.as_ref());
        auth_data.extend_from_slice(self.rp.hash().as_ref());
        auth_data.extend_from_slice(&[key_handle.len() as u8]);
        auth_data.extend_from_slice(key_handle.as_ref());

        let cmd = U2F_AUTHENTICATE;

        Ok(ApduFormat {
            cmd,
            flags,
            data: auth_data,
        })
    }

    fn handle_response_ctap1(
        &self,
        status: Result<(), ApduErrorStatus>,
        input: &[u8],
    ) -> Result<Self::Output, Retryable<TransportError>> {
        if Err(ApduErrorStatus::ConditionsNotSatisfied) == status {
            return Err(Retryable::Retry);
        }
        if status.is_err() {
            return Err(Retryable::Error(TransportError::DeviceError));
        }

        named!(
            parse_authentication<(u8, u32)>,
            do_parse!(user_presence: be_u8 >> counter: be_u32 >> (user_presence, counter))
        );

        let (user_presence, counter, signature) = match parse_authentication(input) {
            Ok((input, (user_presence, counter))) => {
                let signature = Vec::from(input);
                Ok((user_presence, counter, signature))
            }
            Err(e) => {
                error!("error while parsing authentication: {:?}", e);
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    "unable to parse authentication",
                ))
                .map_err(|e| TransportError::IO(None, e))
                .map_err(Retryable::Error)
            }
        }?;

        let mut flags = AuthenticatorDataFlags::empty();
        if user_presence == 1 {
            flags |= AuthenticatorDataFlags::USER_PRESENT;
        }
        let auth_data = AuthenticatorData {
            rp_id_hash: self.rp.hash(),
            flags,
            counter,
            credential_data: None,
            extensions: Vec::new(),
        };
        let assertion = Assertion {
            credentials: None,
            signature,
            public_key: None,
            auth_data,
        };

        Ok(AssertionObject(vec![assertion]))
    }
}

impl RequestCtap2 for GetAssertion {
    type Output = AssertionObject;

    fn command() -> Command {
        Command::GetAssertion
    }

    fn wire_format<Dev>(&self, dev: &mut Dev) -> Result<Vec<u8>, TransportError>
    where
        Dev: U2FDevice + io::Read + io::Write + fmt::Debug,
    {
        let cd = CommandDevice::new(dev, self)?;

        Ok(ser::to_vec(&cd).map_err(Error::Serialization)?)
    }

    fn handle_response_ctap2<Dev>(
        &self,
        dev: &mut Dev,
        input: &[u8],
    ) -> Result<Self::Output, TransportError>
    where
        Dev: U2FDevice + io::Read + io::Write + fmt::Debug,
    {
        if input.is_empty() {
            return Err(Error::InputTooSmall).map_err(TransportError::Command);
        }

        let status: StatusCode = input[0].into();
        debug!("response status code: {:?}", status);
        if input.len() > 1 {
            if status.is_ok() {
                let assertion: GetAssertionResponse =
                    from_slice(&input[1..]).map_err(Error::Parsing)?;
                let number_of_credentials = assertion.number_of_credentials.unwrap_or(1);
                let mut assertions = Vec::with_capacity(number_of_credentials);
                assertions.push(assertion.into());

                let msg = GetNextAssertion;
                for _ in (1..number_of_credentials).rev() {
                    let new_cred = send_cbor(dev, &msg)?;
                    assertions.push(new_cred.into());
                }

                Ok(AssertionObject(assertions))
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

impl RequestWithPin for GetAssertion {
    fn pin(&self) -> Option<&Pin> {
        self.pin.as_ref()
    }

    fn client_data_hash(&self) -> Result<ClientDataHash, Error> {
        self.client_data.hash().map_err(Error::Json)
    }
}

#[derive(Debug)]
pub struct Assertion {
    credentials: Option<serde_cbor::Value>,
    auth_data: AuthenticatorData,
    signature: Vec<u8>,
    public_key: Option<User>,
}

impl From<GetAssertionResponse> for Assertion {
    fn from(r: GetAssertionResponse) -> Self {
        Assertion {
            credentials: r.credentials,
            auth_data: r.auth_data,
            signature: r.signature,
            public_key: r.public_key,
        }
    }
}

// TODO(baloo): Move this to src/ctap2/mod.rs?
#[derive(Debug)]
pub struct AssertionObject(Vec<Assertion>);

impl AssertionObject {
    pub fn u2f_sign_data(&self) -> Vec<u8> {
        if let Some(first) = self.0.first() {
            first.signature.clone()
        } else {
            Vec::new()
        }
    }
}

pub(crate) struct GetAssertionResponse {
    credentials: Option<serde_cbor::Value>,
    auth_data: AuthenticatorData,
    signature: Vec<u8>,
    public_key: Option<User>,
    number_of_credentials: Option<usize>,
}

impl<'de> Deserialize<'de> for GetAssertionResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct GetAssertionResponseVisitor;

        impl<'de> Visitor<'de> for GetAssertionResponseVisitor {
            type Value = GetAssertionResponse;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a byte array")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut credentials = None;
                let mut auth_data = None;
                let mut signature = None;
                let mut public_key = None;
                let mut number_of_credentials = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        1 => {
                            if credentials.is_some() {
                                return Err(M::Error::duplicate_field("credentials"));
                            }
                            credentials = Some(map.next_value()?);
                        }
                        2 => {
                            if auth_data.is_some() {
                                return Err(M::Error::duplicate_field("auth_data"));
                            }
                            auth_data = Some(map.next_value()?);
                        }
                        3 => {
                            if signature.is_some() {
                                return Err(M::Error::duplicate_field("signature"));
                            }
                            let signature_bytes: ByteBuf = map.next_value()?;
                            let signature_bytes: Vec<u8> = signature_bytes.into_vec();
                            signature = Some(signature_bytes);
                        }
                        4 => {
                            if public_key.is_some() {
                                return Err(M::Error::duplicate_field("public_key"));
                            }
                            public_key = map.next_value()?;
                        }
                        5 => {
                            if number_of_credentials.is_some() {
                                return Err(M::Error::duplicate_field("number_of_credentials"));
                            }
                            number_of_credentials = Some(map.next_value()?);
                        }
                        k => return Err(M::Error::custom(format!("unexpected key: {:?}", k))),
                    }
                }

                let auth_data = auth_data.ok_or_else(|| M::Error::missing_field("auth_data"))?;
                let signature = signature.ok_or_else(|| M::Error::missing_field("signature"))?;

                Ok(GetAssertionResponse {
                    credentials,
                    auth_data,
                    signature,
                    public_key,
                    number_of_credentials,
                })
            }
        }

        deserializer.deserialize_bytes(GetAssertionResponseVisitor)
    }
}
