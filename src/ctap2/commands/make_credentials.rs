use super::{
    Command, CommandDevice, Error, Request, RequestCtap1, RequestCtap2, RequestWithPin, Retryable,
    StatusCode,
};
use crate::consts::{PARAMETER_SIZE, U2F_REGISTER, U2F_REQUEST_USER_PRESENCE};
use crate::ctap::CollectedClientData;
use crate::ctap::{ClientDataHash, Version};
use crate::ctap2::attestation::AttestationObject;
use crate::ctap2::commands::client_pin::{Pin};
use crate::ctap2::server::{
    PublicKeyCredentialDescriptor, PublicKeyCredentialParameters, RelyingParty, User,
};
use crate::transport::{ApduErrorStatus, Error as TransportError, FidoDevice};
use crate::u2ftypes::U2FAPDUHeader;


use serde::{
    ser::{Error as SerError, SerializeMap},
    Serialize, Serializer,
};
#[cfg(test)]
use serde::{Deserialize};
use serde_cbor::{self, de::from_slice, ser, Value};
use serde_json::{value as json_value, Map};


#[derive(Copy, Clone, Debug, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
pub struct MakeCredentialsOptions {
    #[serde(rename = "rk")]
    pub resident_key: bool,
    #[serde(rename = "uv")]
    pub user_validation: bool,
}

impl Default for MakeCredentialsOptions {
    fn default() -> Self {
        Self {
            resident_key: false,
            user_validation: true,
        }
    }
}

pub(crate) trait UserValidation {
    fn ask_user_validation(&self) -> bool;
}

impl UserValidation for Option<MakeCredentialsOptions> {
    fn ask_user_validation(&self) -> bool {
        match *self {
            Some(ref e) if e.user_validation => true,
            _ => false,
        }
    }
}

#[derive(Debug)]
pub struct MakeCredentials {
    client_data: CollectedClientData,
    rp: RelyingParty,
    // Note(baloo): If none -> ctap1
    user: Option<User>,
    pub_cred_params: Vec<PublicKeyCredentialParameters>,
    exclude_list: Vec<PublicKeyCredentialDescriptor>,

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

impl MakeCredentials {
    pub fn new(
        client_data: CollectedClientData,
        rp: RelyingParty,
        user: Option<User>,
        pub_cred_params: Vec<PublicKeyCredentialParameters>,
        exclude_list: Vec<PublicKeyCredentialDescriptor>,
        options: Option<MakeCredentialsOptions>,
        pin: Option<Pin>,
    ) -> Self {
        Self {
            client_data,
            rp,
            user,
            pub_cred_params,
            exclude_list,
            // TODO(baloo): need to sort those out once final api is in
            extensions: Map::new(),
            options,
            pin,
        }
    }

    pub(crate) fn handle_response<Dev: FidoDevice>(
        &self,
        dev: &mut Dev,
        input: &[u8],
    ) -> Result<(AttestationObject, CollectedClientData), TransportError> {
        if self.user.is_none() {
            // CTAP 1
            unimplemented!();
        } else {
            // CTAP 2
            self.handle_response_ctap2(dev, input)
        }
    }
}

impl<'command> Serialize for CommandDevice<'command, MakeCredentials> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let command = &self.command;
        let pin_auth = &self.pin_auth;

        // Need to define how many elements are going to be in the map
        // beforehand
        let mut map_len = 4;
        if !command.exclude_list.is_empty() {
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
        let client_data_hash = command
            .client_data
            .hash()
            .map_err(|e| S::Error::custom(format!("error while hashing client data: {}", e)))?;
        map.serialize_entry(&1, &client_data_hash)?;
        match command.rp {
            RelyingParty::Data(ref d) => {
                map.serialize_entry(&2, &d)?;
            }
            _ => {
                return Err(S::Error::custom(
                    "Can't serialize a RelyingParty::Hash for ctap2",
                ));
            }
        }
        map.serialize_entry(&3, &command.user)?;
        map.serialize_entry(&4, &command.pub_cred_params)?;
        if !command.exclude_list.is_empty() {
            map.serialize_entry(&5, &command.exclude_list)?;
        }
        if !command.extensions.is_empty() {
            map.serialize_entry(&6, &command.extensions)?;
        }
        if command.options.is_some() {
            map.serialize_entry(&7, &command.options)?;
        }
        if let Some(pin_auth) = pin_auth {
            map.serialize_entry(&8, &pin_auth)?;
            map.serialize_entry(&9, &1)?;
        }
        map.end()
    }
}

impl Request<(AttestationObject, CollectedClientData)> for MakeCredentials {
    fn maximum_version(&self) -> Version {
        if self.user.is_none() {
            return Version::CTAP1;
        }
        if self.client_data.origin.is_none() {
            return Version::CTAP1;
        }

        Version::CTAP2
    }

    fn minimum_version(&self) -> Version {
        if self.client_data.token_binding.is_some() {
            return Version::CTAP2;
        }

        Version::CTAP1
    }
}

impl RequestCtap1 for MakeCredentials {
    type Output = (AttestationObject, CollectedClientData);

    fn apdu_format<Dev>(&self, _dev: &mut Dev) -> Result<Vec<u8>, TransportError>
    where
        Dev: FidoDevice,
    {
        let flags = if self.options.ask_user_validation() {
            U2F_REQUEST_USER_PRESENCE
        } else {
            0
        };

        let mut register_data = Vec::with_capacity(2 * PARAMETER_SIZE);
        register_data.extend_from_slice(self.client_data.challenge.as_ref());
        register_data.extend_from_slice(self.rp.hash().as_ref());

        let cmd = U2F_REGISTER;
        let apdu = U2FAPDUHeader::serialize(cmd, flags, &register_data)?;

        Ok(apdu)
    }

    fn handle_response_ctap1(
        &self,
        status: Result<(), ApduErrorStatus>,
        _input: &[u8],
    ) -> Result<Self::Output, Retryable<TransportError>> {
        if Err(ApduErrorStatus::ConditionsNotSatisfied) == status {
            return Err(Retryable::Retry);
        }
        /*
        named!(
            parse_register<(&[u8], &[u8])>,
            do_parse!(
                reserved: tag!(&[0x05])
                    >> public_key: take!(65)
                    >> key_handle_len: be_u8
                    >> key_handle: take!(key_handle_len)
                    >> (public_key, key_handle)
            )
        );

        let (rest, (public_key, key_handle)) = parse_register(input)
            .map_err(|e| {
                error!("error while parsing registration = {:?}", e);
                io::Error::new(io::ErrorKind::Other, "unable to parse registration")
            })
            .map_err(|e| TransportError::IO(None, e))
            .map_err(Retryable::Error)?;

        let (signature, cert) = der_parser::parse_der(rest) // TODO(MS): See if this can be done without an external crate
            .map_err(|e| {
                error!("error while parsing cert = {:?}", e);
                let err = io::Error::new(io::ErrorKind::Other, "Failed to parse x509 certificate");
                let err = serde_cbor::Error::from(err);
                let err = Error::Parsing(err);
                let err = TransportError::Command(err);
                Retryable::Error(err)
            })
            .map(|(sig, cert)| (sig, &rest[..rest.len() - sig.len()]))?;

        let auth_data = AuthenticatorData {
            rp_id_hash: self.rp.hash(),
            flags: AuthenticatorDataFlags::empty(),
            counter: 0,
            credential_data: Some(AttestedCredentialData {
                aaguid: AAGuid::empty(),
                credential_id: Vec::from(&key_handle[..]),
                // TODO(baloo): this is wrong, this is not the format expected by cose::PublicKey
                // (or is it?)
                // see This is the (uncompressed) x,y-representation of a curve point on the P-256 NIST elliptic curve.
                // https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html
                credential_public_key: PublicKey::new(
                    SignatureAlgorithm::PS256,
                    Vec::from(&public_key[..]),
                ),
            }),
            extensions: Vec::new(),
        };

        let att_statement_u2f = AttestationStatementFidoU2F::new(cert, signature);
        let att_statement = AttestationStatement::FidoU2F(att_statement_u2f);
        let attestation_object = AttestationObject {
            auth_data,
            att_statement,
        };
        let client_data = self.client_data.clone();

        Ok((attestation_object, client_data))
        */
        unimplemented!();
    }
}

impl RequestCtap2 for MakeCredentials {
    type Output = (AttestationObject, CollectedClientData);

    fn command() -> Command {
        Command::MakeCredentials
    }

    fn wire_format<Dev>(&self, dev: &mut Dev) -> Result<Vec<u8>, TransportError>
    where
        Dev: FidoDevice,
    {
        let cd = CommandDevice::new(dev, self)?;

        Ok(ser::to_vec(&cd).map_err(Error::Serialization)?)
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
                let attestation = from_slice(&input[1..]).map_err(Error::Parsing)?;
                let client_data = self.client_data.clone();
                Ok((attestation, client_data))
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

impl RequestWithPin for MakeCredentials {
    fn pin(&self) -> Option<&Pin> {
        self.pin.as_ref()
    }

    fn client_data_hash(&self) -> Result<ClientDataHash, Error> {
        self.client_data.hash().map_err(Error::Json)
    }
}
