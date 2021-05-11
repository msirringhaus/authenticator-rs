use super::{Command, CommandError, Request, RequestCtap1, RequestCtap2, Retryable, StatusCode};
use crate::consts::{PARAMETER_SIZE, U2F_REGISTER, U2F_REQUEST_USER_PRESENCE};
use crate::ctap2::attestation::{
    AAGuid, AttestationObject, AttestationStatement, AttestationStatementFidoU2F,
    AttestedCredentialData, AuthenticatorData, AuthenticatorDataFlags,
};
use crate::ctap2::client_data::CollectedClientData;
use crate::ctap2::server::{
    PublicKeyCredentialDescriptor, PublicKeyCredentialParameters, RelyingParty, User,
};
use crate::transport::errors::{ApduErrorStatus, HIDError as TransportError};
use crate::u2ftypes::{U2FAPDUHeader, U2FDevice};
use nom::{do_parse, named, number::complete::be_u8, tag, take};
#[cfg(test)]
use serde::Deserialize;
use serde::{
    ser::{Error as SerError, SerializeMap},
    Serialize, Serializer,
};
use serde_cbor::{self, de::from_slice, ser, Value};
use serde_json::{value as json_value, Map};
use std::fmt;
use std::io;

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
pub struct Pin(String); // TODO(MS): unimplemented! Requires more crypto

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
    // TODO(MS): pin_protocol
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
}

impl Serialize for MakeCredentials {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Need to define how many elements are going to be in the map
        // beforehand
        let mut map_len = 4;
        if !self.exclude_list.is_empty() {
            map_len += 1;
        }
        if !self.extensions.is_empty() {
            map_len += 1;
        }
        if self.options.is_some() {
            map_len += 1;
        }

        let mut map = serializer.serialize_map(Some(map_len))?;
        let client_data_hash = self
            .client_data
            .hash()
            .map_err(|e| S::Error::custom(format!("error while hashing client data: {}", e)))?;
        map.serialize_entry(&1, &client_data_hash)?;
        map.serialize_entry(&2, &self.rp)?;
        map.serialize_entry(&3, &self.user)?;
        map.serialize_entry(&4, &self.pub_cred_params)?;
        if !self.exclude_list.is_empty() {
            map.serialize_entry(&5, &self.exclude_list)?;
        }
        if !self.extensions.is_empty() {
            map.serialize_entry(&6, &self.extensions)?;
        }
        if self.options.is_some() {
            map.serialize_entry(&7, &self.options)?;
        }
        map.end()
    }
}

impl Request<(AttestationObject, CollectedClientData)> for MakeCredentials {}

impl RequestCtap1 for MakeCredentials {
    type Output = (AttestationObject, CollectedClientData);

    fn apdu_format<Dev>(&self, _dev: &mut Dev) -> Result<Vec<u8>, TransportError>
    where
        Dev: U2FDevice,
    {
        // TODO(MS): Mandatory sanity checks are missing:
        // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#u2f-authenticatorMakeCredential-interoperability
        // If any of the below conditions is not true, platform errors out with CTAP2_ERR_UNSUPPORTED_OPTION.
        //  * pubKeyCredParams must use the ES256 algorithm (-7).
        //  * Options must not include "rk" set to true.
        //  * Options must not include "uv" set to true.

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
        input: &[u8],
    ) -> Result<Self::Output, Retryable<TransportError>> {
        if Err(ApduErrorStatus::ConditionsNotSatisfied) == status {
            return Err(Retryable::Retry);
        }

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

        let (_rest, (_public_key, key_handle)) = parse_register(input)
            .map_err(|e| {
                error!("error while parsing registration = {:?}", e);
                io::Error::new(io::ErrorKind::Other, "unable to parse registration")
            })
            .map_err(|e| TransportError::IO(None, e))
            .map_err(Retryable::Error)?;

        // TODO(MS): This is currently not parsed within the crate, but outside by a user-provided function
        //           See examples/main.rs: u2f_get_key_handle_from_register_response()
        //           We would need to add a DER parser as a dependency, which I don't want to do right now.
        // let (signature, cert) = der_parser::parse_der(rest)
        //     .map_err(|e| {
        //         error!("error while parsing cert = {:?}", e);
        //         let err = io::Error::new(io::ErrorKind::Other, "Failed to parse x509 certificate");
        //         let err = error::Error::from(err);
        //         let err = CommandError::Parsing(err);
        //         let err = TransportError::Command(err);
        //         Retryable::Error(err)
        //     })
        //     .map(|(sig, cert)| (sig, &rest[..rest.len() - sig.len()]))?;

        let auth_data = AuthenticatorData {
            rp_id_hash: self.rp.hash(),
            flags: AuthenticatorDataFlags::empty(),
            counter: 0,
            credential_data: Some(AttestedCredentialData {
                aaguid: AAGuid::default(),
                credential_id: Vec::from(key_handle),
                // TODO(baloo): this is wrong, this is not the format expected by cose::PublicKey
                // (or is it?)
                // see This is the (uncompressed) x,y-representation of a curve point on the P-256 NIST elliptic curve.
                // https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html
                //credential_public_key: PublicKey::new(EllipticCurve::P256, Vec::from(public_key)),
            }),
            extensions: Vec::new(),
        };

        // TODO(MS)
        // let att_statement_u2f = AttestationStatementFidoU2F::new(cert, signature);
        let att_statement_u2f = AttestationStatementFidoU2F::new(&[], &[]);
        let att_statement = AttestationStatement::FidoU2F(att_statement_u2f);
        let attestation_object = AttestationObject {
            auth_data,
            att_statement,
        };
        let client_data = self.client_data.clone();

        Ok((attestation_object, client_data))
    }
}

impl RequestCtap2 for MakeCredentials {
    type Output = (AttestationObject, CollectedClientData);

    fn command() -> Command {
        Command::MakeCredentials
    }

    fn wire_format<Dev>(&self, _dev: &mut Dev) -> Result<Vec<u8>, TransportError>
    where
        Dev: U2FDevice + io::Read + io::Write + fmt::Debug,
    {
        Ok(ser::to_vec(&self).map_err(CommandError::Serialization)?)
    }

    fn handle_response_ctap2<Dev>(
        &self,
        _dev: &mut Dev,
        input: &[u8],
    ) -> Result<Self::Output, TransportError>
    where
        Dev: U2FDevice + io::Read + io::Write + fmt::Debug,
    {
        if input.is_empty() {
            return Err(TransportError::Command(CommandError::InputTooSmall));
        }

        let status: StatusCode = input[0].into();
        debug!("response status code: {:?}", status);
        if input.len() > 1 {
            if status.is_ok() {
                let attestation = from_slice(&input[1..]).map_err(CommandError::Parsing)?;
                let client_data = self.client_data.clone();
                Ok((attestation, client_data))
            } else {
                let data: Value = from_slice(&input[1..]).map_err(CommandError::Parsing)?;
                Err(TransportError::Command(CommandError::StatusCode(
                    status,
                    Some(data),
                )))
            }
        } else if status.is_ok() {
            Err(TransportError::Command(CommandError::InputTooSmall))
        } else {
            Err(TransportError::Command(CommandError::StatusCode(
                status, None,
            )))
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::MakeCredentials;
    use crate::ctap2::attestation::{
        AAGuid, AttestationCertificate, AttestationObject, AttestationStatement,
        AttestationStatementPacked, AttestedCredentialData, AuthenticatorData,
        AuthenticatorDataFlags, Signature,
    };
    use crate::ctap2::client_data::{Challenge, CollectedClientData, TokenBinding, WebauthnType};
    use crate::ctap2::commands::RequestCtap2;
    use crate::ctap2::server::RpIdHash;
    use crate::ctap2::server::{Alg, PublicKeyCredentialParameters, RelyingParty, User};
    use crate::u2fprotocol::tests::platform::TestDevice;
    use serde_bytes::ByteBuf;
    pub const MAKE_CREDENTIALS_SAMPLE_RESPONSE: [u8; 666] = [
        0x00, // status = success
        0xa3, // map(3)
        0x01, // unsigned(1)
        0x66, // text(6)
        0x70, 0x61, 0x63, 0x6b, 0x65, 0x64, // "packed"
        0x02, // unsigned(2)
        0x58, 0x9a, // bytes(154)
        // authData
        0xc2, 0x89, 0xc5, 0xca, 0x9b, 0x04, 0x60, 0xf9, 0x34, 0x6a, 0xb4, 0xe4, 0x2d, 0x84,
        0x27, // rp_id_hash
        0x43, 0x40, 0x4d, 0x31, 0xf4, 0x84, 0x68, 0x25, 0xa6, 0xd0, 0x65, 0xbe, 0x59, 0x7a,
        0x87, // rp_id_hash
        0x05, 0x1d, 0x41, // authData Flags
        0x00, 0x00, 0x00, 0x0b, // authData counter
        0xf8, 0xa0, 0x11, 0xf3, 0x8c, 0x0a, 0x4d, 0x15, 0x80, 0x06, 0x17, 0x11, 0x1f, 0x9e, 0xdc,
        0x7d, // AAGUID
        0x00, 0x10, // credential id length
        0x89, 0x59, 0xce, 0xad, 0x5b, 0x5c, 0x48, 0x16, 0x4e, 0x8a, 0xbc, 0xd6, 0xd9, 0x43, 0x5c,
        0x6f, // credential id
        0xa3, 0x63, 0x61, 0x6c, 0x67, 0x65, 0x45, 0x53, 0x32, 0x35, 0x36, 0x61, 0x78, 0x58, 0x20,
        0xf7, 0xc4, 0xf4, 0xa6, 0xf1, 0xd7, 0x95, 0x38, 0xdf, 0xa4, 0xc9, 0xac, 0x50, 0x84, 0x8d,
        0xf7, 0x08, 0xbc, 0x1c, 0x99, 0xf5, 0xe6, 0x0e, 0x51, 0xb4, 0x2a, 0x52, 0x1b, 0x35, 0xd3,
        0xb6, 0x9a, 0x61, 0x79, 0x58, 0x20, 0xde, 0x7b, 0x7d, 0x6c, 0xa5, 0x64, 0xe7, 0x0e, 0xa3,
        0x21, 0xa4, 0xd5, 0xd9, 0x6e, 0xa0, 0x0e, 0xf0, 0xe2, 0xdb, 0x89, 0xdd, 0x61, 0xd4, 0x89,
        0x4c, 0x15, 0xac, 0x58, 0x5b, 0xd2, 0x36, 0x84, 0x03, // unsigned(3)
        0xa3, // map(3)
        0x63, // text(3)
        0x61, 0x6c, 0x67, // "alg"
        0x26, // -7 (ES256)
        0x63, // text(3)
        0x73, 0x69, 0x67, // "sig"
        0x58, 0x47, // bytes(71)
        0x30, 0x45, 0x02, 0x20, 0x13, 0xf7, 0x3c, 0x5d, // signature...
        0x9d, 0x53, 0x0e, 0x8c, 0xc1, 0x5c, 0xc9, 0xbd, 0x96, 0xad, 0x58, 0x6d, 0x39, 0x36, 0x64,
        0xe4, 0x62, 0xd5, 0xf0, 0x56, 0x12, 0x35, 0xe6, 0x35, 0x0f, 0x2b, 0x72, 0x89, 0x02, 0x21,
        0x00, 0x90, 0x35, 0x7f, 0xf9, 0x10, 0xcc, 0xb5, 0x6a, 0xc5, 0xb5, 0x96, 0x51, 0x19, 0x48,
        0x58, 0x1c, 0x8f, 0xdd, 0xb4, 0xa2, 0xb7, 0x99, 0x59, 0x94, 0x80, 0x78, 0xb0, 0x9f, 0x4b,
        0xdc, 0x62, 0x29, 0x63, // text(3)
        0x78, 0x35, 0x63, // "x5c"
        0x81, // array(1)
        0x59, 0x01, 0x97, // bytes(407)
        0x30, 0x82, 0x01, 0x93, 0x30, 0x82, 0x01, //certificate...
        0x38, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00, 0x85, 0x9b, 0x72, 0x6c, 0xb2, 0x4b,
        0x4c, 0x29, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
        0x47, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,
        0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0b, 0x59, 0x75, 0x62, 0x69, 0x63,
        0x6f, 0x20, 0x54, 0x65, 0x73, 0x74, 0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04, 0x0b,
        0x0c, 0x19, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x6f, 0x72,
        0x20, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x30, 0x1e, 0x17,
        0x0d, 0x31, 0x36, 0x31, 0x32, 0x30, 0x34, 0x31, 0x31, 0x35, 0x35, 0x30, 0x30, 0x5a, 0x17,
        0x0d, 0x32, 0x36, 0x31, 0x32, 0x30, 0x32, 0x31, 0x31, 0x35, 0x35, 0x30, 0x30, 0x5a, 0x30,
        0x47, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,
        0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0b, 0x59, 0x75, 0x62, 0x69, 0x63,
        0x6f, 0x20, 0x54, 0x65, 0x73, 0x74, 0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04, 0x0b,
        0x0c, 0x19, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x6f, 0x72,
        0x20, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x30, 0x59, 0x30,
        0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xad, 0x11, 0xeb, 0x0e, 0x88, 0x52,
        0xe5, 0x3a, 0xd5, 0xdf, 0xed, 0x86, 0xb4, 0x1e, 0x61, 0x34, 0xa1, 0x8e, 0xc4, 0xe1, 0xaf,
        0x8f, 0x22, 0x1a, 0x3c, 0x7d, 0x6e, 0x63, 0x6c, 0x80, 0xea, 0x13, 0xc3, 0xd5, 0x04, 0xff,
        0x2e, 0x76, 0x21, 0x1b, 0xb4, 0x45, 0x25, 0xb1, 0x96, 0xc4, 0x4c, 0xb4, 0x84, 0x99, 0x79,
        0xcf, 0x6f, 0x89, 0x6e, 0xcd, 0x2b, 0xb8, 0x60, 0xde, 0x1b, 0xf4, 0x37, 0x6b, 0xa3, 0x0d,
        0x30, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0a,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46,
        0x02, 0x21, 0x00, 0xe9, 0xa3, 0x9f, 0x1b, 0x03, 0x19, 0x75, 0x25, 0xf7, 0x37, 0x3e, 0x10,
        0xce, 0x77, 0xe7, 0x80, 0x21, 0x73, 0x1b, 0x94, 0xd0, 0xc0, 0x3f, 0x3f, 0xda, 0x1f, 0xd2,
        0x2d, 0xb3, 0xd0, 0x30, 0xe7, 0x02, 0x21, 0x00, 0xc4, 0xfa, 0xec, 0x34, 0x45, 0xa8, 0x20,
        0xcf, 0x43, 0x12, 0x9c, 0xdb, 0x00, 0xaa, 0xbe, 0xfd, 0x9a, 0xe2, 0xd8, 0x74, 0xf9, 0xc5,
        0xd3, 0x43, 0xcb, 0x2f, 0x11, 0x3d, 0xa2, 0x37, 0x23, 0xf3,
    ];

    pub const MAKE_CREDENTIALS_SAMPLE_REQUEST: [u8; 244] = [
        // 0xa5, // map(5) Replace line below with this one, once MakeCredentialOptions work
        0xa4, // map(4)
        0x01, // unsigned(1) - clientDataHash
        0x58, 0x20, // bytes(32)
        0xc1, 0xdd, 0x35, 0x5f, 0x3c, 0x81, 0x69, 0x23, 0xe0, 0x57, 0xca, 0x03, 0x8d, // hash
        0xba, 0xad, 0xb8, 0x5f, 0x95, 0x55, 0xcf, 0xc7, 0x62, 0x9b, 0x9d, 0x53, 0x66, // hash
        0x97, 0x53, 0x80, 0xd7, 0x69, 0x4f, // hash
        0x02, // unsigned(2) - rp
        // 0xa2, // map(2) Replace line below with this one, once RelyingParty supports "name"
        0xa1, // map(1)
        0x62, // text(2)
        0x69, 0x64, // "id"
        0x6b, // text(11)
        0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, // "example.com"
        // TODO(MS): RelyingParty does not yet support optional fields "name" and "icon"
        // 0x64, // text(4)
        // 0x6e, 0x61, 0x6d, 0x65, // "name"
        // 0x64, // text(4)
        // 0x41, 0x63, 0x6d, 0x65, // "Acme"
        0x03, // unsigned(3) - user
        0xa4, // map(4)
        0x62, // text(2)
        0x69, 0x64, // "id"
        0x58, 0x20, // bytes(32)
        0x30, 0x82, 0x01, 0x93, 0x30, 0x82, 0x01, 0x38, 0xa0, 0x03, 0x02, 0x01,
        0x02, // userid
        0x30, 0x82, 0x01, 0x93, 0x30, 0x82, 0x01, 0x38, 0xa0, 0x03, 0x02, 0x01, 0x02, // ...
        0x30, 0x82, 0x01, 0x93, 0x30, 0x82, // ...
        0x64, // text(4)
        0x69, 0x63, 0x6f, 0x6e, // "icon"
        0x78, 0x2b, // text(43)
        0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x70, 0x69, 0x63, 0x73, 0x2e, 0x65,
        0x78, // "https://pics.example.com/00/p/aBjjjpqPb.png"
        0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x30, 0x30, 0x2f, 0x70,
        0x2f, //
        0x61, 0x42, 0x6a, 0x6a, 0x6a, 0x70, 0x71, 0x50, 0x62, 0x2e, 0x70, 0x6e, 0x67, //
        0x64, // text(4)
        0x6e, 0x61, 0x6d, 0x65, // "name"
        0x76, // text(22)
        0x6a, 0x6f, 0x68, 0x6e, 0x70, 0x73, 0x6d, 0x69, 0x74, 0x68, 0x40, 0x65, 0x78, 0x61,
        0x6d, // "johnpsmith@example.com"
        0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, // ...
        0x6b, // text(11)
        0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x4e, 0x61, 0x6d, 0x65, // "displayName"
        0x6d, // text(13)
        0x4a, 0x6f, 0x68, 0x6e, 0x20, 0x50, 0x2e, 0x20, 0x53, 0x6d, 0x69, 0x74,
        0x68, // "John P. Smith"
        0x04, // unsigned(4) - pubKeyCredParams
        0x82, // array(2)
        0xa2, // map(2)
        0x63, // text(3)
        0x61, 0x6c, 0x67, // "alg"
        0x26, // -7 (ES256)
        0x64, // text(4)
        0x74, 0x79, 0x70, 0x65, // "type"
        0x6a, // text(10)
        0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0x2D, 0x6B, 0x65, 0x79, // "public-key"
        0xa2, // map(2)
        0x63, // text(3)
        0x61, 0x6c, 0x67, // "alg"
        0x39, 0x01, 0x00, // -257 (RS256)
        0x64, // text(4)
        0x74, 0x79, 0x70, 0x65, // "type"
        0x6a, // text(10)
        0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0x2D, 0x6B, 0x65,
        0x79, // "public-key"
              // TODO(MS): Options seem to be parsed differently than in the example here.
              // 0x07, // unsigned(7) - options
              // 0xa1, // map(1)
              // 0x62, // text(2)
              // 0x72, 0x6b, // "rk"
              // 0xf5, // primitive(21)
    ];
    #[test]
    fn parse_response() {
        let req = MakeCredentials::new(
            CollectedClientData {
                webauthn_type: WebauthnType::Create,
                challenge: Challenge::from(vec![0x00, 0x01, 0x02, 0x03]),
                origin: String::from("example.com"),
                cross_origin: None,
                token_binding: Some(TokenBinding::Present(vec![0x00, 0x01, 0x02, 0x03])),
            },
            RelyingParty {
                id: String::from("example.com"),
            },
            Some(User {
                id: base64::decode_config(
                    "MIIBkzCCATigAwIBAjCCAZMwggE4oAMCAQIwggGTMII=",
                    base64::URL_SAFE_NO_PAD,
                )
                .unwrap(),
                icon: Some("https://pics.example.com/00/p/aBjjjpqPb.png".to_string()),
                name: String::from("johnpsmith@example.com"),
                display_name: Some(String::from("John P. Smith")),
            }),
            vec![
                PublicKeyCredentialParameters { alg: Alg::ES256 },
                PublicKeyCredentialParameters { alg: Alg::RS256 },
            ],
            Vec::new(),
            None,
            // Some(MakeCredentialsOptions {
            //     resident_key: true,
            //     user_validation: false,
            // }),
            None,
        );

        let mut device = TestDevice::new(); // not really used (all functions ignore it)
        let req_serialized = req
            .wire_format(&mut device)
            .expect("Failed to serialize MakeCredentials request");
        assert_eq!(req_serialized, MAKE_CREDENTIALS_SAMPLE_REQUEST);
        let (attestation_object, _collected_client_data) = req
            .handle_response_ctap2(&mut device, &MAKE_CREDENTIALS_SAMPLE_RESPONSE)
            .expect("Failed to handle CTAP2 response");

        let expected = AttestationObject {
            auth_data: AuthenticatorData {
                rp_id_hash: RpIdHash::from(&[
                    0xc2, 0x89, 0xc5, 0xca, 0x9b, 0x04, 0x60, 0xf9, 0x34, 0x6a, 0xb4, 0xe4, 0x2d,
                    0x84, 0x27, 0x43, 0x40, 0x4d, 0x31, 0xf4, 0x84, 0x68, 0x25, 0xa6, 0xd0, 0x65,
                    0xbe, 0x59, 0x7a, 0x87, 0x5, 0x1d,
                ])
                .unwrap(),
                flags: AuthenticatorDataFlags::USER_PRESENT | AuthenticatorDataFlags::ATTESTED,
                counter: 11,
                credential_data: Some(AttestedCredentialData {
                    aaguid: AAGuid::from(&[
                        0xf8, 0xa0, 0x11, 0xf3, 0x8c, 0x0a, 0x4d, 0x15, 0x80, 0x06, 0x17, 0x11,
                        0x1f, 0x9e, 0xdc, 0x7d,
                    ])
                    .unwrap(),
                    credential_id: vec![
                        0x89, 0x59, 0xce, 0xad, 0x5b, 0x5c, 0x48, 0x16, 0x4e, 0x8a, 0xbc, 0xd6,
                        0xd9, 0x43, 0x5c, 0x6f,
                    ],
                }),
                extensions: Vec::new(),
            },
            att_statement: AttestationStatement::Packed(AttestationStatementPacked {
                alg: Alg::ES256,
                sig: Signature(ByteBuf::from([
                    0x30, 0x45, 0x02, 0x20, 0x13, 0xf7, 0x3c, 0x5d, 0x9d, 0x53, 0x0e, 0x8c, 0xc1,
                    0x5c, 0xc9, 0xbd, 0x96, 0xad, 0x58, 0x6d, 0x39, 0x36, 0x64, 0xe4, 0x62, 0xd5,
                    0xf0, 0x56, 0x12, 0x35, 0xe6, 0x35, 0x0f, 0x2b, 0x72, 0x89, 0x02, 0x21, 0x00,
                    0x90, 0x35, 0x7f, 0xf9, 0x10, 0xcc, 0xb5, 0x6a, 0xc5, 0xb5, 0x96, 0x51, 0x19,
                    0x48, 0x58, 0x1c, 0x8f, 0xdd, 0xb4, 0xa2, 0xb7, 0x99, 0x59, 0x94, 0x80, 0x78,
                    0xb0, 0x9f, 0x4b, 0xdc, 0x62, 0x29,
                ])),
                attestation_cert: vec![AttestationCertificate(vec![
                    0x30, 0x82, 0x01, 0x93, 0x30, 0x82, 0x01, 0x38, 0xa0, 0x03, 0x02, 0x01, 0x02,
                    0x02, 0x09, 0x00, 0x85, 0x9b, 0x72, 0x6c, 0xb2, 0x4b, 0x4c, 0x29, 0x30, 0x0a,
                    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x47, 0x31,
                    0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,
                    0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0b, 0x59, 0x75, 0x62,
                    0x69, 0x63, 0x6f, 0x20, 0x54, 0x65, 0x73, 0x74, 0x31, 0x22, 0x30, 0x20, 0x06,
                    0x03, 0x55, 0x04, 0x0b, 0x0c, 0x19, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74,
                    0x69, 0x63, 0x61, 0x74, 0x6f, 0x72, 0x20, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74,
                    0x61, 0x74, 0x69, 0x6f, 0x6e, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x36, 0x31, 0x32,
                    0x30, 0x34, 0x31, 0x31, 0x35, 0x35, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x32, 0x36,
                    0x31, 0x32, 0x30, 0x32, 0x31, 0x31, 0x35, 0x35, 0x30, 0x30, 0x5a, 0x30, 0x47,
                    0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,
                    0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0b, 0x59, 0x75,
                    0x62, 0x69, 0x63, 0x6f, 0x20, 0x54, 0x65, 0x73, 0x74, 0x31, 0x22, 0x30, 0x20,
                    0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x19, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e,
                    0x74, 0x69, 0x63, 0x61, 0x74, 0x6f, 0x72, 0x20, 0x41, 0x74, 0x74, 0x65, 0x73,
                    0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a,
                    0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
                    0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xad, 0x11, 0xeb, 0x0e, 0x88, 0x52,
                    0xe5, 0x3a, 0xd5, 0xdf, 0xed, 0x86, 0xb4, 0x1e, 0x61, 0x34, 0xa1, 0x8e, 0xc4,
                    0xe1, 0xaf, 0x8f, 0x22, 0x1a, 0x3c, 0x7d, 0x6e, 0x63, 0x6c, 0x80, 0xea, 0x13,
                    0xc3, 0xd5, 0x04, 0xff, 0x2e, 0x76, 0x21, 0x1b, 0xb4, 0x45, 0x25, 0xb1, 0x96,
                    0xc4, 0x4c, 0xb4, 0x84, 0x99, 0x79, 0xcf, 0x6f, 0x89, 0x6e, 0xcd, 0x2b, 0xb8,
                    0x60, 0xde, 0x1b, 0xf4, 0x37, 0x6b, 0xa3, 0x0d, 0x30, 0x0b, 0x30, 0x09, 0x06,
                    0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0a, 0x06, 0x08, 0x2a,
                    0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02,
                    0x21, 0x00, 0xe9, 0xa3, 0x9f, 0x1b, 0x03, 0x19, 0x75, 0x25, 0xf7, 0x37, 0x3e,
                    0x10, 0xce, 0x77, 0xe7, 0x80, 0x21, 0x73, 0x1b, 0x94, 0xd0, 0xc0, 0x3f, 0x3f,
                    0xda, 0x1f, 0xd2, 0x2d, 0xb3, 0xd0, 0x30, 0xe7, 0x02, 0x21, 0x00, 0xc4, 0xfa,
                    0xec, 0x34, 0x45, 0xa8, 0x20, 0xcf, 0x43, 0x12, 0x9c, 0xdb, 0x00, 0xaa, 0xbe,
                    0xfd, 0x9a, 0xe2, 0xd8, 0x74, 0xf9, 0xc5, 0xd3, 0x43, 0xcb, 0x2f, 0x11, 0x3d,
                    0xa2, 0x37, 0x23, 0xf3,
                ])],
            }),
        };

        assert_eq!(
            &attestation_object.auth_data.rp_id_hash.0,
            &[
                0xc2, 0x89, 0xc5, 0xca, 0x9b, 0x04, 0x60, 0xf9, 0x34, 0x6a, 0xb4, 0xe4, 0x2d, 0x84,
                0x27, 0x43, 0x40, 0x4d, 0x31, 0xf4, 0x84, 0x68, 0x25, 0xa6, 0xd0, 0x65, 0xbe, 0x59,
                0x7a, 0x87, 0x5, 0x1d
            ]
        );

        assert_eq!(attestation_object, expected);
    }
}
