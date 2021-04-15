use super::*; 
use std::fmt;
use serde::{Serialize, Serializer, Deserialize, Deserializer, de::{Error as SerdeError, Visitor, MapAccess}, ser::SerializeMap};
use sha2::{Sha256, Digest};
use serde_bytes::{ByteBuf};
use cose::SignatureAlgorithm;
use super::get_info::AuthenticatorInfo;
use serde_cbor::de::from_slice;
use serde_cbor::ser::to_vec;
use std::convert::TryFrom;
use crate::ctap::ClientDataHash;

// use serde::Deserialize; cfg[test]

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub curve: SignatureAlgorithm,
    // TODO(baloo): yeah, I know jcj :) I shouldn't be using bytes in asn.1 here :p
    pub bytes: Vec<u8>,
}
impl PublicKey {
    fn affine_coordinates(&self) -> Result<(ByteBuf, ByteBuf), Error> {
        unimplemented!();
/*
        let name = self.curve.to_openssl_name();
        let group = EcGroup::from_curve_name(name)?;

        let mut ctx = BigNumContext::new().unwrap();
        let point = EcPoint::from_bytes(&group, &self.bytes[..], &mut ctx).unwrap();

        let mut x = BigNum::new()?;
        let mut y = BigNum::new()?;

        point.affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)?;
        //point.affine_coordinates_gf2m(&group, &mut x, &mut y, &mut ctx)?;

        Ok((x.to_vec().into(), y.to_vec().into()))
*/
    }

    pub fn new(curve: SignatureAlgorithm, bytes: Vec<u8>) -> Self {
        PublicKey { curve, bytes }
    }
}

const KEY_TYPE: u8 = 1;

// https://tools.ietf.org/html/rfc8152#section-13
#[repr(u8)]
enum KeyType {
    OKP = 1,
    EC2 = 2,
    Symmetric = 4,
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PublicKeyVisitor;

        impl<'de> Visitor<'de> for PublicKeyVisitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut curve: Option<SignatureAlgorithm> = None;
                let mut x: Option<ByteBuf> = None;
                let mut y: Option<ByteBuf> = None;

                while let Some(key) = map.next_key()? {
                    trace!("cose key {:?}", key);
                    match key {
                        -1 => {
                            if curve.is_some() {
                                return Err(SerdeError::duplicate_field("curve"));
                            }
                            let value : u64 = map.next_value()?;
                            let val = SignatureAlgorithm::try_from(value).map_err(|_| SerdeError::custom(format!(
                                    "unsupported curve {}",
                                    value
                                )))?;
                            curve = Some(val);
                        }
                        -2 => {
                            if x.is_some() {
                                return Err(SerdeError::duplicate_field("x"));
                            }
                            let value = map.next_value()?;

                            x = Some(value);
                        }
                        -3 => {
                            if y.is_some() {
                                return Err(SerdeError::duplicate_field("y"));
                            }
                            let value = map.next_value()?;

                            y = Some(value);
                        }
                        _ => {
                            // TODO(baloo): need to check key_type (1)
                            //
                            // This unknown field should raise an error, but
                            // there is a couple of field I(baloo) do not understand
                            // yet. I(baloo) chose to ignore silently the
                            // error instead because of that
                            let value: Value = map.next_value()?;
                            trace!("cose unknown value {:?}:{:?}", key, value);
                        }
                    };
                }

                if let Some(curve) = curve {
                    if let Some(x) = x {
                        if let Some(y) = y {
                            unimplemented!();
//                             let pub_key = curve.affine_to_key(&x[..], &y[..]).map_err(|e| {
//                                 SerdeError::custom(format!("nss error: {:?}", e))
//                             })?;
//                             Ok(pub_key)
                        } else {
                            Err(SerdeError::custom("missing required field: y"))
                        }
                    } else {
                        Err(SerdeError::custom("missing required field: x"))
                    }
                } else {
                    Err(SerdeError::custom("missing required field: curve"))
                }
            }
        }

        deserializer.deserialize_bytes(PublicKeyVisitor)
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry(&KEY_TYPE, &(KeyType::EC2 as u8))?;
        map.serialize_entry(&-1, &(self.curve as u8))?;

        let (x, y) = self
            .affine_coordinates()
            .map_err(|e| serde::ser::Error::custom(format!("NSS error: {:?}", e)))?;

        map.serialize_entry(&-2, &x)?;
        map.serialize_entry(&-3, &y)?;
        map.end()
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

#[derive(Clone)]
pub struct ECDHSecret {
    curve: SignatureAlgorithm,
    remote: PublicKey,
    my: PublicKey,
    shared_secret: Vec<u8>,
}

impl ECDHSecret {
    pub fn my_public_key(&self) -> &PublicKey {
        &self.my
    }

    pub fn shared_secret(&self) -> &[u8] {
        self.shared_secret.as_ref()
    }
    
    pub fn encrypt(&self, input: &[u8], iv: &[u8]) -> Result<Vec<u8>, Error> {
        unimplemented!();
        /*let cipher = Cipher::aes_256_cbc();

        // TODO(baloo): This might trigger a panic if size is not big enough
        let mut output = vec![0; input.len() * 2];
        output.resize(input.len() * 2, 0);
        let mut encrypter = Crypter::new(cipher, Mode::Encrypt, self.0.shared_secret(), Some(iv))
            .map_err(Error::Openssl)?;
        encrypter.pad(false);
        let mut out_size = 0;
        out_size += encrypter.update(input, output.as_mut_slice())?;
        out_size += encrypter.finalize(output.as_mut_slice())?;
        output.truncate(out_size);
        Ok(output)*/
    }

    pub fn decrypt(&self, input: &[u8], iv: &[u8]) -> Result<Vec<u8>, Error> {
        unimplemented!();
        /*let cipher = Cipher::aes_256_cbc();

        // TODO(baloo): This might trigger a panic if size is not big enough
        let mut output = vec![0; input.len() * 2];
        output.resize(input.len() * 2, 0);
        let mut encrypter = Crypter::new(cipher, Mode::Decrypt, self.0.shared_secret(), Some(iv))
            .map_err(Error::Openssl)?;
        encrypter.pad(false);
        let mut out_size = 0;
        out_size += encrypter.update(input, output.as_mut_slice())?;
        out_size += encrypter.finalize(output.as_mut_slice())?;
        output.truncate(out_size);

        Ok(output)*/
    }
}

impl fmt::Debug for ECDHSecret {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ECDHSecret(remote: {:?}, my: {:?})",
            self.remote,
            self.my_public_key()
        )
    }
}


#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum PINSubcommand {
    GetRetries = 0x01,
    GetKeyAgreement = 0x02,
    SetPIN = 0x03,
    ChangePIN = 0x04,
    GetPINToken = 0x05,
}

#[derive(Debug)]
pub(crate) struct ClientPIN {
    pin_protocol: u8,
    subcommand: PINSubcommand,
    key_agreement: Option<PublicKey>,
    pin_auth: Option<[u8; 16]>,
    new_pin_enc: Option<ByteBuf>,
    pin_hash_enc: Option<ByteBuf>,
}

impl Default for ClientPIN {
    fn default() -> Self {
        ClientPIN {
            pin_protocol: 0,
            subcommand: PINSubcommand::GetRetries,
            key_agreement: None,
            pin_auth: None,
            new_pin_enc: None,
            pin_hash_enc: None,
        }
    }
}

impl Serialize for ClientPIN {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Need to define how many elements are going to be in the map
        // beforehand
        let mut map_len = 2;
        if self.key_agreement.is_some() {
            map_len += 1;
        }
        if self.pin_auth.is_some() {
            map_len += 1;
        }
        if self.new_pin_enc.is_some() {
            map_len += 1;
        }
        if self.pin_hash_enc.is_some() {
            map_len += 1;
        }

        let mut map = serializer.serialize_map(Some(map_len))?;
        map.serialize_entry(&1, &self.pin_protocol)?;
        let command: u8 = self.subcommand as u8;
        map.serialize_entry(&2, &command)?;
        if let Some(ref key_agreement) = self.key_agreement {
            map.serialize_entry(&3, key_agreement)?;
        }
        if let Some(ref pin_auth) = self.pin_auth {
            map.serialize_entry(&4, pin_auth)?;
        }
        if let Some(ref new_pin_enc) = self.new_pin_enc {
            map.serialize_entry(&5, new_pin_enc)?;
        }
        if let Some(ref pin_hash_enc) = self.pin_hash_enc {
            map.serialize_entry(&6, pin_hash_enc)?;
        }

        map.end()
    }
}

pub(crate) trait ClientPINSubCommand {
    type Output;
    fn as_client_pin(&self) -> Result<ClientPIN, Error>;
    fn parse_response_payload(&self, input: &[u8]) -> Result<Self::Output, Error>;
}

struct ClientPinResponse {
    key_agreement: Option<PublicKey>,
    pin_token: Option<EncryptedPinToken>,
    /// Number of PIN attempts remaining before lockout.
    _retries: Option<u8>,
}

impl<'de> Deserialize<'de> for ClientPinResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ClientPinResponseVisitor;

        impl<'de> Visitor<'de> for ClientPinResponseVisitor {
            type Value = ClientPinResponse;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut key_agreement = None;
                let mut pin_token = None;
                let mut retries = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        1 => {
                            if key_agreement.is_some() {
                                return Err(SerdeError::duplicate_field("key_agreement"));
                            }
                            key_agreement = map.next_value()?;
                        }
                        2 => {
                            if pin_token.is_some() {
                                return Err(SerdeError::duplicate_field("pin_token"));
                            }
                            pin_token = map.next_value()?;
                        }
                        3 => {
                            if retries.is_some() {
                                return Err(SerdeError::duplicate_field("retries"));
                            }
                            retries = Some(map.next_value()?);
                        }
                        k => return Err(M::Error::custom(format!("unexpected key: {:?}", k))),
                    }
                }
                Ok(ClientPinResponse {
                    key_agreement,
                    pin_token,
                    _retries: retries,
                })
            }
        }

        deserializer.deserialize_bytes(ClientPinResponseVisitor)
    }
}

#[derive(Debug)]
pub struct GetKeyAgreement {
    pin_protocol: u8,
}

impl GetKeyAgreement {
    pub fn new(info: &AuthenticatorInfo) -> Result<Self, Error> {
        if info.pin_protocols.contains(&1) {
            Ok(GetKeyAgreement { pin_protocol: 1 })
        } else {
            Err(Error::UnsupportedPinProtocol)
        }
    }
}

impl ClientPINSubCommand for GetKeyAgreement {
    type Output = KeyAgreement;

    fn as_client_pin(&self) -> Result<ClientPIN, Error> {
        Ok(ClientPIN {
            pin_protocol: self.pin_protocol,
            subcommand: PINSubcommand::GetKeyAgreement,
            ..ClientPIN::default()
        })
    }

    fn parse_response_payload(&self, input: &[u8]) -> Result<Self::Output, Error> {
        let value: Value = from_slice(input).map_err(Error::Parsing)?;
        debug!("GetKeyAgreement::parse_response_payload {:?}", value);

        let get_pin_response: ClientPinResponse = from_slice(input).map_err(Error::Parsing)?;
        if let Some(key_agreement) = get_pin_response.key_agreement {
            Ok(KeyAgreement(key_agreement))
        } else {
            Err(Error::MissingRequiredField("key_agreement"))
        }
    }
}

#[derive(Debug)]
pub struct GetPinToken<'sc, 'pin> {
    pin_protocol: u8,
    shared_secret: &'sc ECDHSecret,
    pin: &'pin Pin,
}

impl<'sc, 'pin> GetPinToken<'sc, 'pin> {
    pub fn new(
        info: &AuthenticatorInfo,
        shared_secret: &'sc ECDHSecret,
        pin: &'pin Pin,
    ) -> Result<Self, Error> {
        if info.pin_protocols.contains(&1) {
            Ok(GetPinToken {
                pin_protocol: 1,
                shared_secret,
                pin,
            })
        } else {
            Err(Error::UnsupportedPinProtocol)
        }
    }
}

impl<'sc, 'pin> ClientPINSubCommand for GetPinToken<'sc, 'pin> {
    type Output = PinToken;

    fn as_client_pin(&self) -> Result<ClientPIN, Error> {
        let iv = [0u8; 16];
        let input = self.pin.for_pin_token();
        trace!("pin_hash = {:#04X?}", &input.as_ref());
        let pin_hash_enc = self.shared_secret.encrypt(input.as_ref(), &iv[..])?;
        trace!("pin_hash_enc = {:#04X?}", &pin_hash_enc);

        Ok(ClientPIN {
            pin_protocol: self.pin_protocol,
            subcommand: PINSubcommand::GetPINToken,
            key_agreement: Some(self.shared_secret.my_public_key().clone()),
            pin_hash_enc: Some(ByteBuf::from(pin_hash_enc)),
            ..ClientPIN::default()
        })
    }

    fn parse_response_payload(&self, input: &[u8]) -> Result<Self::Output, Error> {
        let value: Value = from_slice(input).map_err(Error::Parsing)?;
        debug!("GetKeyAgreement::parse_response_payload {:?}", value);

        let get_pin_response: ClientPinResponse = from_slice(input).map_err(Error::Parsing)?;
        if let Some(encrypted_pin_token) = get_pin_response.pin_token {
            let iv = [0u8; 16];
            let pin_token = self
                .shared_secret
                .decrypt(encrypted_pin_token.as_ref(), &iv[..])?;
            let pin_token = PinToken(pin_token);
            Ok(pin_token)
        } else {
            Err(Error::MissingRequiredField("key_agreement"))
        }
    }
}

impl<T> RequestCtap2 for T
where
    T: ClientPINSubCommand,
    T: fmt::Debug,
{
    type Output = <T as ClientPINSubCommand>::Output;

    fn command() -> Command {
        Command::ClientPin
    }

    fn wire_format<Dev>(&self, dev: &mut Dev) -> Result<Vec<u8>, TransportError>
    where
        Dev: FidoDevice,
    {
        let client_pin = self.as_client_pin()?;
        let output = to_vec(&client_pin).map_err(Error::Serialization)?;
        trace!("client subcommmand: {:#04X?}", &output);

        Ok(output)
    }

    fn handle_response_ctap2<Dev>(
        &self,
        _dev: &mut Dev,
        input: &[u8],
    ) -> Result<Self::Output, TransportError>
    where
        Dev: FidoDevice,
    {
        trace!("Client pin subcomand response:{:#04X?}", &input);

        if input.is_empty() {
            return Err(Error::InputTooSmall).map_err(TransportError::Command);
        }
        let status: StatusCode = input[0].into();
        debug!("response status code: {:?}", status);
        if input.len() > 1 {
            if status.is_ok() {
                <T as ClientPINSubCommand>::parse_response_payload(self, &input[1..])
                    .map_err(TransportError::Command)
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

#[derive(Debug)]
pub struct KeyAgreement(PublicKey);

impl KeyAgreement {
    pub fn shared_secret(&self) -> Result<ECDHSecret, Error> {
        unimplemented!();
//         self.0
//             .complete_handshake()
//             .map_err(|_| Error::ECDH)
//             .map(ECDHSecret)
    }
}

// #[derive(Debug, Clone)]
// pub struct ECDHSecret(agreement::ECDHSecret);
/*
impl ECDHSecret {
//     pub fn my_public_key(&self) -> &PublicKey {
//         self.0.my_public_key()
//     }

    pub fn encrypt(&self, input: &[u8], iv: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = Cipher::aes_256_cbc();

        // TODO(baloo): This might trigger a panic if size is not big enough
        let mut output = vec![0; input.len() * 2];
        output.resize(input.len() * 2, 0);
        let mut encrypter = Crypter::new(cipher, Mode::Encrypt, self.0.shared_secret(), Some(iv))
            .map_err(Error::Openssl)?;
        encrypter.pad(false);
        let mut out_size = 0;
        out_size += encrypter.update(input, output.as_mut_slice())?;
        out_size += encrypter.finalize(output.as_mut_slice())?;
        output.truncate(out_size);
        Ok(output)
    }

    pub fn decrypt(&self, input: &[u8], iv: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = Cipher::aes_256_cbc();

        // TODO(baloo): This might trigger a panic if size is not big enough
        let mut output = vec![0; input.len() * 2];
        output.resize(input.len() * 2, 0);
        let mut encrypter = Crypter::new(cipher, Mode::Decrypt, self.0.shared_secret(), Some(iv))
            .map_err(Error::Openssl)?;
        encrypter.pad(false);
        let mut out_size = 0;
        out_size += encrypter.update(input, output.as_mut_slice())?;
        out_size += encrypter.finalize(output.as_mut_slice())?;
        output.truncate(out_size);

        Ok(output)
    }
}
*/
#[derive(Debug, Deserialize)]
pub struct EncryptedPinToken(ByteBuf);

impl AsRef<[u8]> for EncryptedPinToken {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[derive(Debug)]
pub struct PinToken(Vec<u8>);

impl PinToken {
    pub fn auth(&self, client_hash_data: &ClientDataHash) -> Result<PinAuth, PinError> {
        if self.0.len() < 4 {
            return Err(PinError::PinIsTooShort);
        }

        let bytes = self.0.as_slice();
        if bytes.len() > 64 {
            return Err(PinError::PinIsTooLong(bytes.len()));
        }
        
        unimplemented!();
        /*let mut mac =
            Hmac::<Sha256>::new_varkey(self.as_ref()).map_err(|_| PinError::InvalidKeyLen)?;
        mac.input(client_hash_data.as_ref());

        let mut out = [0u8; 16];
        out.copy_from_slice(&mac.result().code().as_slice()[0..16]);

        Ok(PinAuth(out))*/
    }
}

impl AsRef<[u8]> for PinToken {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(Deserialize))]
pub struct PinAuth([u8; 16]);

impl AsRef<[u8]> for PinAuth {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl Serialize for PinAuth {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::serialize(&self.0[..], serializer)
    }
}

pub struct Pin(String);

impl fmt::Debug for Pin {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Pin(redacted)")
    }
}

impl Pin {
    pub fn new(value: &str) -> Pin {
        Pin(String::from(value))
    }

    pub fn for_pin_token(&self) -> PinAuth {
        let mut hasher = Sha256::new();
        hasher.input(&self.0.as_bytes()[..]);

        let mut output = [0u8; 16];
        let len = output.len();
        output.copy_from_slice(&hasher.result().as_slice()[..len]);

        PinAuth(output)
    }
}


#[derive(Debug, Copy, Clone)]
pub enum PinError {
    PinIsTooShort,
    PinIsTooLong(usize),
    InvalidKeyLen,
}

impl fmt::Display for PinError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PinError::PinIsTooShort => write!(f, "PinError: pin is too short"),
            PinError::PinIsTooLong(len) => write!(f, "PinError: pin is too long ({})", len),
            PinError::InvalidKeyLen => write!(f, "PinError: invalid key len"),
        }
    }
}

impl StdErrorT for PinError {
    fn description(&self) -> &str {
        match *self {
            PinError::PinIsTooShort => "PinError: pin is too short",
            PinError::PinIsTooLong(_) => "PinError: pin is too long",
            PinError::InvalidKeyLen => "PinError: hmac invalid key len",
        }
    }
}
