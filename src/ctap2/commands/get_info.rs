use super::{RequestCtap2, Error, Command, StatusCode}; 
use std::fmt;
use serde::{Deserialize, Deserializer, Serialize, de::{Error as SError, Visitor, MapAccess}};
use serde_cbor::de::from_slice;
use serde_cbor::Value;
use crate::transport::{Error as TransportError, FidoDevice};

#[derive(Serialize, PartialEq, Eq, Clone)]
pub struct AAGuid(pub [u8; 16]);

impl AAGuid {
    fn from(src: &[u8]) -> Result<AAGuid, ()> {
        let mut payload = [0u8; 16];
        if src.len() != payload.len() {
            Err(())
        } else {
            payload.copy_from_slice(src);
            Ok(AAGuid(payload))
        }
    }

    pub fn empty() -> Self {
        AAGuid([0u8; 16])
    }
}

impl fmt::Debug for AAGuid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "AAGuid({:x}{:x}{:x}{:x}-{:x}{:x}-{:x}{:x}-{:x}{:x}-{:x}{:x}{:x}{:x}{:x}{:x})",
            self.0[0],
            self.0[1],
            self.0[2],
            self.0[3],
            self.0[4],
            self.0[5],
            self.0[6],
            self.0[7],
            self.0[8],
            self.0[9],
            self.0[10],
            self.0[11],
            self.0[12],
            self.0[13],
            self.0[14],
            self.0[15]
        )
    }
}

impl<'de> Deserialize<'de> for AAGuid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AAGuidVisitor;

        impl<'de> Visitor<'de> for AAGuidVisitor {
            type Value = AAGuid;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a byte array")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: SError,
            {
                if v.len() != 16 {
                    return Err(E::custom("expecting 16 bytes data"));
                }

                let mut buf = [0u8; 16];

                buf.copy_from_slice(v);

                Ok(AAGuid(buf))
            }
        }

        deserializer.deserialize_bytes(AAGuidVisitor)
    }
}

#[derive(Debug)]
pub struct GetInfo {}

impl Default for GetInfo {
    fn default() -> GetInfo {
        GetInfo {}
    }
}

impl RequestCtap2 for GetInfo {
    type Output = AuthenticatorInfo;

    fn command() -> Command {
        Command::GetInfo
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
                trace!(
                    "parsing authenticator info data: {:#04X?}", &input[1..]
                );
                let authenticator_info = from_slice(&input[1..]).map_err(Error::Parsing)?;
                Ok(authenticator_info)
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

#[derive(Debug, Deserialize, Clone)]
pub struct AuthenticatorOptions {
    /// Indicates that the device is attached to the client and therefore can’t
    /// be removed and used on another client.
    #[serde(rename = "plat")]
    platform_device: bool,
    /// Indicates that the device is capable of storing keys on the device
    /// itself and therefore can satisfy the authenticatorGetAssertion request
    /// with allowList parameter not specified or empty.
    #[serde(rename = "rk")]
    resident_key: bool,

    /// Client PIN:
    ///  If present and set to true, it indicates that the device is capable of
    ///   accepting a PIN from the client and PIN has been set.
    ///  If present and set to false, it indicates that the device is capable of
    ///   accepting a PIN from the client and PIN has not been set yet.
    ///  If absent, it indicates that the device is not capable of accepting a
    ///   PIN from the client.
    /// Client PIN is one of the ways to do user verification.
    #[serde(rename = "clientPin")]
    client_pin: Option<bool>,

    /// Indicates that the device is capable of testing user presence.
    #[serde(rename = "up")]
    user_presence: bool,

    /// Indicates that the device is capable of verifying the user within
    /// itself. For example, devices with UI, biometrics fall into this
    /// category.
    ///  If present and set to true, it indicates that the device is capable of
    ///   user verification within itself and has been configured.
    ///  If present and set to false, it indicates that the device is capable of
    ///   user verification within itself and has not been yet configured. For
    ///   example, a biometric device that has not yet been configured will
    ///   return this parameter set to false.
    ///  If absent, it indicates that the device is not capable of user
    ///   verification within itself.
    /// A device that can only do Client PIN will not return the "uv" parameter.
    /// If a device is capable of verifying the user within itself as well as
    /// able to do Client PIN, it will return both "uv" and the Client PIN
    /// option.
    #[serde(rename = "uv")]
    user_verification: Option<bool>,
}

impl Default for AuthenticatorOptions {
    fn default() -> Self {
        AuthenticatorOptions {
            platform_device: false,
            resident_key: false,
            client_pin: None,
            user_presence: true,
            user_verification: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticatorInfo {
    pub(crate) versions: Vec<String>,
    pub(crate) extensions: Vec<String>,
    pub(crate) aaguid: AAGuid,
    pub(crate) options: AuthenticatorOptions,
    pub(crate) max_msg_size: Option<usize>,
    pub(crate) pin_protocols: Vec<u32>,
}

impl AuthenticatorInfo {
    /// Checks if client pin is set, if set platform is expected to send pin
    /// along with all make credentials or get attestation commands
    pub fn client_pin_set(&self) -> bool {
        self.options.client_pin == Some(true)
    }
}

impl<'de> Deserialize<'de> for AuthenticatorInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AuthenticatorInfoVisitor;

        impl<'de> Visitor<'de> for AuthenticatorInfoVisitor {
            type Value = AuthenticatorInfo;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a byte array")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut versions = Vec::new();
                let mut extensions = Vec::new();
                let mut aaguid = None;
                let mut options = AuthenticatorOptions::default();
                let mut max_msg_size = None;
                let mut pin_protocols = Vec::new();

                while let Some(key) = map.next_key()? {
                    match key {
                        1 => {
                            if !versions.is_empty() {
                                return Err(serde::de::Error::duplicate_field("versions"));
                            }
                            versions = map.next_value()?;
                        }
                        2 => {
                            if !extensions.is_empty() {
                                return Err(serde::de::Error::duplicate_field("extensions"));
                            }
                            extensions = map.next_value()?;
                        }
                        3 => {
                            if aaguid.is_some() {
                                return Err(serde::de::Error::duplicate_field("aaguid"));
                            }
                            aaguid = Some(map.next_value()?);
                        }
                        4 => {
                            options = map.next_value()?;
                        }
                        5 => {
                            max_msg_size = Some(map.next_value()?);
                        }
                        6 => {
                            pin_protocols = map.next_value()?;
                        }
                        k => return Err(M::Error::custom(format!("unexpected key: {:?}", k))),
                    }
                }

                if versions.is_empty() {
                    return Err(M::Error::custom(
                        "expected at least one version, got none".to_string(),
                    ));
                }

                if let Some(aaguid) = aaguid {
                    Ok(AuthenticatorInfo {
                        versions,
                        extensions,
                        aaguid,
                        options,
                        max_msg_size,
                        pin_protocols,
                    })
                } else {
                    Err(M::Error::custom("No AAGuid specified".to_string()))
                }
            }
        }

        deserializer.deserialize_bytes(AuthenticatorInfoVisitor)
    }
}
