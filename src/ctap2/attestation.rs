use std::fmt;
#[cfg(test)]
use std::io::{self, Write};

#[cfg(test)]
use byteorder::{BigEndian, WriteBytesExt};
use nom::{number::complete::{be_u16, be_u32, be_u8}, Err as NomErr, IResult, named, do_parse, map_res, map, take, cond};
use serde::{Deserialize, Deserializer, Serialize, de::{Error as SerdeError, MapAccess, Visitor}};
#[cfg(test)]
use serde::{Serialize, Serializer, ser::{Error as SerdeError, SerializeMap}};

use serde_bytes::ByteBuf;

use super::server::Alg;
use super::utils::from_slice_stream;

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct RpIdHash(pub [u8; 32]);

impl RpIdHash {
    pub fn from(src: &[u8]) -> Result<RpIdHash, ()> {
        let mut payload = [0u8; 32];
        if src.len() != payload.len() {
            Err(())
        } else {
            payload.copy_from_slice(src);
            Ok(RpIdHash(payload))
        }
    }
}

impl fmt::Debug for RpIdHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let value = base64::encode_config(&self.0[..], base64::URL_SAFE_NO_PAD);
        write!(f, "RpIdHash({})", value)
    }
}

impl AsRef<[u8]> for RpIdHash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Extension {}

named!(
    parse_extensions<Vec<Extension>>,
    do_parse!(extensions: serde_to_nom >> (extensions))
);

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
                E: SerdeError,
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

#[derive(Debug, PartialEq, Eq)]
pub struct AttestedCredentialData {
    pub aaguid: AAGuid,
    pub credential_id: Vec<u8>,
    pub credential_public_key: crate::ctap2::commands::client_pin::PublicKey,
}

fn serde_to_nom<'a, Output>(input: &'a [u8]) -> IResult<&'a [u8], Output>
where
    Output: Deserialize<'a>,
{
    from_slice_stream(input).map_err(|e| nom::Err::Error(nom::error::make_error(input, nom::error::ErrorKind::NoneOf)))
        // can't use custom errorkind because of error type mismatch in parse_attested_cred_data
        //.map_err(|e| NomErr::Error(Context::Code(input, ErrorKind::Custom(e))))
//         .map_err(|_| NomErr::Error(Context::Code(input, ErrorKind::Custom(42))))
}

named!(
    parse_attested_cred_data<AttestedCredentialData>,
    do_parse!(
        aaguid: map_res!(take!(16), AAGuid::from)
            >> cred_len: be_u16
            >> credential_id: map!(take!(cred_len), Vec::from)
            >> credential_public_key: serde_to_nom
            >> (AttestedCredentialData {
                aaguid,
                credential_id,
                credential_public_key,
            })
    )
);

bitflags! {
    pub struct AuthenticatorDataFlags: u8 {
        const USER_PRESENT = 0x01;
        const USER_VERIFIED = 0x04;
        const ATTESTED = 0x40;
        const EXTENSION_DATA = 0x80;
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct AuthenticatorData {
    pub rp_id_hash: RpIdHash,
    pub flags: AuthenticatorDataFlags,
    pub counter: u32,
    pub credential_data: Option<AttestedCredentialData>,
    pub extensions: Vec<Extension>,
}

named!(
    parse_ad<AuthenticatorData>,
    do_parse!(
        rp_id_hash: map_res!(take!(32), RpIdHash::from) >>
        // be conservative, there is a couple of reserved values in
        // AuthenticatorDataFlags, just truncate the one we don't know
        flags: map!(be_u8, AuthenticatorDataFlags::from_bits_truncate) >>
        counter: be_u32 >>
        credential_data: cond!(flags.contains(AuthenticatorDataFlags::ATTESTED), parse_attested_cred_data) >>
        extensions: cond!(flags.contains(AuthenticatorDataFlags::EXTENSION_DATA), parse_extensions) >>
        // TODO(baloo): we should check for end of buffer and raise a parse
        //              parse error if data is still in the buffer
        //eof!() >>
        (AuthenticatorData{
            rp_id_hash,
            flags,
            counter,
            credential_data,
            extensions: extensions.unwrap_or_default(),
        })
    )
);

impl<'de> Deserialize<'de> for AuthenticatorData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AuthenticatorDataVisitor;

        impl<'de> Visitor<'de> for AuthenticatorDataVisitor {
            type Value = AuthenticatorData;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a byte array")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: SerdeError,
            {
                parse_ad(v)
                    .map(|(_input, value)| value)
                    .map_err(|e| match e {
                        NomErr::Incomplete(len) => E::custom(format!("need {:?} more bytes", len)),
                        // TODO(baloo): is that enough? should we be more
                        //              specific on the error type?
                        e => E::custom(e.to_string()),
                    })
            }
        }

        deserializer.deserialize_bytes(AuthenticatorDataVisitor)
    }
}

#[cfg(test)]
impl Serialize for AuthenticatorData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut data = io::Cursor::new(Vec::new());
        data.write_all(&self.rp_id_hash.0)
            .map_err(|e| S::Error::custom(format!("io error: {:?}", e)))?;
        data.write_all(&[self.flags.bits()])
            .map_err(|e| S::Error::custom(format!("io error: {:?}", e)))?;
        data.write_u32::<BigEndian>(self.counter)
            .map_err(|e| S::Error::custom(format!("io error: {:?}", e)))?;

        // TODO(baloo): need to yield credential_data and extensions, but that dependends on flags,
        //              should we consider another type system?

        data.set_position(0);
        let data = data.into_inner();
        serde_bytes::serialize(&data[..], serializer)
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
/// x509 encoded attestation certificate
pub struct AttestationCertificate(Vec<u8>);

impl AsRef<[u8]> for AttestationCertificate {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<'de> Deserialize<'de> for AttestationCertificate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CertificateVisitor;

        impl<'de> Visitor<'de> for CertificateVisitor {
            type Value = AttestationCertificate;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a byte array")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: SerdeError,
            {
                Ok(AttestationCertificate(Vec::from(v)))
            }
        }

        deserializer.deserialize_bytes(CertificateVisitor)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct Signature(ByteBuf);

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let value = base64::encode_config(&self.0[..], base64::URL_SAFE_NO_PAD);
        write!(f, "Signature({})", value)
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AttestationStatement {
    None,
    Packed(AttestationStatementPacked),
    // TODO(baloo): there is a couple other options than None and Packed:
    //              https://w3c.github.io/webauthn/#generating-an-attestation-object
    //              https://w3c.github.io/webauthn/#defined-attestation-formats
    //TPM,
    //AndroidKey,
    //AndroidSafetyNet,
    FidoU2F(AttestationStatementFidoU2F),
    // TODO(baloo): should we do an Unknow version? most likely
}

impl AttestationStatement {
    pub fn is_none(&self) -> bool {
        *self == AttestationStatement::None
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
// See https://www.w3.org/TR/webauthn/#fido-u2f-attestation
pub struct AttestationStatementFidoU2F {
    pub sig: Signature,

    #[serde(rename = "x5c")]
    /// Certificate chain in x509 format
    pub attestation_cert: Vec<AttestationCertificate>,
}

impl AttestationStatementFidoU2F {
    pub fn new(cert: &[u8], signature: &[u8]) -> Self {
        AttestationStatementFidoU2F {
            sig: Signature(ByteBuf::from(signature)),
            attestation_cert: vec![AttestationCertificate(Vec::from(cert))],
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
// TODO(baloo): there is a couple other options than x5c:
//              https://www.w3.org/TR/webauthn/#packed-attestation
pub struct AttestationStatementPacked {
    alg: Alg,
    sig: Signature,

    #[serde(rename = "x5c")]
    /// Certificate chain in x509 format
    attestation_cert: Vec<AttestationCertificate>,
}

#[derive(Debug, PartialEq, Eq)]
enum AttestationFormat {
    FidoU2F,
    Packed,
    None,
    // TOOD(baloo): only packed is implemented for now see spec:
    //              https://www.w3.org/TR/webauthn/#defined-attestation-formats
    //TPM,
    //AndroidKey,
    //AndroidSafetyNet,
}

impl<'de> Deserialize<'de> for AttestationFormat {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AttestationFormatVisitor;

        impl<'de> Visitor<'de> for AttestationFormatVisitor {
            type Value = AttestationFormat;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a cbor map")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: SerdeError,
            {
                match v {
                    "fido-u2f" => Ok(AttestationFormat::FidoU2F),
                    "packed" => Ok(AttestationFormat::Packed),
                    "none" => Ok(AttestationFormat::None),
                    other => Err(SerdeError::custom(format!("unexpected value {}", other))),
                }
            }
        }

        deserializer.deserialize_bytes(AttestationFormatVisitor)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct AttestationObject {
    pub auth_data: AuthenticatorData,
    pub att_statement: AttestationStatement,
}

impl<'de> Deserialize<'de> for AttestationObject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AttestationObjectVisitor;

        impl<'de> Visitor<'de> for AttestationObjectVisitor {
            type Value = AttestationObject;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a cbor map")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut format: Option<AttestationFormat> = None;
                let mut auth_data = None;
                let mut att_statement = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        // TODO(baloo): spec is wrong (or yubico got it wrong?) and format should
                        //              be numbered 1, and auth_data 2:
                        // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorMakeCredential
                        1 => {
                            if format.is_some() {
                                return Err(SerdeError::duplicate_field("fmt"));
                            }
                            format = Some(map.next_value()?);
                        }
                        2 => {
                            if auth_data.is_some() {
                                return Err(SerdeError::duplicate_field("auth_data"));
                            }
                            auth_data = Some(map.next_value()?);
                        }
                        3 => {
                            let format = format.as_ref().ok_or(SerdeError::missing_field("fmt"))?;
                            if att_statement.is_some() {
                                return Err(SerdeError::duplicate_field("att_statement"));
                            }
                            match format {
                                // This should not actually happen, but ...
                                AttestationFormat::None => {
                                    att_statement = Some(AttestationStatement::None);
                                }
                                AttestationFormat::Packed => {
                                    att_statement =
                                        Some(AttestationStatement::Packed(map.next_value()?));
                                }
                                AttestationFormat::FidoU2F => {
                                    att_statement =
                                        Some(AttestationStatement::FidoU2F(map.next_value()?));
                                }
                            }
                        }
                        k => return Err(M::Error::custom(format!("unexpected key: {:?}", k))),
                    }
                }

                let auth_data =
                    auth_data.ok_or_else(|| M::Error::custom("found no auth_data".to_string()))?;
                let att_statement = att_statement.unwrap_or(AttestationStatement::None);

                Ok(AttestationObject {
                    auth_data,
                    att_statement,
                })
            }
        }

        deserializer.deserialize_bytes(AttestationObjectVisitor)
    }
}

#[cfg(test)]
impl Serialize for AttestationObject {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map_len = 2;
        if !self.att_statement.is_none() {
            map_len += 1;
        }

        let mut map = serializer.serialize_map(Some(map_len))?;

        map.serialize_entry(&2, &self.auth_data)?;

        match self.att_statement {
            AttestationStatement::None => {
                map.serialize_entry(&1, &"none")?;
            }
            AttestationStatement::Packed(ref v) => {
                map.serialize_entry(&1, &"packed")?;
                map.serialize_entry(&3, v)?;
            }
        }

        map.end()
    }
}

#[cfg(test)]
mod test {
    use super::super::utils::from_slice_stream;
    use super::AttestationCertificate;
    use super::AttestationObject;
    use serde_cbor::from_slice;

    const SAMPLE_ATTESTATION: [u8; 1006] = [
        0xa3, 0x1, 0x66, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x64, 0x2, 0x58, 0xc4, 0x49, 0x96, 0xd,
        0xe5, 0x88, 0xe, 0x8c, 0x68, 0x74, 0x34, 0x17, 0xf, 0x64, 0x76, 0x60, 0x5b, 0x8f, 0xe4,
        0xae, 0xb9, 0xa2, 0x86, 0x32, 0xc7, 0x99, 0x5c, 0xf3, 0xba, 0x83, 0x1d, 0x97, 0x63, 0x41,
        0x0, 0x0, 0x0, 0x7, 0xcb, 0x69, 0x48, 0x1e, 0x8f, 0xf7, 0x40, 0x39, 0x93, 0xec, 0xa, 0x27,
        0x29, 0xa1, 0x54, 0xa8, 0x0, 0x40, 0xc3, 0xcf, 0x1, 0x3b, 0xc6, 0x26, 0x93, 0x28, 0xfb,
        0x7f, 0xa9, 0x76, 0xef, 0xa8, 0x4b, 0x66, 0x71, 0xad, 0xa9, 0x64, 0xea, 0xcb, 0x58, 0x76,
        0x54, 0x51, 0xa, 0xc8, 0x86, 0x4f, 0xbb, 0x53, 0x2d, 0xfb, 0x2, 0xfc, 0xdc, 0xa9, 0x84,
        0xc2, 0x5c, 0x67, 0x8a, 0x3a, 0xab, 0x57, 0xf3, 0x71, 0x77, 0xd3, 0xd4, 0x41, 0x64, 0x1,
        0x50, 0xca, 0x6c, 0x42, 0x73, 0x1c, 0x42, 0xcb, 0x81, 0xba, 0xa5, 0x1, 0x2, 0x3, 0x26,
        0x20, 0x1, 0x21, 0x58, 0x20, 0x9, 0x2e, 0x34, 0xfe, 0xa7, 0xd7, 0x32, 0xc8, 0xae, 0x4c,
        0xf6, 0x96, 0xbe, 0x7a, 0x12, 0xdc, 0x29, 0xd5, 0xf1, 0xd3, 0xf1, 0x55, 0x4d, 0xdc, 0x87,
        0xc4, 0xc, 0x9b, 0xd0, 0x17, 0xba, 0xf, 0x22, 0x58, 0x20, 0xc9, 0xf0, 0x97, 0x33, 0x55,
        0x36, 0x58, 0xd9, 0xdb, 0x76, 0xf5, 0xef, 0x95, 0xcf, 0x8a, 0xc7, 0xfc, 0xc1, 0xb6, 0x81,
        0x25, 0x5f, 0x94, 0x6b, 0x62, 0x13, 0x7d, 0xd0, 0xc4, 0x86, 0x53, 0xdb, 0x3, 0xa3, 0x63,
        0x61, 0x6c, 0x67, 0x26, 0x63, 0x73, 0x69, 0x67, 0x58, 0x48, 0x30, 0x46, 0x2, 0x21, 0x0,
        0xac, 0x2a, 0x78, 0xa8, 0xaf, 0x18, 0x80, 0x39, 0x73, 0x8d, 0x3, 0x5e, 0x4, 0x4d, 0x94,
        0x4f, 0x3f, 0x57, 0xce, 0x88, 0x41, 0xfa, 0x81, 0x50, 0x40, 0xb6, 0xd1, 0x95, 0xb5, 0xeb,
        0xe4, 0x6f, 0x2, 0x21, 0x0, 0x8f, 0xf4, 0x15, 0xc9, 0xb3, 0x6d, 0x1c, 0xd, 0x4c, 0xa3,
        0xcf, 0x99, 0x8a, 0x46, 0xd4, 0x4c, 0x8b, 0x5c, 0x26, 0x3f, 0xdf, 0x22, 0x6c, 0x9b, 0x23,
        0x83, 0x8b, 0x69, 0x47, 0x67, 0x48, 0x45, 0x63, 0x78, 0x35, 0x63, 0x81, 0x59, 0x2, 0xc1,
        0x30, 0x82, 0x2, 0xbd, 0x30, 0x82, 0x1, 0xa5, 0xa0, 0x3, 0x2, 0x1, 0x2, 0x2, 0x4, 0x18,
        0xac, 0x46, 0xc0, 0x30, 0xd, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0xb,
        0x5, 0x0, 0x30, 0x2e, 0x31, 0x2c, 0x30, 0x2a, 0x6, 0x3, 0x55, 0x4, 0x3, 0x13, 0x23, 0x59,
        0x75, 0x62, 0x69, 0x63, 0x6f, 0x20, 0x55, 0x32, 0x46, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20,
        0x43, 0x41, 0x20, 0x53, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x20, 0x34, 0x35, 0x37, 0x32, 0x30,
        0x30, 0x36, 0x33, 0x31, 0x30, 0x20, 0x17, 0xd, 0x31, 0x34, 0x30, 0x38, 0x30, 0x31, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0xf, 0x32, 0x30, 0x35, 0x30, 0x30, 0x39, 0x30,
        0x34, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x6e, 0x31, 0xb, 0x30, 0x9, 0x6, 0x3,
        0x55, 0x4, 0x6, 0x13, 0x2, 0x53, 0x45, 0x31, 0x12, 0x30, 0x10, 0x6, 0x3, 0x55, 0x4, 0xa,
        0xc, 0x9, 0x59, 0x75, 0x62, 0x69, 0x63, 0x6f, 0x20, 0x41, 0x42, 0x31, 0x22, 0x30, 0x20,
        0x6, 0x3, 0x55, 0x4, 0xb, 0xc, 0x19, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63,
        0x61, 0x74, 0x6f, 0x72, 0x20, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f,
        0x6e, 0x31, 0x27, 0x30, 0x25, 0x6, 0x3, 0x55, 0x4, 0x3, 0xc, 0x1e, 0x59, 0x75, 0x62, 0x69,
        0x63, 0x6f, 0x20, 0x55, 0x32, 0x46, 0x20, 0x45, 0x45, 0x20, 0x53, 0x65, 0x72, 0x69, 0x61,
        0x6c, 0x20, 0x34, 0x31, 0x33, 0x39, 0x34, 0x33, 0x34, 0x38, 0x38, 0x30, 0x59, 0x30, 0x13,
        0x6, 0x7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x2, 0x1, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x3, 0x1, 0x7, 0x3, 0x42, 0x0, 0x4, 0x79, 0xea, 0x3b, 0x2c, 0x7c, 0x49, 0x70, 0x10, 0x62,
        0x23, 0xc, 0xd2, 0x3f, 0xeb, 0x60, 0xe5, 0x29, 0x31, 0x71, 0xd4, 0x83, 0xf1, 0x0, 0xbe,
        0x85, 0x9d, 0x6b, 0xf, 0x83, 0x97, 0x3, 0x1, 0xb5, 0x46, 0xcd, 0xd4, 0x6e, 0xcf, 0xca,
        0xe3, 0xe3, 0xf3, 0xf, 0x81, 0xe9, 0xed, 0x62, 0xbd, 0x26, 0x8d, 0x4c, 0x1e, 0xbd, 0x37,
        0xb3, 0xbc, 0xbe, 0x92, 0xa8, 0xc2, 0xae, 0xeb, 0x4e, 0x3a, 0xa3, 0x6c, 0x30, 0x6a, 0x30,
        0x22, 0x6, 0x9, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0xc4, 0xa, 0x2, 0x4, 0x15, 0x31, 0x2e,
        0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x31, 0x34, 0x38, 0x32,
        0x2e, 0x31, 0x2e, 0x37, 0x30, 0x13, 0x6, 0xb, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0xe5, 0x1c,
        0x2, 0x1, 0x1, 0x4, 0x4, 0x3, 0x2, 0x5, 0x20, 0x30, 0x21, 0x6, 0xb, 0x2b, 0x6, 0x1, 0x4,
        0x1, 0x82, 0xe5, 0x1c, 0x1, 0x1, 0x4, 0x4, 0x12, 0x4, 0x10, 0xcb, 0x69, 0x48, 0x1e, 0x8f,
        0xf7, 0x40, 0x39, 0x93, 0xec, 0xa, 0x27, 0x29, 0xa1, 0x54, 0xa8, 0x30, 0xc, 0x6, 0x3, 0x55,
        0x1d, 0x13, 0x1, 0x1, 0xff, 0x4, 0x2, 0x30, 0x0, 0x30, 0xd, 0x6, 0x9, 0x2a, 0x86, 0x48,
        0x86, 0xf7, 0xd, 0x1, 0x1, 0xb, 0x5, 0x0, 0x3, 0x82, 0x1, 0x1, 0x0, 0x97, 0x9d, 0x3, 0x97,
        0xd8, 0x60, 0xf8, 0x2e, 0xe1, 0x5d, 0x31, 0x1c, 0x79, 0x6e, 0xba, 0xfb, 0x22, 0xfa, 0xa7,
        0xe0, 0x84, 0xd9, 0xba, 0xb4, 0xc6, 0x1b, 0xbb, 0x57, 0xf3, 0xe6, 0xb4, 0xc1, 0x8a, 0x48,
        0x37, 0xb8, 0x5c, 0x3c, 0x4e, 0xdb, 0xe4, 0x83, 0x43, 0xf4, 0xd6, 0xa5, 0xd9, 0xb1, 0xce,
        0xda, 0x8a, 0xe1, 0xfe, 0xd4, 0x91, 0x29, 0x21, 0x73, 0x5, 0x8e, 0x5e, 0xe1, 0xcb, 0xdd,
        0x6b, 0xda, 0xc0, 0x75, 0x57, 0xc6, 0xa0, 0xe8, 0xd3, 0x68, 0x25, 0xba, 0x15, 0x9e, 0x7f,
        0xb5, 0xad, 0x8c, 0xda, 0xf8, 0x4, 0x86, 0x8c, 0xf9, 0xe, 0x8f, 0x1f, 0x8a, 0xea, 0x17,
        0xc0, 0x16, 0xb5, 0x5c, 0x2a, 0x7a, 0xd4, 0x97, 0xc8, 0x94, 0xfb, 0x71, 0xd7, 0x53, 0xd7,
        0x9b, 0x9a, 0x48, 0x4b, 0x6c, 0x37, 0x6d, 0x72, 0x3b, 0x99, 0x8d, 0x2e, 0x1d, 0x43, 0x6,
        0xbf, 0x10, 0x33, 0xb5, 0xae, 0xf8, 0xcc, 0xa5, 0xcb, 0xb2, 0x56, 0x8b, 0x69, 0x24, 0x22,
        0x6d, 0x22, 0xa3, 0x58, 0xab, 0x7d, 0x87, 0xe4, 0xac, 0x5f, 0x2e, 0x9, 0x1a, 0xa7, 0x15,
        0x79, 0xf3, 0xa5, 0x69, 0x9, 0x49, 0x7d, 0x72, 0xf5, 0x4e, 0x6, 0xba, 0xc1, 0xc3, 0xb4,
        0x41, 0x3b, 0xba, 0x5e, 0xaf, 0x94, 0xc3, 0xb6, 0x4f, 0x34, 0xf9, 0xeb, 0xa4, 0x1a, 0xcb,
        0x6a, 0xe2, 0x83, 0x77, 0x6d, 0x36, 0x46, 0x53, 0x78, 0x48, 0xfe, 0xe8, 0x84, 0xbd, 0xdd,
        0xf5, 0xb1, 0xba, 0x57, 0x98, 0x54, 0xcf, 0xfd, 0xce, 0xba, 0xc3, 0x44, 0x5, 0x95, 0x27,
        0xe5, 0x6d, 0xd5, 0x98, 0xf8, 0xf5, 0x66, 0x71, 0x5a, 0xbe, 0x43, 0x1, 0xdd, 0x19, 0x11,
        0x30, 0xe6, 0xb9, 0xf0, 0xc6, 0x40, 0x39, 0x12, 0x53, 0xe2, 0x29, 0x80, 0x3f, 0x3a, 0xef,
        0x27, 0x4b, 0xed, 0xbf, 0xde, 0x3f, 0xcb, 0xbd, 0x42, 0xea, 0xd6, 0x79,
    ];

    const SAMPLE_CERT_CHAIN: [u8; 709] = [
        0x81, 0x59, 0x2, 0xc1, 0x30, 0x82, 0x2, 0xbd, 0x30, 0x82, 0x1, 0xa5, 0xa0, 0x3, 0x2, 0x1,
        0x2, 0x2, 0x4, 0x18, 0xac, 0x46, 0xc0, 0x30, 0xd, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7,
        0xd, 0x1, 0x1, 0xb, 0x5, 0x0, 0x30, 0x2e, 0x31, 0x2c, 0x30, 0x2a, 0x6, 0x3, 0x55, 0x4, 0x3,
        0x13, 0x23, 0x59, 0x75, 0x62, 0x69, 0x63, 0x6f, 0x20, 0x55, 0x32, 0x46, 0x20, 0x52, 0x6f,
        0x6f, 0x74, 0x20, 0x43, 0x41, 0x20, 0x53, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x20, 0x34, 0x35,
        0x37, 0x32, 0x30, 0x30, 0x36, 0x33, 0x31, 0x30, 0x20, 0x17, 0xd, 0x31, 0x34, 0x30, 0x38,
        0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0xf, 0x32, 0x30, 0x35, 0x30,
        0x30, 0x39, 0x30, 0x34, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x6e, 0x31, 0xb,
        0x30, 0x9, 0x6, 0x3, 0x55, 0x4, 0x6, 0x13, 0x2, 0x53, 0x45, 0x31, 0x12, 0x30, 0x10, 0x6,
        0x3, 0x55, 0x4, 0xa, 0xc, 0x9, 0x59, 0x75, 0x62, 0x69, 0x63, 0x6f, 0x20, 0x41, 0x42, 0x31,
        0x22, 0x30, 0x20, 0x6, 0x3, 0x55, 0x4, 0xb, 0xc, 0x19, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e,
        0x74, 0x69, 0x63, 0x61, 0x74, 0x6f, 0x72, 0x20, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61,
        0x74, 0x69, 0x6f, 0x6e, 0x31, 0x27, 0x30, 0x25, 0x6, 0x3, 0x55, 0x4, 0x3, 0xc, 0x1e, 0x59,
        0x75, 0x62, 0x69, 0x63, 0x6f, 0x20, 0x55, 0x32, 0x46, 0x20, 0x45, 0x45, 0x20, 0x53, 0x65,
        0x72, 0x69, 0x61, 0x6c, 0x20, 0x34, 0x31, 0x33, 0x39, 0x34, 0x33, 0x34, 0x38, 0x38, 0x30,
        0x59, 0x30, 0x13, 0x6, 0x7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x2, 0x1, 0x6, 0x8, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x3, 0x1, 0x7, 0x3, 0x42, 0x0, 0x4, 0x79, 0xea, 0x3b, 0x2c, 0x7c, 0x49,
        0x70, 0x10, 0x62, 0x23, 0xc, 0xd2, 0x3f, 0xeb, 0x60, 0xe5, 0x29, 0x31, 0x71, 0xd4, 0x83,
        0xf1, 0x0, 0xbe, 0x85, 0x9d, 0x6b, 0xf, 0x83, 0x97, 0x3, 0x1, 0xb5, 0x46, 0xcd, 0xd4, 0x6e,
        0xcf, 0xca, 0xe3, 0xe3, 0xf3, 0xf, 0x81, 0xe9, 0xed, 0x62, 0xbd, 0x26, 0x8d, 0x4c, 0x1e,
        0xbd, 0x37, 0xb3, 0xbc, 0xbe, 0x92, 0xa8, 0xc2, 0xae, 0xeb, 0x4e, 0x3a, 0xa3, 0x6c, 0x30,
        0x6a, 0x30, 0x22, 0x6, 0x9, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0xc4, 0xa, 0x2, 0x4, 0x15,
        0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x31, 0x34,
        0x38, 0x32, 0x2e, 0x31, 0x2e, 0x37, 0x30, 0x13, 0x6, 0xb, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82,
        0xe5, 0x1c, 0x2, 0x1, 0x1, 0x4, 0x4, 0x3, 0x2, 0x5, 0x20, 0x30, 0x21, 0x6, 0xb, 0x2b, 0x6,
        0x1, 0x4, 0x1, 0x82, 0xe5, 0x1c, 0x1, 0x1, 0x4, 0x4, 0x12, 0x4, 0x10, 0xcb, 0x69, 0x48,
        0x1e, 0x8f, 0xf7, 0x40, 0x39, 0x93, 0xec, 0xa, 0x27, 0x29, 0xa1, 0x54, 0xa8, 0x30, 0xc,
        0x6, 0x3, 0x55, 0x1d, 0x13, 0x1, 0x1, 0xff, 0x4, 0x2, 0x30, 0x0, 0x30, 0xd, 0x6, 0x9, 0x2a,
        0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0xb, 0x5, 0x0, 0x3, 0x82, 0x1, 0x1, 0x0, 0x97, 0x9d,
        0x3, 0x97, 0xd8, 0x60, 0xf8, 0x2e, 0xe1, 0x5d, 0x31, 0x1c, 0x79, 0x6e, 0xba, 0xfb, 0x22,
        0xfa, 0xa7, 0xe0, 0x84, 0xd9, 0xba, 0xb4, 0xc6, 0x1b, 0xbb, 0x57, 0xf3, 0xe6, 0xb4, 0xc1,
        0x8a, 0x48, 0x37, 0xb8, 0x5c, 0x3c, 0x4e, 0xdb, 0xe4, 0x83, 0x43, 0xf4, 0xd6, 0xa5, 0xd9,
        0xb1, 0xce, 0xda, 0x8a, 0xe1, 0xfe, 0xd4, 0x91, 0x29, 0x21, 0x73, 0x5, 0x8e, 0x5e, 0xe1,
        0xcb, 0xdd, 0x6b, 0xda, 0xc0, 0x75, 0x57, 0xc6, 0xa0, 0xe8, 0xd3, 0x68, 0x25, 0xba, 0x15,
        0x9e, 0x7f, 0xb5, 0xad, 0x8c, 0xda, 0xf8, 0x4, 0x86, 0x8c, 0xf9, 0xe, 0x8f, 0x1f, 0x8a,
        0xea, 0x17, 0xc0, 0x16, 0xb5, 0x5c, 0x2a, 0x7a, 0xd4, 0x97, 0xc8, 0x94, 0xfb, 0x71, 0xd7,
        0x53, 0xd7, 0x9b, 0x9a, 0x48, 0x4b, 0x6c, 0x37, 0x6d, 0x72, 0x3b, 0x99, 0x8d, 0x2e, 0x1d,
        0x43, 0x6, 0xbf, 0x10, 0x33, 0xb5, 0xae, 0xf8, 0xcc, 0xa5, 0xcb, 0xb2, 0x56, 0x8b, 0x69,
        0x24, 0x22, 0x6d, 0x22, 0xa3, 0x58, 0xab, 0x7d, 0x87, 0xe4, 0xac, 0x5f, 0x2e, 0x9, 0x1a,
        0xa7, 0x15, 0x79, 0xf3, 0xa5, 0x69, 0x9, 0x49, 0x7d, 0x72, 0xf5, 0x4e, 0x6, 0xba, 0xc1,
        0xc3, 0xb4, 0x41, 0x3b, 0xba, 0x5e, 0xaf, 0x94, 0xc3, 0xb6, 0x4f, 0x34, 0xf9, 0xeb, 0xa4,
        0x1a, 0xcb, 0x6a, 0xe2, 0x83, 0x77, 0x6d, 0x36, 0x46, 0x53, 0x78, 0x48, 0xfe, 0xe8, 0x84,
        0xbd, 0xdd, 0xf5, 0xb1, 0xba, 0x57, 0x98, 0x54, 0xcf, 0xfd, 0xce, 0xba, 0xc3, 0x44, 0x5,
        0x95, 0x27, 0xe5, 0x6d, 0xd5, 0x98, 0xf8, 0xf5, 0x66, 0x71, 0x5a, 0xbe, 0x43, 0x1, 0xdd,
        0x19, 0x11, 0x30, 0xe6, 0xb9, 0xf0, 0xc6, 0x40, 0x39, 0x12, 0x53, 0xe2, 0x29, 0x80, 0x3f,
        0x3a, 0xef, 0x27, 0x4b, 0xed, 0xbf, 0xde, 0x3f, 0xcb, 0xbd, 0x42, 0xea, 0xd6, 0x79,
    ];

    #[test]
    fn parse_cert_chain() {
        let cert: AttestationCertificate = from_slice(&SAMPLE_CERT_CHAIN[1..]).unwrap();
        assert_eq!(&cert.0[..], &SAMPLE_CERT_CHAIN[4..]);

        let _cert: Vec<AttestationCertificate> = from_slice(&SAMPLE_CERT_CHAIN).unwrap();
    }

    #[test]
    fn parse_attestation_object() {
        let value: AttestationObject = from_slice(&SAMPLE_ATTESTATION).unwrap();
        println!("{:?}", value);

        //assert_eq!(true, false);
    }

    #[test]
    fn parse_reader() {
        let v: Vec<u8> = vec![
            0x66, 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72, 0x66, 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72,
        ];
        let (rest, value): (&[u8], String) = from_slice_stream(&v[..]).unwrap();
        assert_eq!(value, "foobar");
        assert_eq!(rest, &[0x66, 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72]);
        let (rest, value): (&[u8], String) = from_slice_stream(rest).unwrap();
        assert_eq!(value, "foobar");
        let empty: Vec<u8> = Vec::new();
        assert_eq!(rest, &empty[..]);
    }
}
