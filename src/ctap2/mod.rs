use crate::consts::*;
use crate::ctap2::commands::get_info::GetInfo;
use crate::ctap2::commands::RequestCtap2;
use crate::transport;
use crate::u2fprotocol::status_word_to_result;
use crate::u2ftypes::*;
use crate::util::io_err;
use rand::{thread_rng, RngCore};
use std::ffi::CString;
use std::io;
use std::io::{Read, Write};
pub mod attestation;
pub mod commands;
pub mod server;
pub mod utils;

////////////////////////////////////////////////////////////////////////
// Device Commands
////////////////////////////////////////////////////////////////////////

pub fn ctap2_init_device<T>(dev: &mut T) -> bool
where
    T: U2FDevice + Read + Write + std::fmt::Debug,
{
    let mut nonce = [0u8; 8];
    thread_rng().fill_bytes(&mut nonce);

    // Initialize the device and check its version.
    init_device(dev, &nonce)
        .and_then(|_| init_ctap2(dev))
        .and_then(|_| is_v2_device(dev))
        .is_ok()
}

////////////////////////////////////////////////////////////////////////
// Internal Device Commands
////////////////////////////////////////////////////////////////////////

fn init_device<T>(dev: &mut T, nonce: &[u8]) -> io::Result<()>
where
    T: U2FDevice + Read + Write + std::fmt::Debug,
{
    assert_eq!(nonce.len(), INIT_NONCE_SIZE);
    // Send Init to broadcast address to create a new channel
    let raw = sendrecv(dev, HIDCmd::Init, nonce)?;
    let rsp = U2FHIDInitResp::read(&raw, nonce)?;
    // Get the new Channel ID
    dev.set_cid(rsp.cid);

    let vendor = dev
        .get_property("Manufacturer")
        .unwrap_or_else(|_| String::from("Unknown Vendor"));
    let product = dev
        .get_property("Product")
        .unwrap_or_else(|_| String::from("Unknown Device"));

    dev.set_device_info(U2FDeviceInfo {
        vendor_name: vendor.as_bytes().to_vec(),
        device_name: product.as_bytes().to_vec(),
        version_interface: rsp.version_interface,
        version_major: rsp.version_major,
        version_minor: rsp.version_minor,
        version_build: rsp.version_build,
        cap_flags: rsp.cap_flags,
    });

    Ok(())
}

fn is_v2_device<T>(dev: &mut T) -> io::Result<bool>
where
    T: U2FDevice + Read + Write,
{
    if dev.get_device_info().supports_fido1() {
        let (data, status) = send_apdu(dev, U2F_VERSION, 0x00, &[])?;
        let actual = CString::new(data)?;
        let expected = CString::new("U2F_V2")?;
        match status_word_to_result(status, actual == expected) {
            Ok(true) => Ok(true),
            Ok(false) => Err(io_err("Device should support fido1, but isn't v2 device!")),
            e => e,
        }
    } else {
        Ok(false)
    }
}

fn init_ctap2<T>(dev: &mut T) -> io::Result<()>
where
    T: U2FDevice + Read + Write + std::fmt::Debug,
{
    if dev.get_device_info().supports_fido2() {
        let command = GetInfo::default();
        let info = send_cbor(dev, &command).map_err(|e| {
            warn!("ERROR {:?}", e);
            io::Error::new(io::ErrorKind::Other, "TODO")
        })?; // TODO(MS)
        debug!("{:?} infos: {:?}", dev.get_cid(), info);

        dev.set_authenticator_info(info);
    }
    Ok(())
}

////////////////////////////////////////////////////////////////////////
// Device Communication Functions
////////////////////////////////////////////////////////////////////////

pub fn sendrecv<T>(dev: &mut T, cmd: HIDCmd, send: &[u8]) -> io::Result<Vec<u8>>
where
    T: U2FDevice + Read + Write,
{
    // Send initialization packet.
    let mut count = U2FHIDInit::write(dev, cmd.into(), send)?;

    // Send continuation packets.
    let mut sequence = 0u8;
    while count < send.len() {
        count += U2FHIDCont::write(dev, sequence, &send[count..])?;
        sequence += 1;
    }

    // Now we read. This happens in 2 chunks: The initial packet, which has the
    // size we expect overall, then continuation packets, which will fill in
    // data until we have everything.
    let mut data = U2FHIDInit::read(dev)?;

    let mut sequence = 0u8;
    while data.len() < data.capacity() {
        let max = data.capacity() - data.len();
        data.extend_from_slice(&U2FHIDCont::read(dev, sequence, max)?);
        sequence += 1;
    }

    Ok(data)
}

pub(crate) fn send_apdu<T>(
    dev: &mut T,
    cmd: u8,
    p1: u8,
    send: &[u8],
) -> io::Result<(Vec<u8>, [u8; 2])>
where
    T: U2FDevice + Read + Write,
{
    let apdu = U2FAPDUHeader::serialize(cmd.into(), p1, send)?;
    let mut data = sendrecv(dev, HIDCmd::Msg, &apdu)?;

    if data.len() < 2 {
        return Err(io_err("unexpected response"));
    }

    let split_at = data.len() - 2;
    let status = data.split_off(split_at);
    Ok((data, [status[0], status[1]]))
}

pub(crate) fn send_cbor<'msg, T, Req: RequestCtap2>(
    dev: &mut T,
    msg: &'msg Req,
) -> Result<Req::Output, transport::Error>
// fn send_cbor<T, O>(dev: &mut T, msg: &dyn RequestCtap2<Output = O>) -> Result<O, transport::Error>
where
    T: U2FDevice + Read + Write + std::fmt::Debug,
{
    debug!("sending {:?} to {:?}", msg, dev);

    let data = msg.wire_format(dev)?;
    let mut cbor: Vec<u8> = Vec::with_capacity(data.len() + 1);
    // CTAP2 command
    cbor.push(Req::command() as u8);
    // payload
    cbor.extend(data);

    let resp = sendrecv(dev, HIDCmd::Cbor, &cbor)?;

    debug!("got from {:?}: {:?}", dev, to_hex(&resp, " "));

    let res = Ok(msg.handle_response_ctap2(dev, &resp)?);
    res
}

////////////////////////////////////////////////////////////////////////
// Tests
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::{init_ctap2, init_device, send_apdu, sendrecv, U2FDevice};
    use crate::consts::{Capability, HIDCmd, CID_BROADCAST, SW_NO_ERROR};
    use crate::ctap2::commands::get_info::test::{AAGUID_RAW, AUTHENTICATOR_INFO_PAYLOAD};
    use crate::ctap2::commands::get_info::{AAGuid, AuthenticatorInfo, AuthenticatorOptions};
    use rand::{thread_rng, RngCore};

    const IN_HID_RPT_SIZE: usize = 64;
    const OUT_HID_RPT_SIZE: usize = 64;
    mod platform {
        use super::{IN_HID_RPT_SIZE, OUT_HID_RPT_SIZE};
        use crate::ctap2::commands::client_pin::ECDHSecret;
        use crate::ctap2::commands::get_info::AuthenticatorInfo;
        use std::io;
        use std::io::{Read, Write};

        use crate::consts::CID_BROADCAST;
        use crate::u2ftypes::{U2FDevice, U2FDeviceInfo};

        #[derive(Debug)]
        pub struct TestDevice {
            cid: [u8; 4],
            reads: Vec<[u8; IN_HID_RPT_SIZE]>,
            writes: Vec<[u8; OUT_HID_RPT_SIZE + 1]>,
            dev_info: Option<U2FDeviceInfo>,
            authenticator_info: Option<AuthenticatorInfo>,
            secret: Option<ECDHSecret>,
        }

        impl TestDevice {
            pub fn new() -> TestDevice {
                TestDevice {
                    cid: CID_BROADCAST,
                    reads: vec![],
                    writes: vec![],
                    dev_info: None,
                    authenticator_info: None,
                    secret: None,
                }
            }

            pub fn add_write(&mut self, packet: &[u8], fill_value: u8) {
                // Add one to deal with record index check
                let mut write = [fill_value; OUT_HID_RPT_SIZE + 1];
                // Make sure we start with a 0, for HID record index
                write[0] = 0;
                // Clone packet data in at 1, since front is padded with HID record index
                write[1..=packet.len()].clone_from_slice(packet);
                self.writes.push(write);
            }

            pub fn add_read(&mut self, packet: &[u8], fill_value: u8) {
                let mut read = [fill_value; IN_HID_RPT_SIZE];
                read[..packet.len()].clone_from_slice(packet);
                self.reads.push(read);
            }
        }

        impl Write for TestDevice {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                // Pop a vector from the expected writes, check for quality
                // against bytes array.
                assert!(!self.writes.is_empty(), "Ran out of expected write values!");
                let check = self.writes.remove(0);
                assert_eq!(check.len(), bytes.len());
                assert_eq!(&check[..], bytes);
                Ok(bytes.len())
            }

            // nop
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        impl Read for TestDevice {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                assert!(!self.reads.is_empty(), "Ran out of read values!");
                let check = self.reads.remove(0);
                assert_eq!(check.len(), bytes.len());
                bytes.clone_from_slice(&check[..]);
                Ok(check.len())
            }
        }

        impl Drop for TestDevice {
            fn drop(&mut self) {
                assert!(self.reads.is_empty());
                assert!(self.writes.is_empty());
            }
        }

        impl U2FDevice for TestDevice {
            fn get_cid<'a>(&'a self) -> &'a [u8; 4] {
                &self.cid
            }

            fn set_cid(&mut self, cid: [u8; 4]) {
                self.cid = cid;
            }

            fn in_rpt_size(&self) -> usize {
                IN_HID_RPT_SIZE
            }

            fn out_rpt_size(&self) -> usize {
                OUT_HID_RPT_SIZE
            }

            fn get_property(&self, prop_name: &str) -> io::Result<String> {
                Ok(format!("{} not implemented", prop_name))
            }
            fn get_device_info(&self) -> U2FDeviceInfo {
                self.dev_info.clone().unwrap()
            }

            fn set_device_info(&mut self, dev_info: U2FDeviceInfo) {
                self.dev_info = Some(dev_info);
            }

            fn get_authenticator_info(&self) -> Option<&AuthenticatorInfo> {
                self.authenticator_info.as_ref()
            }

            fn set_authenticator_info(&mut self, authenticator_info: AuthenticatorInfo) {
                self.authenticator_info = Some(authenticator_info);
            }

            fn get_shared_secret(&self) -> Option<&ECDHSecret> {
                self.secret.as_ref()
            }

            fn set_shared_secret(&mut self, secret: ECDHSecret) {
                self.secret = Some(secret);
            }
        }
    }

    #[test]
    fn test_init_device() {
        let mut device = platform::TestDevice::new();
        let nonce = vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01];

        // channel id
        let mut cid = [0u8; 4];
        thread_rng().fill_bytes(&mut cid);

        // init packet
        let mut msg = CID_BROADCAST.to_vec();
        msg.extend(vec![HIDCmd::Init.into(), 0x00, 0x08]); // cmd + bcnt
        msg.extend_from_slice(&nonce);
        device.add_write(&msg, 0);

        // init_resp packet
        let mut msg = CID_BROADCAST.to_vec();
        msg.extend(vec![HIDCmd::Init.into(), 0x00, 0x11]); // cmd + bcnt
        msg.extend_from_slice(&nonce);
        msg.extend_from_slice(&cid); // new channel id
        msg.extend(vec![0x02, 0x04, 0x01, 0x08, 0x01]); // versions + flags
        device.add_read(&msg, 0);

        init_device(&mut device, &nonce).unwrap();
        assert_eq!(device.get_cid(), &cid);

        let dev_info = device.get_device_info();
        assert_eq!(dev_info.version_interface, 0x02);
        assert_eq!(dev_info.version_major, 0x04);
        assert_eq!(dev_info.version_minor, 0x01);
        assert_eq!(dev_info.version_build, 0x08);
        assert_eq!(dev_info.cap_flags, Capability::WINK); // 0x01
    }

    #[test]
    fn test_fido2_get_info() {
        let mut device = platform::TestDevice::new();
        let nonce = vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01];

        // channel id
        let mut cid = [0u8; 4];
        thread_rng().fill_bytes(&mut cid);

        // init packet
        let mut msg = CID_BROADCAST.to_vec();
        msg.extend(vec![HIDCmd::Init.into(), 0x00, 0x08]); // cmd + bcnt
        msg.extend_from_slice(&nonce);
        device.add_write(&msg, 0);

        // init_resp packet
        let mut msg = CID_BROADCAST.to_vec();
        msg.extend(vec![HIDCmd::Init.into(), 0x00, 0x11]); // cmd + bcnt
        msg.extend_from_slice(&nonce);
        msg.extend_from_slice(&cid); // new channel id
        msg.extend(vec![0x02, 0x04, 0x01, 0x08, 0x01 | 0x04]); // versions + flags (wink+cbor)
        device.add_read(&msg, 0);

        init_device(&mut device, &nonce).unwrap();
        assert_eq!(device.get_cid(), &cid);

        let dev_info = device.get_device_info();
        assert_eq!(dev_info.cap_flags, Capability::WINK | Capability::CBOR);

        // fido 2 request
        let mut msg = cid.to_vec();
        msg.extend(vec![HIDCmd::Cbor.into(), 0x00, 0x1]); // cmd + bcnt
        msg.extend(vec![0x04]); // authenticatorGetInfo
        device.add_write(&msg, 0);

        // fido response
        let mut msg = cid.to_vec();
        msg.extend(vec![HIDCmd::Cbor.into(), 0x00, 0x59]); // cmd + bcnt
        msg.extend(&AUTHENTICATOR_INFO_PAYLOAD[0..(IN_HID_RPT_SIZE - 7)]);
        device.add_read(&msg, 0);
        // Continuation package
        let mut msg = cid.to_vec();
        msg.extend(vec![0x00]); // SEQ
        msg.extend(&AUTHENTICATOR_INFO_PAYLOAD[(IN_HID_RPT_SIZE - 7)..]);
        device.add_read(&msg, 0);

        init_ctap2(&mut device).expect("Couldn't init fido");

        let result = device
            .get_authenticator_info()
            .expect("Didn't get any authenticator_info");
        let expected = AuthenticatorInfo {
            versions: vec!["U2F_V2".to_string(), "FIDO_2_0".to_string()],
            extensions: vec!["uvm".to_string(), "hmac-secret".to_string()],
            aaguid: AAGuid(AAGUID_RAW),
            options: AuthenticatorOptions {
                platform_device: false,
                resident_key: true,
                client_pin: Some(false),
                user_presence: true,
                user_verification: None,
            },
            max_msg_size: Some(1200),
            pin_protocols: vec![1],
        };

        assert_eq!(result, &expected);
    }

    #[test]
    fn test_sendrecv_multiple() {
        let mut device = platform::TestDevice::new();
        let cid = [0x01, 0x02, 0x03, 0x04];
        device.set_cid(cid);

        // init packet
        let mut msg = cid.to_vec();
        msg.extend(vec![HIDCmd::Ping.into(), 0x00, 0xe4]); // cmd + length = 228
                                                           // write msg, append [1u8; 57], 171 bytes remain
        device.add_write(&msg, 1);
        device.add_read(&msg, 1);

        // cont packet
        let mut msg = cid.to_vec();
        msg.push(0x00); // seq = 0
                        // write msg, append [1u8; 59], 112 bytes remaining
        device.add_write(&msg, 1);
        device.add_read(&msg, 1);

        // cont packet
        let mut msg = cid.to_vec();
        msg.push(0x01); // seq = 1
                        // write msg, append [1u8; 59], 53 bytes remaining
        device.add_write(&msg, 1);
        device.add_read(&msg, 1);

        // cont packet
        let mut msg = cid.to_vec();
        msg.push(0x02); // seq = 2
        msg.extend_from_slice(&[1u8; 53]);
        // write msg, append remaining 53 bytes.
        device.add_write(&msg, 0);
        device.add_read(&msg, 0);

        let data = [1u8; 228];
        let d = sendrecv(&mut device, HIDCmd::Ping, &data).unwrap();
        assert_eq!(d.len(), 228);
        assert_eq!(d, &data[..]);
    }

    #[test]
    fn test_sendapdu() {
        let cid = [0x01, 0x02, 0x03, 0x04];
        let data = [0x01, 0x02, 0x03, 0x04, 0x05];
        let mut device = platform::TestDevice::new();
        device.set_cid(cid);

        let mut msg = cid.to_vec();
        // sendrecv header
        msg.extend(vec![HIDCmd::Msg.into(), 0x00, 0x0e]); // len = 14
                                                          // apdu header
        msg.extend(vec![
            0x00,
            HIDCmd::Ping.into(),
            0xaa,
            0x00,
            0x00,
            0x00,
            0x05,
        ]);
        // apdu data
        msg.extend_from_slice(&data);
        device.add_write(&msg, 0);

        // Send data back
        let mut msg = cid.to_vec();
        msg.extend(vec![HIDCmd::Msg.into(), 0x00, 0x07]);
        msg.extend_from_slice(&data);
        msg.extend_from_slice(&SW_NO_ERROR);
        device.add_read(&msg, 0);

        let (result, status) = send_apdu(&mut device, HIDCmd::Ping.into(), 0xaa, &data).unwrap();
        assert_eq!(result, &data);
        assert_eq!(status, SW_NO_ERROR);
    }

    #[test]
    fn test_get_property() {
        let device = platform::TestDevice::new();

        assert_eq!(device.get_property("a").unwrap(), "a not implemented");
    }
}
