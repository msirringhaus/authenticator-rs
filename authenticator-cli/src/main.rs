use clap::{Args, Subcommand};

use authenticator::{
    authenticatorservice::{
        AuthenticatorService, CtapVersion
    },
    InfoResult,
    AuthenticatorInfo,
    StatusUpdate,
    statecallback::StateCallback,
};
use std::sync::mpsc::{channel, RecvError};
use std::thread;

#[derive(Debug, Subcommand)]
#[clap(about = "Authenticator Utility")]
enum Opt {
    List
}

fn main() {
    env_logger::init();
    // tracing_subscriber::fmt::init();

    /*
    LogTracer::init()
        .map_err(|e| {
            eprintln!("Well Fuck {:?}", e);
            ()
        })
        .expect("Failed to setup logging facade");
    */

    let timeout_ms = 25000;

    let mut manager = AuthenticatorService::new(CtapVersion::CTAP2)
        .expect("The auth service should initialize safely");

    // Later we need to add common options for transports to consume.
    manager.add_u2f_usb_hid_platform_transports();

    let (status_tx, status_rx) = channel::<StatusUpdate>();
    thread::spawn(move || loop {
        match status_rx.recv() {
            Ok(StatusUpdate::DeviceAvailable { dev_info }) => {
                println!("STATUS: device available: {}", dev_info)
            }
            Err(RecvError) => {
                println!("STATUS: end");
                return;
            }
            _ => {
                eprintln!("Unexpected State");
                panic!()
            }
        }
    });

    let (register_tx, register_rx) = channel();
    let callback = StateCallback::new(Box::new(move |rv| {
        register_tx.send(rv).unwrap();
    }));

    if let Err(e) = manager
        .info(timeout_ms, status_tx, callback) {
            eprintln!("Couldn't setup info request - {:?}", e);
    }

    let info_result = register_rx
        .recv()
        .expect("Problem receiving, unable to continue");

    if let Ok(InfoResult::CTAP2(info)) = info_result {
        println!("{:?}", info);
    } else {
        // An error occured.
    }
}
