//! LocalAuthentication's `deviceOwnerAuthentication`: on a Mac, Touch ID, with the login password
//! or an Apple Watch as the fallback macOS offers by itself; on an iPhone or iPad, Face ID or
//! Touch ID, with the passcode as the fallback. (Face ID shows the app's
//! `NSFaceIDUsageDescription`, which `Info.ios.plist` sets.)

use std::sync::mpsc;

use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LABiometryType, LAContext, LAPolicy};

use crate::{Availability, Error, Kind, Parent, Status};

/// `LAError` codes for a prompt closed by the user, the system or the app.
const CANCELLED: [isize; 3] = [-2, -4, -9];

pub fn availability() -> Availability {
    // SAFETY: plain LocalAuthentication calls on a context of our own.
    unsafe {
        let ctx = LAContext::new();
        let status = match ctx.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication) {
            Ok(()) => Status::Ready,
            Err(e) => Status::Unavailable(e.localizedDescription().to_string()),
        };
        // `biometryType` is set by a `canEvaluatePolicy` call for biometrics.
        let biometrics = ctx
            .canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
            .is_ok();
        let kind = match ctx.biometryType() {
            LABiometryType::TouchID if biometrics => Kind::TouchId,
            LABiometryType::FaceID if biometrics => Kind::FaceId,
            _ if cfg!(target_os = "ios") => Kind::Passcode,
            _ => Kind::System,
        };
        Availability { kind, status }
    }
}

pub fn verify(reason: &str, _parent: Parent) -> Result<(), Error> {
    let (tx, rx) = mpsc::channel();
    let reply = RcBlock::new(move |success: Bool, error: *mut NSError| {
        let result = if success.as_bool() {
            Ok(())
        } else {
            // SAFETY: on failure LocalAuthentication passes a valid NSError (or nil).
            match unsafe { error.as_ref() } {
                Some(e) if CANCELLED.contains(&e.code()) => Err(Error::Cancelled),
                Some(e) => Err(Error::Failed(e.localizedDescription().to_string())),
                None => Err(Error::Failed("authentication failed".into())),
            }
        };
        let _ = tx.send(result);
    });
    // SAFETY: the reply block is retained by LocalAuthentication until it has been called.
    unsafe {
        LAContext::new().evaluatePolicy_localizedReason_reply(
            LAPolicy::DeviceOwnerAuthentication,
            &NSString::from_str(reason),
            &reply,
        );
    }
    rx.recv()
        .unwrap_or_else(|_| Err(Error::Failed("LocalAuthentication didn't answer".into())))
}
