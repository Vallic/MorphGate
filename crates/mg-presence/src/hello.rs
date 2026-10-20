//! Windows Hello through `UserConsentVerifier`: face, fingerprint or the Hello PIN.

use windows::Security::Credentials::UI::{
    UserConsentVerificationResult as Outcome, UserConsentVerifier,
    UserConsentVerifierAvailability as Hello,
};
use windows::Win32::Foundation::HWND;
use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
use windows_core::{HSTRING, factory};
use windows_future::IAsyncOperation;

use crate::{Availability, Error, Kind, Parent, Status};

fn why_not(hello: Hello) -> String {
    match hello {
        Hello::DeviceNotPresent => {
            "this PC has no Windows Hello camera, fingerprint reader or PIN".into()
        }
        Hello::NotConfiguredForUser => {
            "Windows Hello isn't set up for this account (Settings → Accounts → Sign-in options)"
                .into()
        }
        Hello::DisabledByPolicy => "Windows Hello is turned off by your organization".into(),
        Hello::DeviceBusy => "Windows Hello is busy; try again".into(),
        other => format!("Windows Hello isn't available (state {})", other.0),
    }
}

pub fn availability() -> Availability {
    let status = match UserConsentVerifier::CheckAvailabilityAsync().and_then(|op| op.join()) {
        Ok(Hello::Available) => Status::Ready,
        Ok(other) => Status::Unavailable(why_not(other)),
        Err(e) => Status::Unavailable(format!("Windows Hello: {}", e.message())),
    };
    Availability {
        kind: Kind::WindowsHello,
        status,
    }
}

/// "unlock your vault" → "Unlock your vault."
fn sentence(reason: &str) -> String {
    let mut chars = reason.chars();
    let mut out: String = chars
        .next()
        .map(|c| c.to_uppercase().collect())
        .unwrap_or_default();
    out.push_str(chars.as_str());
    if !out.ends_with('.') {
        out.push('.');
    }
    out
}

pub fn verify(reason: &str, parent: Parent) -> Result<(), Error> {
    let failed = |e: windows_core::Error| Error::Failed(format!("Windows Hello: {}", e.message()));
    let message = HSTRING::from(sentence(reason));
    let op: IAsyncOperation<Outcome> = match parent.0 {
        // Attached to our window; without it the dialog can open behind the app.
        Some(hwnd) => {
            let interop =
                factory::<UserConsentVerifier, IUserConsentVerifierInterop>().map_err(failed)?;
            // SAFETY: `hwnd` is a live top-level window of this process.
            unsafe { interop.RequestVerificationForWindowAsync(HWND(hwnd as _), &message) }
                .map_err(failed)?
        }
        None => UserConsentVerifier::RequestVerificationAsync(&message).map_err(failed)?,
    };
    match op.join().map_err(failed)? {
        Outcome::Verified => Ok(()),
        Outcome::Canceled => Err(Error::Cancelled),
        Outcome::RetriesExhausted => Err(Error::Failed("Windows Hello: too many attempts".into())),
        Outcome::DeviceNotPresent => Err(Error::Unavailable(why_not(Hello::DeviceNotPresent))),
        Outcome::NotConfiguredForUser => {
            Err(Error::Unavailable(why_not(Hello::NotConfiguredForUser)))
        }
        Outcome::DisabledByPolicy => Err(Error::Unavailable(why_not(Hello::DisabledByPolicy))),
        Outcome::DeviceBusy => Err(Error::Failed(why_not(Hello::DeviceBusy))),
        other => Err(Error::Failed(format!(
            "Windows Hello didn't verify you (result {})",
            other.0
        ))),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn reasons_become_sentences() {
        assert_eq!(super::sentence("unlock your vault"), "Unlock your vault.");
        assert_eq!(super::sentence("Done."), "Done.");
    }
}
