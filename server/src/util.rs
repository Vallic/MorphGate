use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use mg_sync::ApiError;

pub(crate) fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("system RNG");
    b
}

pub(crate) fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// RFC 3339 UTC timestamp, second precision.
pub(crate) fn rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

pub(crate) fn now() -> String {
    rfc3339(now_secs())
}

/// ULIDs are what clients generate for vault, item and device ids.
pub(crate) fn valid_id(id: &str) -> bool {
    id.len() == 26 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'A'..=b'H' | b'J' | b'K' | b'M' | b'N' | b'P'..=b'T' | b'V'..=b'Z'))
}

/// A refusal: the status and the `{code, message, …}` body (boxed: errors stay small).
#[derive(Debug)]
pub(crate) struct Fail(pub StatusCode, pub Box<ApiError>);

impl Fail {
    pub fn new(status: StatusCode, code: &str, message: impl Into<String>) -> Self {
        Self(status, Box::new(ApiError::new(code, message)))
    }
    pub fn bad(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }
    pub fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "invalid credentials or session",
        )
    }
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", "not found")
    }
}

impl From<rusqlite::Error> for Fail {
    fn from(e: rusqlite::Error) -> Self {
        tracing::error!(%e, "database error");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "internal error",
        )
    }
}

impl IntoResponse for Fail {
    fn into_response(self) -> Response {
        (self.0, Json(*self.1)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_known_dates() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_791_542_099), "2026-10-09T10:34:59Z");
    }

    #[test]
    fn ulid_check() {
        assert!(valid_id("01JABCDEFGHJKMNPQRSTVWXYZ0"));
        assert!(!valid_id("01JABCDEFGHJKMNPQRSTVWXYZI"));
        assert!(!valid_id("../etc/passwd"));
    }
}
