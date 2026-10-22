//! Item history: the version every write carries inside its signed envelope, and signed
//! deletions, so a server can't serve a device an older copy of an item than one it has seen.
//!
//! An item's plaintext is its JSON with an `item_version`: the time of the write in milliseconds,
//! or one more than the highest version the writer knows of the item when that is larger. A
//! deletion is an envelope too, `{"type":"deleted","item_version":n}`, sealed for the same item.
//! Apps before item history (0.2.0) ignore both: they write items without a version and
//! deletions without an envelope, which a device accepts while such apps may still be in use
//! (see `LocalVault::set_strict_history`).

use serde::Deserialize;
use zeroize::Zeroizing;

use crate::vault::now;
use crate::{Error, ItemData, Result};

/// The plaintext field that holds an item's version.
const FIELD: &str = "item_version";
/// The `type` of a deletion's plaintext.
const DELETED: &str = "deleted";

/// What an envelope says: an item (`data`) or a deletion (`None`), and its version (`None`:
/// written by an app before item history).
#[derive(Debug)]
pub(crate) struct Copy {
    pub data: Option<ItemData>,
    pub version: Option<i64>,
}

/// The version of a write after `known`, the highest version the writer has of the item.
pub(crate) fn next(known: i64) -> i64 {
    known.saturating_add(1).max(now())
}

/// `data` as an item's plaintext with `version`.
pub(crate) fn plaintext(data: &ItemData, version: i64) -> Result<Zeroizing<Vec<u8>>> {
    let json = Zeroizing::new(serde_json::to_vec(data).map_err(|e| Error::Invalid(e.to_string()))?);
    // An item is always a JSON object with a `type`: the version goes in before its end.
    let (end, body) = json
        .split_last()
        .filter(|(end, body)| **end == b'}' && body.len() > 1)
        .ok_or_else(|| Error::Invalid("an item must be a JSON object".into()))?;
    let field = format!(",\"{FIELD}\":{version}");
    let mut out = Zeroizing::new(Vec::with_capacity(json.len() + field.len()));
    out.extend_from_slice(body);
    out.extend_from_slice(field.as_bytes());
    out.push(*end);
    Ok(out)
}

/// A deletion's plaintext.
pub(crate) fn deletion(version: i64) -> Vec<u8> {
    format!("{{\"type\":\"{DELETED}\",\"{FIELD}\":{version}}}").into_bytes()
}

/// `plain` (an item or a deletion, of any kind, from any app) with its version set to `version`.
pub(crate) fn with_version(plain: &[u8], version: i64) -> Result<Zeroizing<Vec<u8>>> {
    let mut value: serde_json::Value =
        serde_json::from_slice(plain).map_err(|e| Error::Corrupt(e.to_string()))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| Error::Corrupt("an item must be a JSON object".into()))?;
    object.insert(FIELD.into(), version.into());
    Ok(Zeroizing::new(
        serde_json::to_vec(&value).map_err(|e| Error::Invalid(e.to_string()))?,
    ))
}

/// Reads an opened envelope of item `id`.
pub(crate) fn read(id: &str, plain: &[u8]) -> Result<Copy> {
    #[derive(Deserialize)]
    struct Head {
        #[serde(rename = "type")]
        kind: String,
        #[serde(default)]
        item_version: Option<i64>,
    }
    let corrupt = |e: serde_json::Error| Error::Corrupt(format!("item {id}: {e}"));
    let head: Head = serde_json::from_slice(plain).map_err(corrupt)?;
    // Versions start at 1; anything else counts as none.
    let version = head.item_version.filter(|v| *v > 0);
    let data = if head.kind == DELETED {
        None
    } else {
        Some(serde_json::from_slice(plain).map_err(corrupt)?)
    };
    Ok(Copy { data, version })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Snippet;

    fn snippet() -> ItemData {
        ItemData::Snippet(Snippet {
            name: "uptime".into(),
            body: "uptime".into(),
            tags: vec![],
            source: None,
        })
    }

    #[test]
    fn items_and_deletions_carry_their_version() {
        let plain = plaintext(&snippet(), 1_760_000_000_123).unwrap();
        assert_eq!(
            std::str::from_utf8(&plain).unwrap(),
            r#"{"type":"snippet","name":"uptime","body":"uptime","item_version":1760000000123}"#
        );
        let copy = read("I", &plain).unwrap();
        assert_eq!(
            (copy.data, copy.version),
            (Some(snippet()), Some(1_760_000_000_123))
        );

        let gone = deletion(7);
        assert_eq!(gone, br#"{"type":"deleted","item_version":7}"#);
        let copy = read("I", &gone).unwrap();
        assert_eq!((copy.data, copy.version), (None, Some(7)));
    }

    #[test]
    fn items_from_older_apps_have_no_version() {
        let plain = serde_json::to_vec(&snippet()).unwrap();
        let copy = read("I", &plain).unwrap();
        assert_eq!((copy.data, copy.version), (Some(snippet()), None));
        // Not a version: zero or below.
        let copy = read(
            "I",
            br#"{"type":"snippet","name":"a","body":"b","item_version":0}"#,
        )
        .unwrap();
        assert_eq!(copy.version, None);
    }

    #[test]
    fn a_new_version_keeps_what_this_app_doesnt_know() {
        let plain = br#"{"type":"future_kind","shape":{"x":1},"item_version":3}"#;
        let copy = read("I", plain).unwrap();
        assert_eq!(
            (copy.data, copy.version),
            (Some(ItemData::Unknown), Some(3))
        );
        let again: serde_json::Value =
            serde_json::from_slice(&with_version(plain, 9).unwrap()).unwrap();
        assert_eq!(
            again,
            serde_json::json!({"type": "future_kind", "shape": {"x": 1}, "item_version": 9})
        );
    }

    #[test]
    fn versions_only_grow() {
        let far_ahead = now() + 86_400_000;
        assert_eq!(next(far_ahead), far_ahead + 1);
        assert!(next(0) >= now() - 1000);
        assert_eq!(next(i64::MAX), i64::MAX);
    }
}
