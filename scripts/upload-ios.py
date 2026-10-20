#!/usr/bin/env python3
"""Uploads an .ipa to App Store Connect (TestFlight) through the API's build uploads, from any
system (no Xcode, altool or Transporter). RELEASING.md (iOS) says when.

usage: scripts/upload-ios.py <ipa> <bundle id> <version> <build>

The App Store Connect API key: ASC_KEY_ID and ASC_ISSUER_ID, and the .p8 at ASC_KEY_PATH
(default ~/.apple/AuthKey_<ASC_KEY_ID>.p8). It needs the Admin or App Manager role. Needs PyJWT
with cryptography.
"""
import hashlib
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.request

import jwt

KEY_ID = os.environ["ASC_KEY_ID"]
ISSUER = os.environ["ASC_ISSUER_ID"]
KEY = pathlib.Path(
    os.environ.get("ASC_KEY_PATH") or pathlib.Path.home() / ".apple" / f"AuthKey_{KEY_ID}.p8"
).read_text()
API = "https://api.appstoreconnect.apple.com"


def token():
    now = int(time.time())
    return jwt.encode(
        {"iss": ISSUER, "iat": now, "exp": now + 600, "aud": "appstoreconnect-v1"},
        KEY,
        algorithm="ES256",
        headers={"kid": KEY_ID, "typ": "JWT"},
    )


def api(method, path, body=None):
    req = urllib.request.Request(
        API + path,
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={"Authorization": f"Bearer {token()}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        sys.exit(f"{method} {path}: {e.code} {e.read().decode()[:1500]}")


ipa, bundle_id, version, build = sys.argv[1:5]
data = pathlib.Path(ipa).read_bytes()

apps = api("GET", f"/v1/apps?filter%5BbundleId%5D={bundle_id}&fields%5Bapps%5D=name")["data"]
if not apps:
    sys.exit(f"no App Store Connect app for {bundle_id}: create it first (Apps → + → New App)")
app = apps[0]["id"]

upload = api("POST", "/v1/buildUploads", {"data": {
    "type": "buildUploads",
    "attributes": {"cfBundleShortVersionString": version, "cfBundleVersion": build, "platform": "IOS"},
    "relationships": {"app": {"data": {"type": "apps", "id": app}}},
}})["data"]
print("build upload", upload["id"])

file = api("POST", "/v1/buildUploadFiles", {"data": {
    "type": "buildUploadFiles",
    "attributes": {"fileName": pathlib.Path(ipa).name, "fileSize": len(data),
                   "uti": "com.apple.ipa", "assetType": "ASSET"},
    "relationships": {"buildUpload": {"data": {"type": "buildUploads", "id": upload["id"]}}},
}})["data"]
ops = file["attributes"]["uploadOperations"]
print(f"uploading {len(data)} bytes in {len(ops)} parts")
for op in ops:
    part = data[op["offset"]:op["offset"] + op["length"]]
    req = urllib.request.Request(op["url"], data=part, method=op["method"],
                                 headers={h["name"]: h["value"] for h in op.get("requestHeaders") or []})
    with urllib.request.urlopen(req, timeout=300) as r:
        if r.status >= 300:
            sys.exit(f"part {op.get('partNumber')}: HTTP {r.status}")

api("PATCH", f"/v1/buildUploadFiles/{file['id']}", {"data": {
    "type": "buildUploadFiles", "id": file["id"],
    "attributes": {"uploaded": True, "sourceFileChecksums": {
        "file": {"hash": hashlib.md5(data).hexdigest(), "algorithm": "MD5"}}},
}})
print("uploaded; Apple is processing it")

for _ in range(120):
    state = api("GET", f"/v1/buildUploads/{upload['id']}")["data"]["attributes"]["state"]
    if state.get("state") in ("COMPLETE", "FAILED"):
        print(json.dumps(state, indent=1))
        sys.exit(0 if state["state"] == "COMPLETE" else 1)
    time.sleep(30)
print("still processing after an hour")
