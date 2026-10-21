#!/usr/bin/env python3
"""Uploads an .ipa to App Store Connect (TestFlight) through the API's build uploads, from any
system (no Xcode, altool or Transporter). RELEASING.md (iOS) says when.

usage: scripts/upload-ios.py <ipa> <bundle id> <version> <build>

The App Store Connect API key: ASC_KEY_ID and ASC_ISSUER_ID, and the .p8 at ASC_KEY_PATH
(default ~/.apple/AuthKey_<ASC_KEY_ID>.p8). It needs the Admin or App Manager role. Needs PyJWT
with cryptography.

Apple's API and its upload storage drop a request now and then: requests that can be repeated
are, after a pause. A build App Store Connect has already (an earlier run that got through,
though its answer didn't) counts as uploaded.
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
# Pauses before each further try of a request that can be repeated.
PAUSES = (5, 15, 30, 60)


def token():
    now = int(time.time())
    return jwt.encode(
        {"iss": ISSUER, "iat": now, "exp": now + 600, "aud": "appstoreconnect-v1"},
        KEY,
        algorithm="ES256",
        headers={"kid": KEY_ID, "typ": "JWT"},
    )


def send(make, what, timeout, repeat):
    """Sends the request `make()` builds; a repeatable one again after a dropped connection, a
    timeout or a 5xx answer. Returns the body."""
    for pause in (*PAUSES, None) if repeat else (None,):
        try:
            with urllib.request.urlopen(make(), timeout=timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code < 500 or pause is None:
                sys.exit(f"{what}: {e.code} {e.read().decode()[:1500]}")
            why = f"HTTP {e.code}"
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            if pause is None:
                sys.exit(f"{what}: {e}")
            why = str(e)
        print(f"{what}: {why}; again in {pause} s")
        time.sleep(pause)


def api(method, path, body=None, timeout=60, repeat=True):
    def make():
        return urllib.request.Request(
            API + path,
            data=json.dumps(body).encode() if body is not None else None,
            method=method,
            headers={"Authorization": f"Bearer {token()}", "Content-Type": "application/json"},
        )

    raw = send(make, f"{method} {path}", timeout, repeat)
    return json.loads(raw) if raw else {}


ipa, bundle_id, version, build = sys.argv[1:5]
data = pathlib.Path(ipa).read_bytes()

apps = api("GET", f"/v1/apps?filter%5BbundleId%5D={bundle_id}&fields%5Bapps%5D=name")["data"]
if not apps:
    sys.exit(f"no App Store Connect app for {bundle_id}: create it first (Apps → + → New App)")
app = apps[0]["id"]

existing = api("GET", f"/v1/builds?filter%5Bapp%5D={app}&filter%5Bversion%5D={build}"
                      f"&filter%5BpreReleaseVersion.version%5D={version}&limit=1")["data"]
if existing:
    state = existing[0]["attributes"].get("processingState")
    print(f"{version} ({build}) is in App Store Connect already ({state}): nothing to upload")
    sys.exit(0)

# Not repeated: a retry after a lost answer could start a second upload of the same build.
upload = api("POST", "/v1/buildUploads", {"data": {
    "type": "buildUploads",
    "attributes": {"cfBundleShortVersionString": version, "cfBundleVersion": build, "platform": "IOS"},
    "relationships": {"app": {"data": {"type": "apps", "id": app}}},
}}, repeat=False)["data"]
print("build upload", upload["id"])

file = api("POST", "/v1/buildUploadFiles", {"data": {
    "type": "buildUploadFiles",
    "attributes": {"fileName": pathlib.Path(ipa).name, "fileSize": len(data),
                   "uti": "com.apple.ipa", "assetType": "ASSET"},
    "relationships": {"buildUpload": {"data": {"type": "buildUploads", "id": upload["id"]}}},
}}, repeat=False)["data"]
ops = file["attributes"]["uploadOperations"]
print(f"uploading {len(data)} bytes in {len(ops)} parts")
for op in ops:
    part = data[op["offset"]:op["offset"] + op["length"]]
    headers = {h["name"]: h["value"] for h in op.get("requestHeaders") or []}
    send(lambda: urllib.request.Request(op["url"], data=part, method=op["method"], headers=headers),
         f"part {op.get('partNumber')}", 300, True)

# Apple checks the whole file before it answers: give it time.
api("PATCH", f"/v1/buildUploadFiles/{file['id']}", {"data": {
    "type": "buildUploadFiles", "id": file["id"],
    "attributes": {"uploaded": True, "sourceFileChecksums": {
        "file": {"hash": hashlib.md5(data).hexdigest(), "algorithm": "MD5"}}},
}}, timeout=300)
print("uploaded; Apple is processing it")

for _ in range(120):
    state = api("GET", f"/v1/buildUploads/{upload['id']}")["data"]["attributes"]["state"]
    if state.get("state") in ("COMPLETE", "FAILED"):
        print(json.dumps(state, indent=1))
        sys.exit(0 if state["state"] == "COMPLETE" else 1)
    time.sleep(30)
print("still processing after an hour")
