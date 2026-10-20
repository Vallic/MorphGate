# Security

MorphGate is published by Vallic d.o.o. To report a vulnerability in the apps (desktop, Android, iOS),
the sync protocol or the morphgate.com service, email **contact@vallic.com** with "MorphGate
security" in the subject. Please don't post it anywhere public until a fix is out.

Helpful to include:

- what an attacker can do, and what they need first (a network position, a device, an account);
- the version and platform (Settings → About), and the steps or code that show it;
- whether you'd like to be credited when the fix is released.

Reports are handled privately. Fixes ship in a new release, and the release notes
([CHANGELOG.md](CHANGELOG.md)) say what was fixed. Only the latest release gets security fixes:
the app updates itself, so please check you're on it.

[docs/sync-crypto-spec.md](docs/sync-crypto-spec.md) describes the design: what the vault
encrypts, what the sync server can and can't see, and how devices and teams are trusted.
