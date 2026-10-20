PuTTY key files (`.ppk`) for the key tests, from the
[ssh-key](https://github.com/RustCrypto/SSH/tree/master/ssh-key/tests/examples) crate's test
examples (Apache-2.0 OR MIT). Throwaway keys, never used anywhere; the encrypted ones' passphrase
is `123`.

OpenSSH certificates, made with `ssh-keygen` (throwaway keys too): `user-cert.pub` is a user
certificate for `user.pub` (key id `alice@example`, principals `deploy` and `ops`, serial 7,
valid forever), signed by `user-ca.pub`; `host-cert.pub` is a host certificate for `other.pub`.
