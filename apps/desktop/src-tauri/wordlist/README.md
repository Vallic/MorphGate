# EFF's long wordlist

`eff_large_wordlist.txt` is the [Electronic Frontier Foundation](https://www.eff.org/dice)'s long
wordlist for passphrases, as published at
<https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt> (7776 words, sha256
`addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`), under the
[Creative Commons Attribution 3.0 United States License](https://creativecommons.org/licenses/by/3.0/us/).

"Suggest one" under a new master password (`password_suggest` in `src/password.rs`) picks five of
its words at random. It leaves out the four with a hyphen, so that a hyphen always separates words.
The app's open-source licenses list it (`scripts/licenses.mjs`).
