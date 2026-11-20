# Age v1 compatibility fixture

These files are a fixed test vector generated with the reference Go `age` CLI
and `age-keygen` 1.0.0. The identity and RSA signing key are test-only keys;
they must never be used for real data. `envelope.age` contains a signed test
payload encrypted to the commented identity in `identity.txt`.

The Core suite reads these files directly and does not need the `age` or
`age-keygen` executables.
