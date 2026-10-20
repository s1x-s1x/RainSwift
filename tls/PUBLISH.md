# Verified TLS post-quantum certificate-chain port

This directory carries the verified TLS-B line: Rain-VOLEitH as the online
CertificateVerify signer, ECDSA P-256 + Rain dual signatures, and forced
SLH-DSA-SM3-128-24 alternative signatures on both CA issuance edges.

Branch: `publish/tls-pq-20261019`
Base: `3a4c582` (`docs: add the combined speed data for the 55-item test plan`)

## What is included

- `tls/`: alt-chain, independent client root, native policy pass-through,
  explicit SLH cache recovery, 2^14-byte fragmentation and record limits,
  TLS-B/Rain integration.
- `tools/`: `native.py`, `signing_budget.py`, `alt_chain_fixtures.py`,
  `ds_acceptance.py`, audit driver.
- `tests/`: TLS-B suite, Rain tests, recovery tests and the new field-level
  acceptance contract tests.
- `fixtures/`: 128-24, 128s and ML-DSA-44 test-only preissued credentials.
- `reference/`, `third_party/py-acvp-pqc/fips205.py`: independent Python model
  used for the second verification path.
- `delivery/`: the full acceptance report, diffs, hashes, acceptance JSON/JUnit,
  server environment and raw evidence package.

## Verified results

- TLS-B server suite with Rain: **502 passed / 1 skipped**.
- TLS-B `--profile-set full`: **36/36 passed**; strict P2 `checked_edges=2`,
  `legacy_edges=0`, `complete=true`, CV `classic_ok/pq_ok/accepted=true`,
  independent root digest matches; loopback TCP `error/server_error=null`,
  `exporters_match=true`.
- Rain `--profile-set p2-only`: **29 passed / 0 failed / 7 not_covered**,
  JUnit `skipped=7`; CertificateVerify scheme `65204` (`0xFEB4`, rain4-bal).
- A1-5 side and its full evidence remain in the `pqc-a1-5` repository.

## Run

```bash
cd tls
python -m pytest -q tests
python tools/audit_live_checks.py

# Rain native library (Linux)
bash native/rain_voleith/build_linux.sh /path/to/rain-src /path/to/XKCP build
export RAIN_VOLEITH_LIB=$PWD/build/librain_voleith_tls.so

# SLH native library from the A1-5 checkout
export SLHDSA_SM3_LIB=/path/to/libslhdsa_sm3.so
export A15_NATIVE_LIBRARY=$SLHDSA_SM3_LIB
export A15_ALT_FIXTURES=$PWD/fixtures/public-alt-chain

python tools/ds_acceptance.py \
  --fixtures fixtures/public-alt-chain --library "$SLHDSA_SM3_LIB" \
  --client-root fixtures/public-alt-chain/slh-dsa-sm3-128-24/root.der \
  --output build/acceptance --threads 8 --backend 2 --profile-set full
```

## Warning

`fixtures/**` and `delivery/**` contain **test-only** private keys and test
credentials. They are not production keys. 128-24 is offline-CA-only; online
CertificateVerify uses Falcon-512 or Rain-VOLEitH.
