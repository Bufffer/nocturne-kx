---
title: HSM integration
description: Drive Nocturne-KX from a real PKCS#11 token — SoftHSM2 for dev/CI, Thales / Utimaco / YubiHSM2 / AWS CloudHSM for production.
---

# HSM integration

Nocturne-KX never touches a private key directly when configured for
HSM mode. The CLI selects an HSM via a URI scheme:

| URI                          | Backend                | Use case             |
|------------------------------|------------------------|----------------------|
| `file:///path/to/sk.bin`     | `FileHSM`              | Dev / fixture-only   |
| `hsm://&lt;token_id&gt;:&lt;key_label&gt;` | `PKCS11HSM` adapter   | Production HSM       |

`FileHSM` accepts both raw 64 B Ed25519 secret keys and the encrypted
`NCHSM2` format (Argon2id-derived AEAD + passphrase via
`NOCTURNE_HSM_PASSPHRASE`).

## SoftHSM2 — local dev and CI

The cheapest way to exercise the PKCS#11 code path is SoftHSM2. The
[CI workflow](https://github.com/Bufffer/nocturne-kx/blob/main/.github/workflows/cmake.yml)
runs the same recipe on every push.

```bash
# 1. Install
sudo apt-get install -y softhsm2

# 2. Configure a token directory in this project
mkdir -p .softhsm/tokens
export SOFTHSM2_CONF=$(pwd)/.softhsm/softhsm2.conf
echo "directories.tokendir = $(pwd)/.softhsm/tokens" > $SOFTHSM2_CONF

# 3. Initialise a token
softhsm2-util --init-token --slot 0 \
  --label "nocturne-dev" --so-pin 0000 --pin 1234

# 4. Point the CLI at it
export PKCS11_LIB=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
export NOCTURNE_HSM_PIN=1234

./build/nocturne-kx encrypt \
  --rx-pk ./keys/receiver_hybrid_pk.bin \
  --kem hybrid \
  --sign-hsm-uri "hsm://nocturne-dev:my-signing-key" \
  --in plaintext.txt --out msg.pkt
```

Behind the scenes the CLI's inline `PKCS11HSM` is a thin adapter that
forwards every call to `nocturne::hsm::PKCS11HSM`. The full v2.40
`CK_FUNCTION_LIST` layout — 68 function pointer slots in OASIS spec
order — was rewritten in P7.1 (commit `c8f9767`) after the SoftHSM CI
step caught a struct misalignment that had been latent for months.

::: tip CI proves the wiring
The `cmake.yml` workflow's "SoftHSM PKCS#11 integration (must pass)"
step generates a key in SoftHSM, signs with it, then verifies the
signature against the public key the HSM just reported. 13 assertions
across one Catch2 case — green on every push to `main`.
:::

## Production providers

### Thales Luna Network HSM

```bash
export PKCS11_LIB=/usr/safenet/lunaclient/lib/libCryptoki2_64.so
./build/nocturne-kx encrypt --sign-hsm-uri "hsm://prod-token:rsa-key-01" ...
```

The session pool starts at `min_sessions=4`; raise via the
`KeyPolicy` if your throughput needs more parallel signs.

### Utimaco SecurityServer

```bash
export PKCS11_LIB=/opt/utimaco/lib/libcs_pkcs11_R3.so
```

### YubiHSM2 (via yubihsm-shell PKCS#11)

```bash
export PKCS11_LIB=/usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so
export YUBIHSM_PKCS11_CONF=/path/to/yubihsm_pkcs11.conf
```

### AWS CloudHSM

```bash
export PKCS11_LIB=/opt/cloudhsm/lib/libcloudhsm_pkcs11.so
```

## Mechanism support

Nocturne uses **CKM_EDDSA** (PKCS#11 v3.0+) for Ed25519. Verify your
provider exposes it via `pkcs11-tool --list-mechanisms` — the older
**CKM_ECDSA** is not Ed25519-compatible and the CLI refuses to fall
back silently. Key generation uses **CKM_EC_EDWARDS_KEY_PAIR_GEN**
with `CKA_EC_PARAMS = id-Ed25519` OID DER.

## FIPS mode

`nocturne::hsm::PKCS11HSM` reports `require_fips` in `get_status()`.
The CLI's inline adapter respects `NOCTURNE_HSM_FIPS=1` to refuse a
slot whose `CK_TOKEN_INFO` doesn't carry the FIPS flag. SoftHSM2 is
not FIPS certified — use FIPS mode only with a real device.

## Audit trail

Every PKCS#11 operation produces an `AuditRecord`:

```
{
  "ts": "2026-06-13T11:00:24.123Z",
  "operation": "SIGN",
  "key_label": "rsa-key-01",
  "operator_id": "nocturne-cli",
  "result": "SUCCESS"
}
```

`PKCS11HSM::get_audit_trail(start, end)` returns the records in-memory;
the inline CLI mirrors them into the main JSONL audit log so an
auditor sees one stream, not two. See the [audit guide](./audit) for
the chain-verify recipe.
