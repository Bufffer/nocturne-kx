---
title: Audit log
description: Hash-chained, Ed25519-signed JSONL with O(records) verification — Nocturne-KX writes one and verifies it on demand.
---

# Audit log

Every CLI invocation that touches a key or modifies state writes a
JSONL record. Records are chained by BLAKE2b-256; optionally signed
per-record by an Ed25519 audit key; optionally written into a WORM
directory for immutability.

## File layout

```jsonl
{"ts":"2026-06-13T11:00:24.123Z","seq":1,"op":"GEN_RECEIVER","detail":"kem=hybrid","prev_hash":"00..00","hash":"7f3a..c4d2"}
{"ts":"2026-06-13T11:01:02.481Z","seq":2,"op":"ENCRYPT","detail":"rotation=0,session=7f3a","prev_hash":"7f3a..c4d2","hash":"a1b2..ef10"}
{"ts":"2026-06-13T11:01:54.992Z","seq":3,"op":"DECRYPT","detail":"replay_db=ok","prev_hash":"a1b2..ef10","hash":"deca..f00d"}
```

- `prev_hash` is the BLAKE2b-256 of the previous record's *canonical*
  bytes (the JSON keys are sorted; whitespace is fixed).
- `hash` is the BLAKE2b-256 of this record's canonical bytes.
- If `--audit-sign-key` was passed, each record also carries `sig`
  (64 B base64 Ed25519 detached signature over canonical bytes).

The first record's `prev_hash` is 32 zero bytes — the chain "head".

## Enabling

```bash
# Append to a chained, unsigned log
./build/nocturne-kx encrypt \
  --audit-log /var/log/nocturne/audit.log \
  ...

# Add per-record Ed25519 signing
./build/nocturne-kx encrypt \
  --audit-log /var/log/nocturne/audit.log \
  --audit-sign-key /etc/nocturne/auditor_sk.bin \
  ...

# Mirror into a WORM directory (one file per record, append-only mount)
./build/nocturne-kx encrypt \
  --audit-log /var/log/nocturne/audit.log \
  --audit-worm-dir /mnt/worm/nocturne \
  ...
```

`--audit-worm-dir` writes each record as `<seq>.json` so a
write-once filesystem (e.g. AWS S3 Object Lock, GCS Bucket Lock,
NetApp SnapLock) can refuse modifications at the storage layer.

## Verifying

```bash
./build/nocturne-kx audit-verify /var/log/nocturne/audit.log
# ok: 247 records verified
# chain head: deca...f00d
```

With a pinned signer:

```bash
./build/nocturne-kx audit-verify /var/log/nocturne/audit.log \
  --expect-signer /etc/nocturne/auditor_pk.bin
# ok: 247 records verified, all Ed25519 signatures match
# chain head: deca...f00d
```

The verifier walks the file once, recomputes the chain, and reports
the first record whose `hash` doesn't match the expected value:

```
fail: chain break at seq=78
expected prev_hash=a1b2..ef10
actual   prev_hash=0000..0000
```

`seq` makes the tampered region findable in `O(log n)` once you know
the failure point.

## Programmatic API

The enterprise audit logger lives at
`src/security/audit_logger.hpp`. The CLI uses a simpler legacy format
inline in `nocturne-kx.cpp` for backward compatibility; bridging the
two is a tracked cleanup item.

```cpp
#include "src/security/audit_logger.hpp"

nocturne::security::AuditLogger logger(
    "/var/log/nocturne/audit.log",
    /*sign_sk=*/audit_sk,
    /*worm_dir=*/std::nullopt
);

logger.append("ENCRYPT", "rotation=0,session=7f3a");

const auto result = logger.verify_chain();
if (!result.ok) {
    std::cerr << "chain broken at seq=" << result.first_failure_seq << "\n";
    for (const auto& e : result.errors) std::cerr << "  " << e << "\n";
}
```

`verify_chain` returns at most 16 error strings to keep the report
bounded; the first error is always the most informative.

## SIEM forwarding

Audit records can be forwarded to a SIEM via the configured
`SIEMConnector`. Currently wired sinks:

- **SYSLOG_UDP** — RFC 5424
- **SYSLOG_TCP** — RFC 6587 octet-counting
- **SYSLOG_TLS** — RFC 5425 with TLS 1.3 + optional mTLS
- **CEF / LEEF** — formatters wrap any of the above transports

HTTP-based sinks (Splunk HEC, Elasticsearch, Kafka, generic webhook)
are stubbed pending a libcurl + librdkafka dependency decision. See
the roadmap for status.
