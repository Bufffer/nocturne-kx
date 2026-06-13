---
title: Replay protection
description: How Nocturne-KX's bidirectional replay defence works, and why it's patent pending.
---

# Replay protection <span class="nx-badge nx-badge--violet">patent pending</span>

The classic replay defence is "remember the last counter; reject
anything ≤ that". Nocturne extends it in two ways:

1. **Bidirectional separation.** Sender→receiver and receiver→sender
   counters live in different prefix spaces inside the same on-disk
   database. An attacker can't exhaust one side's counter by replaying
   the other.
2. **MAC-protected on-disk store.** The DB file is encrypted with
   XChaCha20-Poly1305 and authenticated against a static AAD (the file
   version), so swapping in an attacker-controlled DB or truncating
   the file fails at load time, not at first false-accept.

The patent application covers the prefix-based counter separation —
specifically the way independent sessions multiplex through one DB
without sharing a single monotonic count.

## On-disk format

```
[8B version | MSB=encryption-flag] [24B nonce] [4B ct_len] [AEAD ct]
```

- `version` is the file format version. The high bit doubles as the
  "encrypted" flag — a non-encrypted dev DB has the high bit clear
  and skips the AEAD block.
- `nonce` is fresh on every write.
- `ct` is `XChaCha20-Poly1305(key, nonce, plaintext, aad=version)`.
  AAD pinning means a v1 ciphertext can't be replayed against a v2
  reader.

Atomicity: writes go to `&lt;path&gt;.tmp`, then `rename(2)` over the live
file. Crash-during-write leaves the previous DB intact.

## API surface

```cpp
#include "src/security/inline/replay_db.hpp"

nocturne::ReplayDB rdb(
    "/var/lib/nocturne/replay.db",          // path
    "/run/nocturne/replay.macsk",           // MAC key (optional but recommended)
    std::nullopt                             // external monotonic counter (TPM)
);

// Tracked per (receiver_pk, session_id) tuple
const bool seen = rdb.has_seen(receiver_pk, session_id, counter);
if (seen) return std::unexpected{Error{ErrorCode::ReplayDetected, "counter ≤ last seen"}};
rdb.record(receiver_pk, session_id, counter);
```

`record` is atomic against the file; `has_seen` is a pure read with
no side effects.

::: warning Not thread-safe
`ReplayDB` is single-writer by design. Running two encrypt processes
against the same DB file is undefined behaviour. Coordinate at the
policy layer (one daemon, or a flock).
:::

## TPM-backed monotonic counter

For deployments that need rollback resistance against a malicious
filesystem (think: container migration, snapshot restore), pass a TPM
or PSA counter path:

```bash
./build/nocturne-kx encrypt \
  --replay-db /var/lib/nocturne/replay.db \
  --tpm-counter /dev/tpm0/counter-7 \
  ...
```

The DB's logical counter is then bound to the TPM's hardware
monotonic counter — any rollback that drops the DB below the TPM
value is detected on the next read.

## CLI commands

```bash
# Inspect (no decrypt happens)
nocturne-kx rate-limit-status alice@example.com

# Reset (auditable; requires --hsm-pass or operator policy)
nocturne-kx rate-limit-reset alice@example.com
```

## Failure mode

When the DB rejects a packet you'll see:

```
ReplayDetected: counter 42 ≤ last seen 42 for session 7f3a
exit 2
```

`exit 2` is grep-stable for CI assertions. The `[pqc]` and
`[hsm]` test suites both assert it on tampered inputs.
