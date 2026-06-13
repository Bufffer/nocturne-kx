---
title: audit-verify
description: Walk a JSONL audit log; recompute the BLAKE2b hash chain, verify Ed25519 per-record signatures.
---

# `audit-verify`

Validates an audit log written by any `--audit-log` invocation.
Reports the first chain break (with seq number) or a clean head hash.

## Synopsis

```
nocturne-kx audit-verify <log-path> [--expect-signer <pk-file>]
```

## Arguments

| Argument            | Description |
|---------------------|-------------|
| `&lt;log-path&gt;`        | JSONL file written by `--audit-log`. |
| `--expect-signer`   | Optional Ed25519 PK to pin. With this, every record's `sig` field must verify against this key; mismatches are reported per-record. |

## Examples

### Plain chain verification

```bash
nocturne-kx audit-verify /var/log/nocturne/audit.log
# ok: 247 records verified
# chain head: deca...f00d
```

### Chain + signer pinning

```bash
nocturne-kx audit-verify /var/log/nocturne/audit.log \
  --expect-signer /etc/nocturne/auditor_pk.bin
# ok: 247 records verified, all Ed25519 signatures match
# chain head: deca...f00d
```

### Tampered log

```bash
# attacker rewrote record 78
sed -i '78s/.*/{"ts":"forged","seq":78,"op":"DECRYPT",...}/' audit.log

nocturne-kx audit-verify /var/log/nocturne/audit.log
# fail: chain break at seq=78
# expected prev_hash=a1b2..ef10
# actual   prev_hash=0000..0000
# exit 1
```

Only the first failure is shown; up to 16 follow-on errors are
captured for diagnostics but truncated to keep stderr usable.

## What gets canonicalised

The chain hash is computed over a deterministic byte serialisation:

- JSON keys sorted lexicographically.
- Whitespace stripped between values.
- UTF-8 throughout.

This means the on-disk pretty-printed form can be re-pretty-printed
without breaking the chain, but content changes (adding a field,
modifying a value) break it deterministically.

## Two different formats

The CLI's inline `audit_log::AuditLogger` (legacy) and the enterprise
`nocturne::security::AuditLogger` write subtly different canonical
forms. `audit-verify` accepts both, it sniffs the first record's
shape to pick the right canonicaliser.

Bridging the two formats is a tracked cleanup item; in the meantime,
the user-facing CLI is always the inline format.

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | Chain verified end-to-end; all signatures match (if pinned). |
| 1    | Chain break or signature mismatch. |
| 2    | File missing, malformed JSON, or pinned-signer file invalid. |
