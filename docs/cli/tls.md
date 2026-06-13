---
title: tls-send / tls-recv
description: Carry one encrypted Nocturne packet over TLS 1.3 with optional mTLS. Composes with encrypt / decrypt.
---

# `tls-send` / `tls-recv`

One-shot TLS 1.3 sender and receiver pair. The on-the-wire payload
is the same opaque packet `encrypt` produced, TLS just provides
reachability, server authentication, and optional mTLS.

See the [TLS guide](../guide/tls) for the operational story; this
page documents the flags.

## Synopsis

```
nocturne-kx tls-send \
  --host <h> --port <n> --in <packet>
  [--ca <pem>] [--sni <name>]
  [--cert <pem> --key <pem>]

nocturne-kx tls-recv \
  --port <n> --cert <pem> --key <pem> --out <packet>
  [--bind <host>] [--ca <pem> --require-client-cert]
```

## `tls-send` flags

| Flag      | Required | Description |
|-----------|----------|-------------|
| `--host`  | yes      | DNS name or IP of the receiver. |
| `--port`  | yes      | TLS server port. |
| `--in`    | yes      | Packet to send (produced by `encrypt`). |
| `--ca`    | no       | CA bundle for server verification. Without it, the server cert is not validated. |
| `--sni`   | no       | SNI hostname (and `SSL_set1_host` target). Required if `--ca` is set. |
| `--cert`  | no       | Client cert PEM for mTLS. |
| `--key`   | no       | Client key PEM for mTLS. Required if `--cert`. |

## `tls-recv` flags

| Flag                   | Required | Description |
|------------------------|----------|-------------|
| `--port`               | yes      | Port to listen on. |
| `--cert`               | yes      | Server cert PEM. |
| `--key`                | yes      | Server key PEM. |
| `--out`                | yes      | Where to write the received packet. |
| `--bind`               | no       | Listen address. Default: `0.0.0.0`. |
| `--ca`                 | no       | CA bundle to verify client certs against. |
| `--require-client-cert`| no       | Demand a client cert. Pairs with `--ca`. |

## Examples

### Plain TLS 1.3 (server auth only)

```bash
# Receiver
nocturne-kx tls-recv \
  --port 8443 \
  --cert /etc/nocturne/server.crt --key /etc/nocturne/server.key \
  --out msg.pkt

# Sender
nocturne-kx tls-send \
  --host bob.example.com --port 8443 \
  --ca /etc/nocturne/ca.pem --sni bob.example.com \
  --in msg.pkt
```

### mTLS

```bash
# Receiver, requires a client cert signed by the named CA
nocturne-kx tls-recv \
  --port 8443 \
  --cert server.crt --key server.key \
  --ca clients-ca.pem --require-client-cert \
  --out msg.pkt

# Sender presents its own cert
nocturne-kx tls-send \
  --host bob.example.com --port 8443 \
  --ca server-ca.pem --sni bob.example.com \
  --cert alice.crt --key alice.key \
  --in msg.pkt
```

## What can't be tuned

- TLS version (1.3 only).
- Cipher suite (OpenSSL default 1.3 list).
- Length framing (4-byte BE prefix, 16 MiB cap).
- `SSL_MODE_AUTO_RETRY` (always on).
- Compression (always off).

These are intentional. TLS-the-protocol has too many knobs that
weaken it; we picked the conservative end of every one.

## Build requirement

`tls-send` / `tls-recv` only exist when the binary was built with
`-DENABLE_TLS_TRANSPORT=ON` (default on Linux/macOS where OpenSSL is
available). Without that, both subcommands print:

```
ERR: this binary was built without the TLS transport
exit 2
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | One packet sent / received cleanly.                    |
| 1    | Usage error (missing flag, file).                       |
| 2    | TLS handshake or socket error; build-without-OpenSSL.  |
