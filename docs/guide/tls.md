---
title: TLS transport
description: Carry one encrypted Nocturne packet over TLS 1.3 with optional mTLS. Composes with encrypt / decrypt; never replaces them.
---

# TLS transport

The `tls-send` / `tls-recv` subcommands carry one opaque encrypted
packet over `TcpTlsTransport`, a sibling of `MemoryTransport`
implemented on top of OpenSSL.

TLS here is a *transport*, not the cryptography. The packet itself is
already encrypted, signed, and replay-protected by `encrypt`. TLS
adds:

- Network reachability over arbitrary IP infrastructure.
- Optional mutual authentication (mTLS) against a CA bundle.
- Server certificate verification with SNI hostname pinning.

## Requirements

- Build with `-DENABLE_TLS_TRANSPORT=ON` (default).
- OpenSSL ≥ 3.0 in the link line (libssl-dev on Debian / Ubuntu).

## Receiver

```bash
./build/nocturne-kx tls-recv \
  --port 8443 \
  --cert /etc/nocturne/server.crt.pem \
  --key  /etc/nocturne/server.key.pem \
  --out  msg.pkt
```

mTLS:

```bash
./build/nocturne-kx tls-recv \
  --port 8443 \
  --cert /etc/nocturne/server.crt.pem \
  --key  /etc/nocturne/server.key.pem \
  --ca   /etc/nocturne/clients-ca.pem \
  --require-client-cert \
  --out  msg.pkt
```

## Sender

```bash
./build/nocturne-kx tls-send \
  --host bob.example.internal \
  --port 8443 \
  --ca   /etc/nocturne/server-ca.pem \
  --sni  bob.example.internal \
  --in   msg.pkt
```

mTLS client cert:

```bash
./build/nocturne-kx tls-send \
  --host bob.example.internal \
  --port 8443 \
  --ca   /etc/nocturne/server-ca.pem \
  --sni  bob.example.internal \
  --cert /etc/nocturne/alice.crt.pem \
  --key  /etc/nocturne/alice.key.pem \
  --in   msg.pkt
```

## Defaults

| Setting           | Value             | Override?       |
|-------------------|-------------------|-----------------|
| TLS version       | 1.3 only          | No              |
| Cipher policy     | OpenSSL default 1.3 | No            |
| Framing           | 4-byte BE length prefix | No        |
| Max frame size    | 16 MiB            | No              |
| Auto retry        | `SSL_MODE_AUTO_RETRY` | No          |
| Compression       | Disabled          | No              |

The "no override" defaults are intentional, TLS-the-protocol has
been weakened often enough by knobs that we picked the conservative
end of every dial.

## Composing with `encrypt`/`decrypt`

```bash
# Sender pipeline
nocturne-kx encrypt --rx-pk bob.pk --kem hybrid --in note.txt --out msg.pkt
nocturne-kx tls-send --host bob.internal --port 8443 --ca ca.pem --in msg.pkt

# Receiver pipeline (run on bob's box)
nocturne-kx tls-recv --port 8443 --cert s.crt --key s.key --out msg.pkt
nocturne-kx decrypt --rx-pk bob.pk --rx-sk bob.sk --in msg.pkt --out note.txt
```

Why split? Because the on-the-wire packet is *already* end-to-end
authenticated. TLS is an availability + addressability layer; if it
breaks tomorrow the packet is still safe to handle out of band
(USB stick, paper QR, ham radio). The CLI never loses the property
that ciphertext is independent of transport.

## Design notes

- `tls-send` / `tls-recv` skip the `NEGOTIATE` frame. `Session::on_receive`
  resets `remote_seq_=0` on NEGOTIATE but NEGOTIATE itself consumes
  seq 1, so a following `DATA(seq=2)` would draw a `NAK`. The CLI
  uses `DATA(seq=1) + CLOSE(seq=2)` for a clean one-shot.
- Certificates are loaded from disk per invocation; no global state
  is shared across runs.
- The TLS code is exercised in CI on every push: `tests/protocol/test_tcp_tls_transport.cpp`
  covers TLS 1.3 loopback, mTLS, missing-cert rejection, and graceful
  peer close.
